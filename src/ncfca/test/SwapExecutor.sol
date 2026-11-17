// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {RequestVerifier} from "./RequestVerifier.sol";
import {DynamicState} from "./DynamicState.sol";
import {StateContext} from "./StateContext.sol";
import {CalibrationExecution} from "./CalibrationExecution.sol";

interface IERC20Minimal {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title SwapExecutor (L-Channel Execution Engine — Document 07)
/// @notice Coordinates R verification, S freshness, D policy bounds, L token transfers, and C telemetry.
contract SwapExecutor {
    RequestVerifier public immutable verifier;
    DynamicState public immutable dynamicState;
    StateContext public immutable stateContext;
    CalibrationExecution public immutable calibration;

    uint256 public immutable maxObservationAge;
    uint256 private _locked = 1;

    event SwapExecuted(address indexed user, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut);

    error ReentrancyGuard();
    error StaleStateContext(uint256 observedAt, uint256 currentTimestamp);
    error SlippageExceedsSignedMin(uint256 amountOut, uint256 minAmountOut);
    error SlippageExceedsPolicyCap(uint256 deviationBps, uint256 maxSlippageBps);
    error TransferFailed();

    modifier nonReentrant() {
        if (_locked != 1) revert ReentrancyGuard();
        _locked = 2;
        _;
        _locked = 1;
    }

    constructor(
        address _verifier,
        address _dynamicState,
        address _stateContext,
        address _calibration,
        uint256 _maxObservationAge
    ) {
        verifier = RequestVerifier(_verifier);
        dynamicState = DynamicState(_dynamicState);
        stateContext = StateContext(_stateContext);
        calibration = CalibrationExecution(_calibration);
        maxObservationAge = _maxObservationAge;
    }

    /// @notice Executes an authorized token swap on L.
    /// @dev Remains live even when CircuitBreaker freezes D writes (Section 9 Graceful Degradation).
    function executeSwap(
        RequestVerifier.TransactionRequest calldata req,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 simulatedPoolRateE18 // Represents deterministic AMM execution rate for prototype testing
    ) external nonReentrant returns (uint256 amountOut) {
        uint256 startGas = gasleft();

        // 1. Validate R (EIP-712 signature, deadline, nonce, and D maxSwapAmount)
        bytes32 digest = verifier.verifyAndConsume(req, v, r, s);

        // 2. Read S (verify environmental observation freshness)
        StateContext.MarketObservation memory obs = stateContext.getObservation(req.tokenIn, req.tokenOut);
        if (obs.observedAt == 0 || block.timestamp - obs.observedAt > maxObservationAge) {
            revert StaleStateContext(obs.observedAt, block.timestamp);
        }

        // 3. Calculate L-channel outputs and enforce both signed minAmountOut and D-channel policy cap
        uint256 expectedOut = (req.amountIn * obs.referencePriceE18) / 1e18;
        amountOut = (req.amountIn * simulatedPoolRateE18) / 1e18;

        if (amountOut < req.minAmountOut) {
            revert SlippageExceedsSignedMin(amountOut, req.minAmountOut);
        }

        DynamicState.Policy memory policy = dynamicState.getPolicy(req.policyId);
        uint256 deviationBps = expectedOut > amountOut ? ((expectedOut - amountOut) * 10_000) / expectedOut : 0;
        if (deviationBps > policy.maxSlippageBps) {
            revert SlippageExceedsPolicyCap(deviationBps, policy.maxSlippageBps);
        }

        // 4. Execute L-channel token transfers
        if (!IERC20Minimal(req.tokenIn).transferFrom(req.signer, address(this), req.amountIn)) {
            revert TransferFailed();
        }
        if (!IERC20Minimal(req.tokenOut).transfer(req.signer, amountOut)) {
            revert TransferFailed();
        }

        emit SwapExecuted(req.signer, req.tokenIn, req.tokenOut, req.amountIn, amountOut);

        // 5. Log execution telemetry to C (which updates CircuitBreaker without touching D)
        uint256 gasUsed = startGas - gasleft();
        calibration.recordExecution(digest, expectedOut, amountOut, gasUsed);
    }
}
