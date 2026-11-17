// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {CircuitBreaker} from "../src/ncfca/CircuitBreaker.sol";
import {DynamicState} from "../src/ncfca/DynamicState.sol";
import {StateContext} from "../src/ncfca/StateContext.sol";
import {RequestVerifier} from "../src/ncfca/RequestVerifier.sol";
import {CalibrationExecution} from "../src/ncfca/CalibrationExecution.sol";
import {SwapExecutor} from "../src/ncfca/SwapExecutor.sol";
import {ConventionalSwapBaseline} from "../src/baseline/ConventionalSwapBaseline.sol";

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract ComparativeBenchmarkTest is Test {
    MockERC20 tokenIn;
    MockERC20 tokenOut;

    // System C (NCFCA)
    CircuitBreaker breaker;
    DynamicState dynamicState;
    StateContext stateContext;
    RequestVerifier verifier;
    CalibrationExecution calibration;
    SwapExecutor executorC;

    // System B (Conventional Baseline)
    ConventionalSwapBaseline baselineB;

    uint256 userKey = 0xB0B;
    address user;
    address controller = address(0xD1);
    address oracle = address(0x51);
    bytes32 constant POLICY_ID = keccak256("ETH_USDC_SWAP");

    function setUp() public {
        user = vm.addr(userKey);
        tokenIn = new MockERC20();
        tokenOut = new MockERC20();

        // Pre-compute addresses for circular immutable wiring (Calibration <-> Breaker, Verifier <-> Executor)
        uint256 nonce = vm.getNonce(address(this));
        address predictedBreaker = vm.computeCreateAddress(address(this), nonce);
        address predictedDynamic = vm.computeCreateAddress(address(this), nonce + 1);
        address predictedContext = vm.computeCreateAddress(address(this), nonce + 2);
        address predictedVerifier = vm.computeCreateAddress(address(this), nonce + 3);
        address predictedCalib = vm.computeCreateAddress(address(this), nonce + 4);
        address predictedExecutor = vm.computeCreateAddress(address(this), nonce + 5);

        // Trigger anomaly at 40 bps (0.40%), reset below 20 bps for 2 consecutive clean swaps
        breaker = new CircuitBreaker(predictedCalib, 40, 20, 2);
        dynamicState = new DynamicState(controller, predictedBreaker);
        stateContext = new StateContext(oracle);
        verifier = new RequestVerifier(predictedDynamic, predictedExecutor);
        calibration = new CalibrationExecution(predictedExecutor, predictedBreaker);
        executorC = new SwapExecutor(predictedVerifier, predictedDynamic, predictedContext, predictedCalib, 300);

        require(address(executorC) == predictedExecutor, "NCFCA wiring mismatch");

        // Configure D policy (max 100 bps slippage, 100 ether max swap) & S price (2,000 USDC/ETH)
        vm.prank(controller);
        dynamicState.setPolicy(POLICY_ID, 100, 100 ether, true);

        vm.prank(oracle);
        stateContext.recordObservation(address(tokenIn), address(tokenOut), 2_000e18, keccak256("CHAINLINK_ETH_USD"));

        // Deploy System B (Conventional Baseline)
        baselineB = new ConventionalSwapBaseline(100, 100 ether);

        // Fund user and liquidity pools
        tokenIn.mint(user, 100 ether);
        tokenOut.mint(address(executorC), 500_000e18);
        tokenOut.mint(address(baselineB), 500_000e18);

        vm.startPrank(user);
        tokenIn.approve(address(executorC), type(uint256).max);
        tokenIn.approve(address(baselineB), type(uint256).max);
        vm.stopPrank();
    }

    function test_CompareGasOverhead_B_vs_C() public {
        // 1. Measure System B swap gas
        ConventionalSwapBaseline.SwapRequest memory reqB = ConventionalSwapBaseline.SwapRequest({
            signer: user,
            tokenIn: address(tokenIn),
            tokenOut: address(tokenOut),
            amountIn: 1 ether,
            minAmountOut: 1_980e18,
            nonce: 1,
            deadline: block.timestamp + 600
        });
        bytes32 digestB = keccak256(
            abi.encodePacked(
                "\x19\x01",
                baselineB.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        baselineB.SWAP_TYPEHASH(),
                        reqB.signer,
                        reqB.tokenIn,
                        reqB.tokenOut,
                        reqB.amountIn,
                        reqB.minAmountOut,
                        reqB.nonce,
                        reqB.deadline
                    )
                )
            )
        );
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(userKey, digestB);

        uint256 gasBeforeB = gasleft();
        baselineB.executeSwap(reqB, vB, rB, sB, 2_000e18, 1_998e18); // 10 bps slippage
        uint256 gasUsedB = gasBeforeB - gasleft();

        // 2. Measure System C (NCFCA) swap gas
        RequestVerifier.TransactionRequest memory reqC = RequestVerifier.TransactionRequest({
            signer: user,
            policyId: POLICY_ID,
            tokenIn: address(tokenIn),
            tokenOut: address(tokenOut),
            amountIn: 1 ether,
            minAmountOut: 1_980e18,
            nonce: 1,
            deadline: block.timestamp + 600
        });
        (uint8 vC, bytes32 rC, bytes32 sC) = vm.sign(userKey, verifier.getDigest(reqC));

        uint256 gasBeforeC = gasleft();
        executorC.executeSwap(reqC, vC, rC, sC, 1_998e18); // 10 bps slippage
        uint256 gasUsedC = gasBeforeC - gasleft();

        console2.log("System B (Conventional) Gas:", gasUsedB);
        console2.log("System C (NCFCA)      Gas:", gasUsedC);
        console2.log("NCFCA Gas Overhead        :", gasUsedC - gasUsedB);
        assertGt(gasUsedC, gasUsedB);
    }

    /// @notice Proves Liveness + Safety: Anomaly freezes D-policy updates, while L-swaps continue executing
    function test_GracefulDegradation_LivenessDuringSuspension() public {
        // Swap 1 experiences 50 bps slippage (within 100 bps policy cap, but >= 40 bps thetaAct)
        RequestVerifier.TransactionRequest memory req1 = RequestVerifier.TransactionRequest({
            signer: user,
            policyId: POLICY_ID,
            tokenIn: address(tokenIn),
            tokenOut: address(tokenOut),
            amountIn: 1 ether,
            minAmountOut: 1_980e18,
            nonce: 1,
            deadline: block.timestamp + 600
        });
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(userKey, verifier.getDigest(req1));
        executorC.executeSwap(req1, v1, r1, s1, 1_990e18); // 50 bps slippage

        // CircuitBreaker is now SUSPENDED -> D-channel writes are frozen
        assertFalse(breaker.isWritePermitted());
        vm.prank(controller);
        vm.expectRevert(DynamicState.CircuitBreakerSuspended.selector);
        dynamicState.setPolicy(POLICY_ID, 200, 200 ether, true);

        // Swap 2 (normal 5 bps slippage) STILL SUCCEEDS on L while D is suspended!
        RequestVerifier.TransactionRequest memory req2 = RequestVerifier.TransactionRequest({
            signer: user,
            policyId: POLICY_ID,
            tokenIn: address(tokenIn),
            tokenOut: address(tokenOut),
            amountIn: 1 ether,
            minAmountOut: 1_980e18,
            nonce: 2,
            deadline: block.timestamp + 600
        });
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(userKey, verifier.getDigest(req2));
        uint256 out2 = executorC.executeSwap(req2, v2, r2, s2, 1_999e18); // 5 bps slippage
        assertEq(out2, 1_999e18);
        assertEq(calibration.traceCount(), 2);
    }
}
