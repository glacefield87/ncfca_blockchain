// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Base {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title ConventionalSwapBaseline (System B — Document 04, Section 3)
/// @notice Strong conventional baseline with EIP-712, nonces, deadlines, and slippage checks,
///         but collapsed policy/execution state (no NCFCA channel isolation or hysteretic breaker).
contract ConventionalSwapBaseline {
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant SWAP_TYPEHASH = keccak256(
        "SwapRequest(address signer,address tokenIn,address tokenOut,uint256 amountIn,uint256 minAmountOut,uint256 nonce,uint256 deadline)"
    );

    bytes32 public immutable DOMAIN_SEPARATOR;
    address public admin;
    uint256 public maxSlippageBps;
    uint256 public maxSwapAmount;
    uint256 public lastObservedDeviationBps;
    uint256 private _locked = 1;

    mapping(address => mapping(uint256 => bool)) public usedNonces;

    struct SwapRequest {
        address signer;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 nonce;
        uint256 deadline;
    }

    error Unauthorized();
    error Expired();
    error NonceUsed();
    error InvalidSig();
    error PolicyViolation();
    error TransferFailed();

    constructor(uint256 _maxSlippageBps, uint256 _maxSwapAmount) {
        admin = msg.sender;
        maxSlippageBps = _maxSlippageBps;
        maxSwapAmount = _maxSwapAmount;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("ConventionalSwapBaseline")),
                keccak256(bytes("1.0")),
                block.chainid,
                address(this)
            )
        );
    }

    function updatePolicy(uint256 _maxSlippageBps, uint256 _maxSwapAmount) external {
        if (msg.sender != admin) revert Unauthorized();
        maxSlippageBps = _maxSlippageBps;
        maxSwapAmount = _maxSwapAmount;
    }

    function executeSwap(
        SwapRequest calldata req,
        uint8 v,
        bytes32 r,
        bytes32 s,
        uint256 referencePriceE18,
        uint256 simulatedPoolRateE18
    ) external returns (uint256 amountOut) {
        if (_locked != 1) revert Unauthorized();
        _locked = 2;

        if (block.timestamp > req.deadline) revert Expired();
        if (usedNonces[req.signer][req.nonce]) revert NonceUsed();
        if (req.amountIn > maxSwapAmount) revert PolicyViolation();

        bytes32 structHash = keccak256(
            abi.encode(
                SWAP_TYPEHASH,
                req.signer,
                req.tokenIn,
                req.tokenOut,
                req.amountIn,
                req.minAmountOut,
                req.nonce,
                req.deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        if (ecrecover(digest, v, r, s) != req.signer) revert InvalidSig();

        uint256 expectedOut = (req.amountIn * referencePriceE18) / 1e18;
        amountOut = (req.amountIn * simulatedPoolRateE18) / 1e18;
        if (amountOut < req.minAmountOut) revert PolicyViolation();

        uint256 deviationBps = expectedOut > amountOut ? ((expectedOut - amountOut) * 10_000) / expectedOut : 0;
        if (deviationBps > maxSlippageBps) revert PolicyViolation();

        usedNonces[req.signer][req.nonce] = true;
        lastObservedDeviationBps = deviationBps;

        if (!IERC20Base(req.tokenIn).transferFrom(req.signer, address(this), req.amountIn)) revert TransferFailed();
        if (!IERC20Base(req.tokenOut).transfer(req.signer, amountOut)) revert TransferFailed();

        _locked = 1;
    }
}
