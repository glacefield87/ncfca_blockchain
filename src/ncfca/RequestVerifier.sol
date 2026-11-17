// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IDynamicState {
    struct Policy {
        uint256 maxSlippageBps;
        uint256 maxSwapAmount;
        bool active;
    }

    function getPolicy(bytes32 policyId) external view returns (Policy memory);
}

/// @title RequestVerifier (External R-Object Validator — Document 07, Section 8)
/// @notice Verifies EIP-712 typed TransactionRequests without holding write authority over D or L.
contract RequestVerifier {
    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 public constant TRANSACTION_REQUEST_TYPEHASH = keccak256(
        "TransactionRequest(address signer,bytes32 policyId,address tokenIn,address tokenOut,uint256 amountIn,uint256 minAmountOut,uint256 nonce,uint256 deadline)"
    );

    bytes32 public immutable DOMAIN_SEPARATOR;
    IDynamicState public immutable dynamicState;
    address public immutable authorizedExecutor;

    /// @notice Tracks consumed nonces per signer to prevent replay attacks (T03)
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    struct TransactionRequest {
        address signer;
        bytes32 policyId;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        uint256 nonce;
        uint256 deadline;
    }

    event RequestVerified(address indexed signer, bytes32 indexed requestHash, uint256 nonce);

    error UnauthorizedExecutor(address caller);
    error RequestExpired(uint256 deadline, uint256 currentTimestamp);
    error NonceAlreadyUsed(address signer, uint256 nonce);
    error InvalidSignature();
    error InactivePolicy(bytes32 policyId);
    error ExceedsPolicyMaxAmount(uint256 amountIn, uint256 maxSwapAmount);

    constructor(address _dynamicState, address _authorizedExecutor) {
        dynamicState = IDynamicState(_dynamicState);
        authorizedExecutor = _authorizedExecutor;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("NCFCA-TransactionVerifier")),
                keccak256(bytes("0.2")),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Computes the EIP-712 struct hash for a TransactionRequest (R)
    function hashRequest(TransactionRequest calldata req) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TRANSACTION_REQUEST_TYPEHASH,
                req.signer,
                req.policyId,
                req.tokenIn,
                req.tokenOut,
                req.amountIn,
                req.minAmountOut,
                req.nonce,
                req.deadline
            )
        );
    }

    /// @notice Computes the full EIP-712 digest bound to chainId and verifyingContract (T04/T05)
    function getDigest(TransactionRequest calldata req) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashRequest(req)));
    }

    /// @notice Validates signature, deadline, nonce, and read-only D-channel bounds.
    /// @dev Only callable by the authorized L-executor so attackers cannot burn nonces via griefing.
    function verifyAndConsume(
        TransactionRequest calldata req,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bytes32 digest) {
        if (msg.sender != authorizedExecutor) {
            revert UnauthorizedExecutor(msg.sender);
        }

        // T06: Deadline enforcement
        if (block.timestamp > req.deadline) {
            revert RequestExpired(req.deadline, block.timestamp);
        }

        // T03: Replay protection
        if (usedNonces[req.signer][req.nonce]) {
            revert NonceAlreadyUsed(req.signer, req.nonce);
        }

        // T01/T02/T04/T05: EIP-712 signature verification with malleability guard (EIP-2)
        if (
            req.signer == address(0) ||
            uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0 ||
            (v != 27 && v != 28)
        ) {
            revert InvalidSignature();
        }

        digest = getDigest(req);
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != req.signer) {
            revert InvalidSignature();
        }

        // Read-only check against protected D-channel policy (no writes to D)
        IDynamicState.Policy memory policy = dynamicState.getPolicy(req.policyId);
        if (!policy.active) {
            revert InactivePolicy(req.policyId);
        }
        if (req.amountIn > policy.maxSwapAmount) {
            revert ExceedsPolicyMaxAmount(req.amountIn, policy.maxSwapAmount);
        }

        usedNonces[req.signer][req.nonce] = true;
        emit RequestVerified(req.signer, digest, req.nonce);
    }
}
