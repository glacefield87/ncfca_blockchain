// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {RequestVerifier} from "../src/ncfca/RequestVerifier.sol";

contract RequestVerifierTest is Test {
    RequestVerifier verifier;

    address executor = address(0xE1);
    uint256 userPrivateKey = 0xA11CE;
    address user;

    uint256 attackerPrivateKey = 0xBAD;
    address attacker;

    bytes32 constant POLICY_ID = keccak256("ETH_USDC_SWAP");

    function setUp() public {
        user = vm.addr(userPrivateKey);
        attacker = vm.addr(attackerPrivateKey);
        verifier = new RequestVerifier(executor);
    }

    function _buildDefaultRequest(uint256 nonce, uint256 deadline)
        internal
        view
        returns (RequestVerifier.TransactionRequest memory)
    {
        return RequestVerifier.TransactionRequest({
            signer: user,
            policyId: POLICY_ID,
            tokenIn: address(0x1111),
            tokenOut: address(0x2222),
            amountIn: 10 ether,
            minAmountOut: 25_000e6,
            nonce: nonce,
            deadline: deadline
        });
    }

    function _signRequest(RequestVerifier.TransactionRequest memory req, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = verifier.getDigest(req);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @notice T01: Valid EIP-712 request verifies and consumes nonce
    function test_T01_ValidRequestSucceeds() public {
        RequestVerifier.TransactionRequest memory req = _buildDefaultRequest(0, block.timestamp + 10 minutes);
        bytes memory sig = _signRequest(req, userPrivateKey);

        vm.prank(executor);
        verifier.verifyAndConsume(req, sig);

        assertEq(verifier.nonces(user), 1);
    }

    /// @notice T02: Forged signature from unauthorized signer is rejected
    function test_T02_RejectForgedSignature() public {
        RequestVerifier.TransactionRequest memory req = _buildDefaultRequest(0, block.timestamp + 10 minutes);
        bytes memory forgedSig = _signRequest(req, attackerPrivateKey);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(RequestVerifier.SignatureMismatch.selector, user, attacker)
        );
        verifier.verifyAndConsume(req, forgedSig);
    }

    /// @notice T03: Replaying an already-consumed request is rejected
    function test_T03_RejectReplayAttack() public {
        RequestVerifier.TransactionRequest memory req = _buildDefaultRequest(0, block.timestamp + 10 minutes);
        bytes memory sig = _signRequest(req, userPrivateKey);

        vm.startPrank(executor);
        verifier.verifyAndConsume(req, sig);

        // Attempt exact replay
        vm.expectRevert(abi.encodeWithSelector(RequestVerifier.InvalidNonce.selector, 1, 0));
        verifier.verifyAndConsume(req, sig);
        vm.stopPrank();
    }

    /// @notice T04: Cross-chain or cross-contract domain mismatch is rejected
    function test_T04_RejectWrongDomainOrChainId() public {
        RequestVerifier.TransactionRequest memory req = _buildDefaultRequest(0, block.timestamp + 10 minutes);
        bytes memory sigOnChain1 = _signRequest(req, userPrivateKey);

        // Simulate chain fork / cross-chain replay on chainId 999
        vm.chainId(999);

        vm.prank(executor);
        vm.expectRevert(); // Recovered address will be random garbage due to changed domainSeparator
        verifier.verifyAndConsume(req, sigOnChain1);
    }

    /// @notice T05: Expired deadline is rejected
    function test_T05_RejectExpiredDeadline() public {
        uint256 deadline = block.timestamp + 5 minutes;
        RequestVerifier.TransactionRequest memory req = _buildDefaultRequest(0, deadline);
        bytes memory sig = _signRequest(req, userPrivateKey);

        // Warp past deadline
        vm.warp(deadline + 1);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(RequestVerifier.RequestExpired.selector, deadline, deadline + 1)
        );
        verifier.verifyAndConsume(req, sig);
    }

    /// @notice T06: Parameter tampering after signing (e.g., lowering minAmountOut) is rejected
    function test_T06_RejectParameterTampering() public {
        RequestVerifier.TransactionRequest memory req = _buildDefaultRequest(0, block.timestamp + 10 minutes);
        bytes memory sig = _signRequest(req, userPrivateKey);

        // Relayer tampers with minAmountOut after user signed
        req.minAmountOut = 1;

        vm.prank(executor);
        vm.expectRevert(); // Digest changes -> recovered signer != user
        verifier.verifyAndConsume(req, sig);
    }
}
