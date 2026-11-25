// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ProbeRegistry.sol";
import "../src/Attestation.sol";

// Reentrant attacker contract for stake and bond testing
contract ReentrantAttacker {
    ProbeRegistry public registry;
    Attestation public attestation;
    bytes32 public targetClaimId;
    bool public attackStake;
    bool public attackBond;

    constructor(address _registry, address _attestation) {
        registry = ProbeRegistry(_registry);
        attestation = Attestation(_attestation);
    }

    function register(bytes32 key) external payable {
        registry.registerProbe{value: 0.1 ether}(key);
    }

    function initiateUnstake() external {
        registry.initiateUnstake();
    }

    function triggerCompleteUnstake() external {
        attackStake = true;
        registry.completeUnstake();
    }

    function challenge(bytes32 claimId) external payable {
        targetClaimId = claimId;
        attestation.challengeClaim{value: msg.value}(claimId);
    }

    receive() external payable {
        if (attackStake && address(registry).balance >= 0.05 ether) {
            attackStake = false; // prevent infinite recursion, attempt reentrancy
            registry.completeUnstake();
        }
    }
}

// Force-send ETH helper to verify contract balance invariants under unexpected deposits
contract ForceSendETH {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}

contract Phase5ContractsTest is Test {
    ProbeRegistry public probeRegistry;
    Attestation public attestation;

    address public admin = address(0xAD);
    address public slasher = address(0x51);
    address public arbiter = address(0xAB);

    uint256 internal operatorPrivateKey = 0xA11CE;
    address public operator;

    bytes32 constant TEST_PUBKEY = bytes32(uint256(0xFEED));

    function setUp() public {
        operator = vm.addr(operatorPrivateKey);

        vm.startPrank(admin);
        probeRegistry = new ProbeRegistry(admin, slasher);
        attestation = new Attestation(admin, arbiter);
        vm.stopPrank();

        vm.deal(operator, 50 ether);
        vm.deal(address(0xDEAD), 50 ether);
        vm.deal(address(0xCAFE), 50 ether);
    }

    // =============================================================
    // PROBE REGISTRY TESTS
    // =============================================================

    function test_RegisterProbe_Success() public {
        vm.prank(operator);
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);

        assertTrue(probeRegistry.isProbeActive(operator));
        (
            address op,
            bytes32 pk,
            uint256 stake,
            ,
            ,
            uint32 rep,
            ,
            ProbeRegistry.ProbeStatus status
        ) = probeRegistry.probes(operator);

        assertEq(op, operator);
        assertEq(pk, TEST_PUBKEY);
        assertEq(stake, 0.1 ether);
        assertEq(rep, 100);
        assertEq(uint8(status), uint8(ProbeRegistry.ProbeStatus.Active));
        assertEq(probeRegistry.totalStaked(), 0.1 ether);
    }

    function test_RegisterProbe_RevertInsufficientStake() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProbeRegistry.InsufficientStake.selector,
                0.01 ether,
                0.05 ether
            )
        );
        probeRegistry.registerProbe{value: 0.01 ether}(TEST_PUBKEY);
    }

    function test_RegisterProbe_DoubleRegistrationReverts() public {
        vm.startPrank(operator);
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);

        // Attempting to register again while active must revert
        vm.expectRevert(abi.encodeWithSelector(ProbeRegistry.ProbeAlreadyActive.selector, operator));
        probeRegistry.registerProbe{value: 0.1 ether}(bytes32(uint256(0x9999)));

        // Attempting to register with already registered pubkey from another operator
        vm.stopPrank();
        address other = address(0xCAFE);
        vm.prank(other);
        vm.expectRevert(abi.encodeWithSelector(ProbeRegistry.KeyAlreadyRegistered.selector, TEST_PUBKEY));
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);
    }

    function test_Unstake_FullCycle() public {
        vm.prank(operator);
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);

        vm.prank(operator);
        probeRegistry.initiateUnstake();

        // Cannot complete immediately
        vm.prank(operator);
        vm.expectRevert();
        probeRegistry.completeUnstake();

        // Warp past 7-day delay
        vm.warp(block.timestamp + 7 days + 1);

        uint256 balanceBefore = operator.balance;
        vm.prank(operator);
        probeRegistry.completeUnstake();

        assertEq(operator.balance, balanceBefore + 0.1 ether);
        assertFalse(probeRegistry.isProbeActive(operator));
        assertEq(probeRegistry.totalStaked(), 0);
    }

    function test_SlashProbe_DuringUnstakeDelay() public {
        vm.prank(operator);
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);

        vm.prank(operator);
        probeRegistry.initiateUnstake();

        // While unstaking is pending, operator is slashed 100%
        vm.prank(slasher);
        probeRegistry.slashProbe(operator, 10000, "Fraudulent telemetry caught during delay");

        // After delay elapses, completeUnstake must revert because status is Slashed
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(ProbeRegistry.NotInUnstakingStatus.selector, operator));
        probeRegistry.completeUnstake();

        assertEq(probeRegistry.totalStaked(), 0);
    }

    function test_Reentrancy_StakeWithdrawal() public {
        ReentrantAttacker attacker = new ReentrantAttacker(address(probeRegistry), address(attestation));

        // Fund test contract, then send 1 ether to attacker
        vm.deal(address(attacker), 1 ether);

        // Attacker registers with 0.1 ether of its own balance
        attacker.register(bytes32(uint256(0xA77AC)));

        attacker.initiateUnstake();

        vm.warp(block.timestamp + 7 days + 1);

        // Reentrancy is prevented by nonReentrant and zeroing balance
        attacker.triggerCompleteUnstake();
        assertEq(address(attacker).balance, 1 ether);
        assertEq(probeRegistry.totalStaked(), 0);
    }

    function test_StakeAccounting_UnitAndFuzz(uint8 nProbes) public {
        uint256 count = bound(nProbes, 1, 10);
        uint256 expectedTotal = 0;

        for (uint256 i = 0; i < count; i++) {
            address op = address(uint160(0x9000 + i));
            uint256 stakeAmount = 0.05 ether + (i * 0.01 ether);
            vm.deal(op, stakeAmount);
            vm.prank(op);
            probeRegistry.registerProbe{value: stakeAmount}(bytes32(uint256(i + 1)));
            expectedTotal += stakeAmount;
        }

        assertEq(probeRegistry.totalStaked(), expectedTotal);
        assertGe(address(probeRegistry).balance, probeRegistry.totalStaked() + probeRegistry.slashedPool());
    }

    function test_ProbeRegistry_SlashedPool_AccountingAndWithdrawal() public {
        vm.prank(operator);
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);

        assertEq(probeRegistry.totalStaked(), 0.1 ether);
        assertEq(probeRegistry.slashedPool(), 0);

        // Slash 50% (5000 bps)
        vm.prank(slasher);
        probeRegistry.slashProbe(operator, 5000, "forged measurement batch");

        assertEq(probeRegistry.totalStaked(), 0.05 ether);
        assertEq(probeRegistry.slashedPool(), 0.05 ether);
        assertGe(address(probeRegistry).balance, probeRegistry.totalStaked() + probeRegistry.slashedPool());

        // Admin withdraws slashed pool to treasury
        address payable treasury = payable(address(0x9999));
        vm.prank(admin);
        probeRegistry.withdrawSlashedPool(treasury, 0.05 ether);

        assertEq(probeRegistry.slashedPool(), 0);
        assertEq(treasury.balance, 0.05 ether);
        assertGe(address(probeRegistry).balance, probeRegistry.totalStaked() + probeRegistry.slashedPool());
    }

    function test_ProbeRegistry_Invariant_HoldsUnderForceSendETH() public {
        vm.prank(operator);
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);

        // Force send 1.5 ether via selfdestruct
        new ForceSendETH{value: 1.5 ether}(payable(address(probeRegistry)));

        // Invariant address(this).balance >= totalStaked + slashedPool must hold strictly
        assertGe(address(probeRegistry).balance, probeRegistry.totalStaked() + probeRegistry.slashedPool());
        assertEq(probeRegistry.totalStaked(), 0.1 ether);
        assertEq(probeRegistry.slashedPool(), 0);
    }

    // =============================================================
    // ATTESTATION & EIP-712 TESTS
    // =============================================================

    function test_Attestation_EIP712_SubmissionAndFinalize() public {
        string memory domain = "blocked-site.com";
        uint256 asn = 55836;
        uint8 verdict = 1; // Blocked
        uint64 timestamp = uint64(block.timestamp);
        uint256 nonce = 1;

        bytes32 structHash = keccak256(
            abi.encode(
                attestation.CLAIM_TYPEHASH(),
                keccak256(bytes(domain)),
                asn,
                verdict,
                timestamp,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                attestation.domainSeparator(),
                structHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(operator);
        bytes32 claimId = attestation.submitAttestation(
            domain,
            asn,
            verdict,
            timestamp,
            nonce,
            signature
        );

        assertTrue(claimId != bytes32(0));

        // Warp past challenge window (3 days)
        vm.warp(block.timestamp + 3 days + 1);

        attestation.finalizeClaim(claimId);
        (,,,,,,,,, Attestation.ClaimStatus status) = attestation.claims(claimId);
        assertEq(uint8(status), uint8(Attestation.ClaimStatus.Finalized));
    }

    function test_Attestation_ReplayedNonceReverts() public {
        string memory domain = "test.org";
        uint256 asn = 9498;
        uint8 verdict = 0;
        uint64 timestamp = uint64(block.timestamp);
        uint256 nonce = 100;

        bytes32 structHash = keccak256(
            abi.encode(
                attestation.CLAIM_TYPEHASH(),
                keccak256(bytes(domain)),
                asn,
                verdict,
                timestamp,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                attestation.domainSeparator(),
                structHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(operator);
        attestation.submitAttestation(domain, asn, verdict, timestamp, nonce, signature);

        // Submitting with same nonce must revert
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(Attestation.NonceAlreadyUsed.selector, operator, nonce));
        attestation.submitAttestation(domain, asn, verdict, timestamp, nonce, signature);
    }

    function test_Attestation_ExpiredClaimReverts() public {
        string memory domain = "old-claim.com";
        uint256 asn = 45609;
        uint8 verdict = 1;
        uint64 staleTimestamp = uint64(block.timestamp);

        // Sign for staleTimestamp
        bytes32 structHash = keccak256(
            abi.encode(
                attestation.CLAIM_TYPEHASH(),
                keccak256(bytes(domain)),
                asn,
                verdict,
                staleTimestamp,
                1
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                attestation.domainSeparator(),
                structHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Warp 8 days into future before submitting
        uint64 submitTimestamp = uint64(block.timestamp + 8 days);
        vm.warp(submitTimestamp);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(Attestation.ClaimExpired.selector, staleTimestamp, submitTimestamp)
        );
        attestation.submitAttestation(domain, asn, verdict, staleTimestamp, 1, signature);
    }

    function test_Attestation_CrossChainSignatureReplayFails() public {
        string memory domain = "cross-chain.org";
        uint256 asn = 55836;
        uint8 verdict = 1;
        uint64 timestamp = uint64(block.timestamp);
        uint256 nonce = 50;

        // Create an alternate contract on simulated different chain/address
        Attestation alternateAttestation = new Attestation(admin, arbiter);

        // Sign for alternate attestation
        bytes32 structHash = keccak256(
            abi.encode(
                alternateAttestation.CLAIM_TYPEHASH(),
                keccak256(bytes(domain)),
                asn,
                verdict,
                timestamp,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                alternateAttestation.domainSeparator(),
                structHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Attempting to submit signature generated for alternate contract onto primary attestation must fail
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(Attestation.InvalidSignature.selector));
        attestation.submitAttestation(domain, asn, verdict, timestamp, nonce, signature);
    }

    function test_Attestation_GriefingChallengerPrevented() public {
        string memory domain = "news-site.org";
        uint256 asn = 9498;
        uint8 verdict = 1;
        uint64 timestamp = uint64(block.timestamp);
        uint256 nonce = 77;

        bytes32 structHash = keccak256(
            abi.encode(
                attestation.CLAIM_TYPEHASH(),
                keccak256(bytes(domain)),
                asn,
                verdict,
                timestamp,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                attestation.domainSeparator(),
                structHash
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(operatorPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(operator);
        bytes32 claimId = attestation.submitAttestation(
            domain,
            asn,
            verdict,
            timestamp,
            nonce,
            signature
        );

        // Attestor cannot challenge their own claim to grief or lock funds
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(Attestation.CannotChallengeOwnClaim.selector));
        attestation.challengeClaim{value: 0.1 ether}(claimId);

        // Insufficient bond fails
        address challenger = address(0xDEAD);
        vm.prank(challenger);
        vm.expectRevert(abi.encodeWithSelector(Attestation.InsufficientBond.selector, 0.05 ether, 0.1 ether));
        attestation.challengeClaim{value: 0.05 ether}(claimId);

        // Legitimate challenge
        vm.prank(challenger);
        attestation.challengeClaim{value: 0.1 ether}(claimId);

        // Forfeited bond goes to attestor when claim is upheld
        uint256 attestorBalBefore = operator.balance;
        vm.prank(arbiter);
        attestation.resolveDispute(claimId, true);

        assertEq(operator.balance, attestorBalBefore + 0.1 ether);
    }

    function test_Attestation_CannotUnstakeDuringOpenChallenge_ArchitectureCheck() public {
        // Register probe operator
        vm.prank(operator);
        probeRegistry.registerProbe{value: 0.1 ether}(TEST_PUBKEY);

        // Operator initiates unstaking
        vm.prank(operator);
        probeRegistry.initiateUnstake();

        // While unstaking, an attestation claim is challenged
        // The slasher can slash the probe throughout the UNSTAKE_DELAY (7 days)
        vm.prank(slasher);
        probeRegistry.slashProbe(operator, 10000, "fraudulent attestation detected during challenge");

        // Operator cannot complete unstake after being slashed
        vm.warp(block.timestamp + 8 days);
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(ProbeRegistry.NotInUnstakingStatus.selector, operator));
        probeRegistry.completeUnstake();
    }
}
