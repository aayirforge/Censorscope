// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Attestation
 * @notice PROTOTYPE WITH A TRUSTED ARBITER: Implements EIP-712 censorship claim attestations,
 * challenge bond windows, and dispute resolution for high-impact censorship classifications.
 *
 * CAUTION - TRUST MODEL & SECURITY LIMITATIONS:
 * 1. PROTOTYPE WITH A TRUSTED ARBITER: This contract relies on ARBITER_ROLE to unilaterally resolve disputes.
 *    In production, this must be replaced by a decentralized oracle network, UMA optimistic oracle, or multi-sig council.
 * 2. CHALLENGE BOND DESTINATION: When a challenge is upheld (claim was correct), the challenger's forfeited
 *    bond goes to the attestor (`winner = c.attestor`). When overturned, the bond is returned to the challenger.
 * 3. EXPIRED CLAIMS: Claims have an explicit valid lifetime (`claim.timestamp` must not be expired upon submission).
 * 4. REPLAY PROTECTION: Uses nonces and EIP-712 domain separator (which binds chainId and contract address),
 *    preventing cross-chain and cross-contract signature replays.
 */
contract Attestation is AccessControl, Pausable, ReentrancyGuard, EIP712 {
    bytes32 public constant ARBITER_ROLE = keccak256("ARBITER_ROLE");

    bytes32 public constant CLAIM_TYPEHASH = keccak256(
        "CensorshipClaim(string domain,uint256 asn,uint8 verdict,uint256 timestamp,uint256 nonce)"
    );

    enum ClaimStatus {
        Pending,
        Challenged,
        Finalized,
        Overturned
    }

    struct Claim {
        string domain;
        uint256 asn;
        uint8 verdict; // 0=Accessible, 1=Blocked, 2=LikelyBlocked, 3=Inconclusive
        uint64 timestamp;
        uint256 nonce;
        address attestor;
        uint256 challengeBond;
        address challenger;
        uint64 challengeDeadline;
        ClaimStatus status;
    }

    uint64 public constant CHALLENGE_WINDOW = 3 days;
    uint256 public constant CHALLENGE_BOND = 0.1 ether;
    uint64 public constant CLAIM_MAX_AGE = 7 days;

    // Track used nonces per attestor to prevent nonce reuse
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    mapping(bytes32 => Claim) public claims;
    bytes32[] public claimIds;

    event ClaimAttested(bytes32 indexed claimId, string domain, uint256 indexed asn, uint8 verdict, address indexed attestor);
    event ClaimChallenged(bytes32 indexed claimId, address indexed challenger, uint256 bondAmount);
    event ClaimFinalized(bytes32 indexed claimId);
    event ClaimResolved(bytes32 indexed claimId, bool upheld, address recipient, uint256 rewardAmount);

    error ClaimAlreadyExists(bytes32 claimId);
    error ClaimNotFound(bytes32 claimId);
    error ClaimNotPending(bytes32 claimId);
    error ClaimNotChallenged(bytes32 claimId);
    error ChallengeWindowPassed(uint64 currentTime, uint64 deadline);
    error ChallengeWindowNotPassed(uint64 currentTime, uint64 deadline);
    error InsufficientBond(uint256 provided, uint256 required);
    error InvalidSignature();
    error NonceAlreadyUsed(address attestor, uint256 nonce);
    error ClaimExpired(uint64 claimTimestamp, uint64 currentTimestamp);
    error CannotChallengeOwnClaim();
    error TransferFailed();

    constructor(address defaultAdmin, address arbiter)
        EIP712("CensorScopeAttestation", "1")
    {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(ARBITER_ROLE, arbiter);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function computeClaimId(
        string calldata domain,
        uint256 asn,
        uint8 verdict,
        uint64 timestamp,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(domain, asn, verdict, timestamp, nonce));
    }

    /**
     * @notice Submit an EIP-712 signed attestation for a censorship finding.
     */
    function submitAttestation(
        string calldata domain,
        uint256 asn,
        uint8 verdict,
        uint64 timestamp,
        uint256 nonce,
        bytes calldata signature
    ) external whenNotPaused nonReentrant returns (bytes32) {
        if (block.timestamp > timestamp + CLAIM_MAX_AGE) {
            revert ClaimExpired(timestamp, uint64(block.timestamp));
        }
        if (usedNonces[msg.sender][nonce]) {
            revert NonceAlreadyUsed(msg.sender, nonce);
        }

        bytes32 claimId = computeClaimId(domain, asn, verdict, timestamp, nonce);
        if (claims[claimId].timestamp != 0) {
            revert ClaimAlreadyExists(claimId);
        }

        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_TYPEHASH,
                keccak256(bytes(domain)),
                asn,
                verdict,
                timestamp,
                nonce
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (signer != msg.sender) {
            revert InvalidSignature();
        }

        usedNonces[msg.sender][nonce] = true;

        claims[claimId] = Claim({
            domain: domain,
            asn: asn,
            verdict: verdict,
            timestamp: timestamp,
            nonce: nonce,
            attestor: msg.sender,
            challengeBond: 0,
            challenger: address(0),
            challengeDeadline: uint64(block.timestamp) + CHALLENGE_WINDOW,
            status: ClaimStatus.Pending
        });

        claimIds.push(claimId);

        emit ClaimAttested(claimId, domain, asn, verdict, msg.sender);
        return claimId;
    }

    /**
     * @notice Challenge an attestation within the 3-day challenge window by posting CHALLENGE_BOND.
     */
    function challengeClaim(bytes32 claimId) external payable whenNotPaused nonReentrant {
        Claim storage c = claims[claimId];
        if (c.timestamp == 0) {
            revert ClaimNotFound(claimId);
        }
        if (c.status != ClaimStatus.Pending) {
            revert ClaimNotPending(claimId);
        }
        if (msg.sender == c.attestor) {
            revert CannotChallengeOwnClaim();
        }
        if (block.timestamp > c.challengeDeadline) {
            revert ChallengeWindowPassed(uint64(block.timestamp), c.challengeDeadline);
        }
        if (msg.value < CHALLENGE_BOND) {
            revert InsufficientBond(msg.value, CHALLENGE_BOND);
        }

        c.status = ClaimStatus.Challenged;
        c.challenger = msg.sender;
        c.challengeBond = msg.value;

        emit ClaimChallenged(claimId, msg.sender, msg.value);
    }

    /**
     * @notice Finalize an unchallenged claim after the challenge window expires.
     */
    function finalizeClaim(bytes32 claimId) external whenNotPaused {
        Claim storage c = claims[claimId];
        if (c.timestamp == 0) {
            revert ClaimNotFound(claimId);
        }
        if (c.status != ClaimStatus.Pending) {
            revert ClaimNotPending(claimId);
        }
        if (block.timestamp <= c.challengeDeadline) {
            revert ChallengeWindowNotPassed(uint64(block.timestamp), c.challengeDeadline);
        }

        c.status = ClaimStatus.Finalized;
        emit ClaimFinalized(claimId);
    }

    /**
     * @notice Resolve a challenged claim (called by ARBITER_ROLE).
     * @param claimId ID of the claim under dispute.
     * @param upheld True if original attestor was correct; false if challenger was correct.
     */
    function resolveDispute(bytes32 claimId, bool upheld) external onlyRole(ARBITER_ROLE) nonReentrant {
        Claim storage c = claims[claimId];
        if (c.status != ClaimStatus.Challenged) {
            revert ClaimNotChallenged(claimId);
        }

        uint256 bond = c.challengeBond;
        c.challengeBond = 0;

        address winner;
        if (upheld) {
            c.status = ClaimStatus.Finalized;
            winner = c.attestor; // Forfeited bond goes to attestor as compensation
        } else {
            c.status = ClaimStatus.Overturned;
            winner = c.challenger; // Bond refunded to challenger
        }

        (bool success, ) = payable(winner).call{value: bond}("");
        if (!success) {
            revert TransferFailed();
        }

        emit ClaimResolved(claimId, upheld, winner, bond);
    }
}
