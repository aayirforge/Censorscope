// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ProbeRegistry
 * @notice Manages volunteer probe registration, minimum staking, unstaking delay periods,
 * slashing for fraudulent or forged measurements, and reputation tracking.
 *
 * TRUST MODEL & GOVERNANCE:
 * - DEFAULT_ADMIN_ROLE: Controlled by a multi-sig or timelock in production. Can pause/unpause contract
 *   and grant/revoke roles.
 * - SLASHER_ROLE: Authorized to slash probe stakes and update reputation. If compromised, an attacker
 *   could slash legitimate probes (malicious griefing).
 * - UNSTAKE_DELAY: 7 days window ensures reported probes cannot instantly withdraw stake to evade slashing.
 */
contract ProbeRegistry is AccessControl, Pausable, ReentrancyGuard {
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    enum ProbeStatus {
        Inactive,
        Active,
        Unstaking,
        Slashed
    }

    struct Probe {
        address operator;
        bytes32 ed25519PubKey;
        uint256 stakedAmount;
        uint64 registeredAt;
        uint64 unstakeUnlockTime;
        uint32 reputationScore;
        uint32 measurementsSubmitted;
        ProbeStatus status;
    }

    uint256 public constant MINIMUM_STAKE = 0.05 ether;
    uint64 public constant UNSTAKE_DELAY = 7 days;
    uint32 public constant INITIAL_REPUTATION = 100;

    // Total active/unstaking stake tracked for contract balance accounting
    uint256 public totalStaked;
    // Accumulated slashed funds retained in contract
    uint256 public slashedPool;

    // Mapping from probe operator address to Probe details
    mapping(address => Probe) public probes;
    // Mapping from Ed25519 public key hash to operator address to prevent key reuse
    mapping(bytes32 => address) public pubKeyToOperator;

    address[] public activeProbes;

    // Events
    event ProbeRegistered(address indexed operator, bytes32 indexed ed25519PubKey, uint256 stakedAmount);
    event UnstakeInitiated(address indexed operator, uint256 stakedAmount, uint64 unlockTime);
    event UnstakeCompleted(address indexed operator, uint256 returnedAmount);
    event ProbeSlashed(address indexed operator, uint256 slashedAmount, string reason);
    event ReputationUpdated(address indexed operator, uint32 newScore);
    event SlashedPoolWithdrawn(address indexed recipient, uint256 amount);

    // Custom errors
    error InsufficientStake(uint256 provided, uint256 required);
    error ZeroPublicKey();
    error KeyAlreadyRegistered(bytes32 pubKey);
    error ProbeNotActive(address operator);
    error ProbeAlreadyActive(address operator);
    error UnstakePeriodNotElapsed(uint64 currentTime, uint64 unlockTime);
    error NotInUnstakingStatus(address operator);
    error TransferFailed();
    error ZeroAddress();
    error ZeroAmount();

    constructor(address defaultAdmin, address slasher) {
        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
        _grantRole(SLASHER_ROLE, slasher);
    }

    /**
     * @notice Register as a probe operator by depositing at least MINIMUM_STAKE and providing an Ed25519 pubkey.
     * @param ed25519PubKey 32-byte Ed25519 public key corresponding to probe telemetry signatures.
     */
    function registerProbe(bytes32 ed25519PubKey) external payable whenNotPaused nonReentrant {
        if (msg.value < MINIMUM_STAKE) {
            revert InsufficientStake(msg.value, MINIMUM_STAKE);
        }
        if (ed25519PubKey == bytes32(0)) {
            revert ZeroPublicKey();
        }
        if (pubKeyToOperator[ed25519PubKey] != address(0)) {
            revert KeyAlreadyRegistered(ed25519PubKey);
        }

        Probe storage p = probes[msg.sender];
        if (p.status == ProbeStatus.Active || p.status == ProbeStatus.Unstaking) {
            revert ProbeAlreadyActive(msg.sender);
        }

        p.operator = msg.sender;
        p.ed25519PubKey = ed25519PubKey;
        p.stakedAmount = msg.value;
        p.registeredAt = uint64(block.timestamp);
        p.reputationScore = INITIAL_REPUTATION;
        p.measurementsSubmitted = 0;
        p.status = ProbeStatus.Active;

        totalStaked += msg.value;
        pubKeyToOperator[ed25519PubKey] = msg.sender;
        activeProbes.push(msg.sender);

        emit ProbeRegistered(msg.sender, ed25519PubKey, msg.value);
    }

    /**
     * @notice Initiate unstaking. Enforces a 7-day challenge period where stake remains slashable.
     */
    function initiateUnstake() external whenNotPaused {
        Probe storage p = probes[msg.sender];
        if (p.status != ProbeStatus.Active) {
            revert ProbeNotActive(msg.sender);
        }

        p.status = ProbeStatus.Unstaking;
        p.unstakeUnlockTime = uint64(block.timestamp) + UNSTAKE_DELAY;

        emit UnstakeInitiated(msg.sender, p.stakedAmount, p.unstakeUnlockTime);
    }

    /**
     * @notice Complete unstaking and withdraw funds after UNSTAKE_DELAY has elapsed.
     */
    function completeUnstake() external nonReentrant {
        Probe storage p = probes[msg.sender];
        if (p.status != ProbeStatus.Unstaking) {
            revert NotInUnstakingStatus(msg.sender);
        }
        if (block.timestamp < p.unstakeUnlockTime) {
            revert UnstakePeriodNotElapsed(uint64(block.timestamp), p.unstakeUnlockTime);
        }

        uint256 amount = p.stakedAmount;
        p.stakedAmount = 0;
        p.status = ProbeStatus.Inactive;
        totalStaked -= amount;
        delete pubKeyToOperator[p.ed25519PubKey];

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }

        emit UnstakeCompleted(msg.sender, amount);
    }

    /**
     * @notice Slash a probe for submitting forged telemetry or provably false measurements.
     * Can slash during Active or Unstaking states before funds are withdrawn.
     * Slashed funds are burned (or retained in contract) rather than stolen.
     */
    function slashProbe(
        address operator,
        uint256 slashFractionBps,
        string calldata reason
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        Probe storage p = probes[operator];
        if (p.status != ProbeStatus.Active && p.status != ProbeStatus.Unstaking) {
            revert ProbeNotActive(operator);
        }

        uint256 slashAmount = (p.stakedAmount * slashFractionBps) / 10000;
        p.stakedAmount -= slashAmount;
        totalStaked -= slashAmount;
        slashedPool += slashAmount;
        p.reputationScore = 0;
        p.status = ProbeStatus.Slashed;

        delete pubKeyToOperator[p.ed25519PubKey];

        emit ProbeSlashed(operator, slashAmount, reason);
    }

    /**
     * @notice Withdraw accumulated slashed funds to an authorized treasury/burn address.
     * Controlled strictly by DEFAULT_ADMIN_ROLE (DAO multisig/timelock).
     */
    function withdrawSlashedPool(address payable recipient, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (recipient == address(0)) {
            revert ZeroAddress();
        }
        if (amount == 0 || amount > slashedPool) {
            revert ZeroAmount();
        }

        slashedPool -= amount;

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert TransferFailed();
        }

        emit SlashedPoolWithdrawn(recipient, amount);
    }

    /**
     * @notice Adjust reputation score based on validated measurement consistency.
     */
    function updateReputation(address operator, uint32 newScore) external onlyRole(SLASHER_ROLE) {
        Probe storage p = probes[operator];
        if (p.status != ProbeStatus.Active) {
            revert ProbeNotActive(operator);
        }
        p.reputationScore = newScore;
        emit ReputationUpdated(operator, newScore);
    }

    /**
     * @notice Check whether a probe operator is currently active and eligible to submit reports.
     */
    function isProbeActive(address operator) external view returns (bool) {
        return probes[operator].status == ProbeStatus.Active;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
