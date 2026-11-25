// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface Vm {
    function startPrank(address) external;
    function stopPrank() external;
}

contract EvidenceAnchorTest {
    // Basic test contract compatible with Foundry forge test
}
