// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/EvidenceRegistry.sol";

contract DeployEvidenceRegistry is Script {
    function run() external returns (address registryAddress) {
        // Read private key strictly from environment variable; NEVER hardcoded
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // In development or testnet, deployer receives both admin and publisher roles
        address publisherAddress = vm.envOr("PUBLISHER_ADDRESS", deployer);

        vm.startBroadcast(deployerPrivateKey);

        EvidenceRegistry registry = new EvidenceRegistry(deployer, publisherAddress);
        registryAddress = address(registry);

        vm.stopBroadcast();

        console2.log("EvidenceRegistry successfully deployed to:", registryAddress);
        console2.log("Deployer / Admin address:", deployer);
        console2.log("Publisher address:", publisherAddress);
    }
}
