// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {ClientRegistry} from "src/ClientRegistry.sol";

/**
 * @title DeployClientRegistry
 * @notice Foundry deployment script for the ClientRegistry smart contract.
 * @dev Run with `forge script script/Deploy.s.sol --rpc-url <RPC_URL> --private-key <PRIVATE_KEY> --broadcast`
 */
contract DeployClientRegistry is Script {
    function run() external {
        // Start broadcasting transactions using the private key supplied via CLI or environment variable
        vm.startBroadcast();

        // Use the deployer address as admin by default
        address admin = msg.sender;

        // Deploy the contract
        ClientRegistry registry = new ClientRegistry(admin);

        console.log("ClientRegistry deployed at:", address(registry));
        console.log("Admin address:", admin);

        vm.stopBroadcast();
    }
}
