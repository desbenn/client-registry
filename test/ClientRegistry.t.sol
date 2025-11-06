// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "src/ClientRegistry.sol";

contract ClientRegistryTest is Test {
    ClientRegistry registry;
    address admin = address(0xA11CE);
    address issuer = address(0xB0B);
    address revoker = address(0xC0FFEE);
    address alice = address(0xD0E);

    function setUp() public {
        // deploy the contract with admin
        vm.prank(admin);
        registry = new ClientRegistry(admin);

        // grant roles to issuer and revoker
        vm.startPrank(admin);
        registry.grantRole(registry.ISSUER_ROLE(), issuer);
        registry.grantRole(registry.REVOKER_ROLE(), revoker);
        vm.stopPrank();
    }

    function testInitialRoles() public {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(registry.hasRole(registry.ISSUER_ROLE(), admin));
        assertTrue(registry.hasRole(registry.REVOKER_ROLE(), admin));
    }

    function testIssuerCanRegister() public {
        bytes32 dataHash = keccak256(bytes("{\"abi\":\"example\"}"));
        vm.prank(issuer);
        registry.registerClient(alice, dataHash);

        uint256 count = registry.recordCount(alice);
        assertEq(count, 1);

        (address rIssuer,, bytes32 rHash, bool revoked) = registry.latestRecord(alice);
        assertEq(rIssuer, issuer);
        assertEq(rHash, dataHash);
        assertFalse(revoked);
    }

    function testNonIssuerCannotRegister() public {
        bytes32 dataHash = keccak256("payload");
        vm.expectRevert("ClientRegistry: caller is not an issuer");
        vm.prank(address(0x1234));
        registry.registerClient(alice, dataHash);
    }

    function testRevokerCanRevokeLatest() public {
        bytes32 dataHash = keccak256("payload");
        vm.prank(issuer);
        registry.registerClient(alice, dataHash);

        vm.prank(revoker);
        registry.revokeLatest(alice, dataHash);

        (, , bytes32 rHash, bool revoked) = registry.latestRecord(alice);
        assertEq(rHash, dataHash);
        assertTrue(revoked);
    }

    function testRevokeMismatchReverts() public {
        bytes32 h1 = keccak256("one");
        bytes32 h2 = keccak256("two");
        vm.prank(issuer);
        registry.registerClient(alice, h1);

        vm.expectRevert("ClientRegistry: dataHash mismatch");
        vm.prank(revoker);
        registry.revokeLatest(alice, h2);
    }

    function testLatestRecordRevertsWhenNoRecords() public {
        vm.expectRevert("ClientRegistry: no records");
        registry.latestRecord(alice);
    }
}