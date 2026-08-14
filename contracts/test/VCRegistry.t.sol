// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/VCRegistry.sol";

contract VCRegistryTest is Test {
    VCRegistry public registry;
    address issuer = address(0x15A);
    address attacker = address(0xBAD);
    bytes32 constant VC_HASH = keccak256("sample-credential");

    function setUp() public {
        registry = new VCRegistry();
    }

    function testRegisterCredential() public {
        vm.prank(issuer);
        registry.registerCredential(VC_HASH, "did:key:z6MkHolder");
        (address iss, string memory subjectDid, uint256 ts, bool exists, bool revoked) = registry.getCredential(VC_HASH);
        assertTrue(exists);
        assertFalse(revoked);
        assertEq(iss, issuer);
        assertEq(subjectDid, "did:key:z6MkHolder");
        assertEq(ts, block.timestamp);
    }

    function testRegisterDuplicateFails() public {
        vm.prank(issuer);
        registry.registerCredential(VC_HASH, "did:key:z6MkHolder");
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(VCRegistry.CredentialAlreadyExists.selector, VC_HASH));
        registry.registerCredential(VC_HASH, "did:key:z6MkHolder");
    }

    function testRevokeCredential() public {
        vm.prank(issuer);
        registry.registerCredential(VC_HASH, "did:key:z6MkHolder");
        vm.prank(issuer);
        registry.revokeCredential(VC_HASH);
        assertTrue(registry.isRevoked(VC_HASH));
    }

    function testRevokeUnauthorizedFails() public {
        vm.prank(issuer);
        registry.registerCredential(VC_HASH, "did:key:z6MkHolder");
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(VCRegistry.NotIssuer.selector, VC_HASH, attacker));
        registry.revokeCredential(VC_HASH);
    }

    function testRevokeUnknownFails() public {
        vm.expectRevert(abi.encodeWithSelector(VCRegistry.CredentialNotFound.selector, VC_HASH));
        registry.revokeCredential(VC_HASH);
    }
}
