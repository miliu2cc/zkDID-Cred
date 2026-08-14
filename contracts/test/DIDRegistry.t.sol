// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/DIDRegistry.sol";

contract DIDRegistryTest is Test {
    DIDRegistry public registry;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        registry = new DIDRegistry();
    }

    function testRegisterDID() public {
        vm.prank(alice);
        registry.registerDID("did:key:z6MkAlice");
        assertEq(registry.didToController("did:key:z6MkAlice"), alice);
    }

    function testResolveDID() public {
        vm.prank(alice);
        registry.registerDID("did:key:z6MkAlice");
        assertEq(registry.resolveDID("did:key:z6MkAlice"), alice);
    }

    function testRegisterDuplicateFails() public {
        vm.prank(alice);
        registry.registerDID("did:key:z6MkAlice");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(DIDRegistry.DIDAlreadyExists.selector, "did:key:z6MkAlice"));
        registry.registerDID("did:key:z6MkAlice");
    }

    function testRegisterEmptyFails() public {
        vm.expectRevert(DIDRegistry.EmptyDID.selector);
        registry.registerDID("");
    }

    function testTransferControl() public {
        vm.prank(alice);
        registry.registerDID("did:key:z6MkAlice");
        vm.prank(alice);
        registry.transferControl("did:key:z6MkAlice", bob);
        assertEq(registry.didToController("did:key:z6MkAlice"), bob);
        string[] memory bobDids = registry.getDIDsByController(bob);
        assertEq(bobDids.length, 1);
        assertEq(bobDids[0], "did:key:z6MkAlice");
    }

    function testTransferControlUnauthorizedFails() public {
        vm.prank(alice);
        registry.registerDID("did:key:z6MkAlice");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(DIDRegistry.NotController.selector, "did:key:z6MkAlice", bob));
        registry.transferControl("did:key:z6MkAlice", address(0x1234));
    }

    function testDeactivateDID() public {
        vm.prank(alice);
        registry.registerDID("did:key:z6MkAlice");
        vm.prank(alice);
        registry.deactivateDID("did:key:z6MkAlice");
        assertEq(registry.didToController("did:key:z6MkAlice"), address(0));
    }

    function testResolveUnknownFails() public {
        vm.expectRevert(abi.encodeWithSelector(DIDRegistry.DIDNotFound.selector, "did:key:unknown"));
        registry.resolveDID("did:key:unknown");
    }
}
