// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/IssuerRegistry.sol";

contract IssuerRegistryTest is Test {
    IssuerRegistry public registry;
    address schoolA = address(0x5C001A);
    address attacker = address(0xBAD);

    function setUp() public {
        registry = new IssuerRegistry();
    }

    function testConstructorSetsOwner() public view {
        assertEq(registry.owner(), address(this));
    }

    function testAddIssuer() public {
        registry.addIssuer(schoolA, "Beijing University");
        assertTrue(registry.isIssuer(schoolA));
        assertEq(registry.issuerName(schoolA), "Beijing University");
        assertEq(registry.getIssuerCount(), 1);
    }

    function testAddIssuerNotOwnerFails() public {
        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.NotOwner.selector, attacker));
        registry.addIssuer(schoolA, "Evil School");
    }

    function testRemoveIssuer() public {
        registry.addIssuer(schoolA, "Beijing University");
        registry.removeIssuer(schoolA);
        assertFalse(registry.isIssuer(schoolA));
        assertEq(registry.getIssuerCount(), 0);
    }

    function testIsAuthorized() public {
        assertFalse(registry.isAuthorized(schoolA));
        registry.addIssuer(schoolA, "Beijing University");
        assertTrue(registry.isAuthorized(schoolA));
    }

    function testAddDuplicateIssuerFails() public {
        registry.addIssuer(schoolA, "Beijing University");
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.AlreadyIssuer.selector, schoolA));
        registry.addIssuer(schoolA, "Beijing University");
    }
}
