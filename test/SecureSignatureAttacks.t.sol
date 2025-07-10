// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/SecureSignatureContract.sol";

contract SecureSignatureAttacksTest is Test {
    SecureSignatureContract public secureContract;
    
    // Test accounts
    address public alice = address(0x1);
    address public bob = address(0x2);
    address public attacker = address(0x3);
    
    function setUp() public {
        secureContract = new SecureSignatureContract();
    }
    
    function testValidSignature() public {
        // Create a valid signature
        bytes32 hash = secureContract.createAuthorizationHash(bob, 1);
        
        // Sign the hash with Alice's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash); // private key 1 corresponds to alice
        
        // Authorize Bob using Alice's signature
        secureContract.authorizeUser(v, r, s, hash, bob);
        
        // Verify Bob is now authorized
        assertTrue(secureContract.isAuthorized(bob));
    }
    
    function testRejectsInvalidSignature() public {
        // Create a hash
        bytes32 hash = secureContract.createAuthorizationHash(attacker, 1);
        
        // Use invalid signature components that will cause ecrecover to return address(0)
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);
        
        // This should now fail due to the security fix
        vm.expectRevert("Invalid signature");
        secureContract.authorizeUser(v, r, s, hash, attacker);
        
        // The attacker should not be authorized
        assertFalse(secureContract.isAuthorized(attacker));
    }
    
    function testRejectsMalformedSignature() public {
        // Create a hash
        bytes32 hash = secureContract.createAuthorizationHash(attacker, 2);
        
        // Use malformed signature components
        uint8 v = 255; // Invalid v value
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));
        
        // This should also fail due to the security fix
        vm.expectRevert("Invalid signature");
        secureContract.authorizeUser(v, r, s, hash, attacker);
        
        // The attacker should not be authorized
        assertFalse(secureContract.isAuthorized(attacker));
    }
    
    function testRecoverSignerRejectsInvalidSignature() public {
        // Test the recoverSigner function with invalid signature
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);
        bytes32 hash = keccak256("test");
        
        // This should revert due to the security fix
        vm.expectRevert("Invalid signature");
        secureContract.recoverSigner(v, r, s, hash);
    }
    
    function testReplayAttack() public {
        // Create a valid signature
        bytes32 hash = secureContract.createAuthorizationHash(bob, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);
        
        // First authorization should succeed
        secureContract.authorizeUser(v, r, s, hash, bob);
        
        // Try to use the same signature again (should fail due to hash reuse protection)
        vm.expectRevert("Hash already used");
        secureContract.authorizeUser(v, r, s, hash, bob);
    }
    
    function testProcessDataRequiresAuthorization() public {
        // Try to process data without authorization
        vm.expectRevert("Not authorized");
        secureContract.processData("test data");
        
        // Authorize the caller
        bytes32 hash = secureContract.createAuthorizationHash(address(this), 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);
        secureContract.authorizeUser(v, r, s, hash, address(this));
        
        // Now should be able to process data
        assertTrue(secureContract.processData("test data"));
    }
} 