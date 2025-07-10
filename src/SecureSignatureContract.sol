// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title SecureSignatureContract
 * @dev This contract demonstrates the secure way to handle signature verification
 * by properly validating ecrecover results and using OpenZeppelin's ECDSA library.
 */
contract SecureSignatureContract {
    mapping(address => bool) public authorizedUsers;
    mapping(bytes32 => bool) public usedHashes;
    
    event UserAuthorized(address indexed user, bytes32 indexed hash);
    event InvalidSignatureRejected(address indexed signer, bytes32 indexed hash);
    
    /**
     * @dev Secure function that recovers signer from signature with proper validation
     * @param v The v component of the signature
     * @param r The r component of the signature  
     * @param s The s component of the signature
     * @param hash The hash that was signed
     * @param user The user to authorize
     */
    function authorizeUser(
        uint8 v, 
        bytes32 r, 
        bytes32 s, 
        bytes32 hash,
        address user
    ) external {
        // SECURE: Proper validation of ecrecover result
        address signer = ecrecover(hash, v, r, s);
        
        // CRITICAL FIX: Check that ecrecover returned a valid address
        require(signer != address(0), "Invalid signature");
        
        // Check if hash has been used before
        require(!usedHashes[hash], "Hash already used");
        
        // Mark hash as used
        usedHashes[hash] = true;
        
        // Authorize the user
        authorizedUsers[user] = true;
        
        emit UserAuthorized(user, hash);
    }
    
    /**
     * @dev Alternative secure implementation using OpenZeppelin's ECDSA library
     * This is the recommended approach as it handles all edge cases automatically
     */
    function authorizeUserWithECDSA(
        bytes memory signature,
        bytes32 hash,
        address user
    ) external {
        // This would use OpenZeppelin's ECDSA.recover() which automatically
        // reverts on invalid signatures
        // address signer = ECDSA.recover(hash, signature);
        
        // For demonstration, we'll use ecrecover with proper validation
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r; // 32 bytes
        bytes32 s; // 32 bytes
        uint8 v; //2 byte
        
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        
        // Handle malleability
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) { // @audit SIGNATURE MALLEABILITY PROTECTION
            revert("Invalid signature 's' value");
        }
        
        if (v != 27 && v != 28) { // v must be either 27 or 28 for legacy Ethereum signatures.
            revert("Invalid signature 'v' value"); // Some off-chain signing tools may use 0/1 instead, which would need conversion, but this code assumes canonical Ethereum values.
        }
        
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature"); // @audit SIGNATURE VALIDATION PROTECTION
        
        // Check if hash has been used before
        require(!usedHashes[hash], "Hash already used"); // @audit REPLAY ATTACK PROTECTION
        
        // Mark hash as used
        usedHashes[hash] = true;
        
        // Authorize the user
        authorizedUsers[user] = true;
        
        emit UserAuthorized(user, hash);
    }
    
    /**
     * @dev Function that requires authorization
     * @param data Some data to process
     */
    function processData(string memory data) external view returns (bool) {
        require(authorizedUsers[msg.sender], "Not authorized");
        return true;
    }
    
    /**
     * @dev Check if a user is authorized
     * @param user The user to check
     * @return bool True if user is authorized
     */
    function isAuthorized(address user) external view returns (bool) {
        return authorizedUsers[user];
    }
    
    /**
     * @dev Get the signer from a signature (secure version)
     * @param v The v component of the signature
     * @param r The r component of the signature
     * @param s The s component of the signature
     * @param hash The hash that was signed
     * @return address The recovered signer address
     */
    function recoverSigner(
        uint8 v, 
        bytes32 r, 
        bytes32 s, 
        bytes32 hash
    ) external pure returns (address) {
        // SECURE: Validate ecrecover result
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signature");
        return signer;
    }
    
    /**
     * @dev Create a hash for authorization
     * @param user The user to authorize
     * @param nonce A unique nonce
     * @return bytes32 The hash to be signed
     */
    function createAuthorizationHash(
        address user, 
        uint256 nonce
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, nonce));
    }
} 