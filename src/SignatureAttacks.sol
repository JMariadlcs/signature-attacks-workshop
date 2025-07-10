// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title VulnerableSignatureContract
 * @dev This contract demonstrates a signature-related vulnerability where ecrecover
 * is used without proper validation, allowing invalid signatures to pass as valid.
 */
contract VulnerableSignatureContract {
    mapping(address => bool) public authorizedUsers;
    mapping(bytes32 => bool) public usedHashes;
    
    event UserAuthorized(address indexed user, bytes32 indexed hash);
    event InvalidSignatureUsed(address indexed signer, bytes32 indexed hash);
    
    /**
     * @dev Vulnerable function that recovers signer from signature without validation
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
        // VULNERABILITY: Missing validation of ecrecover result
        address signer = ecrecover(hash, v, r, s);
        
        // This check is missing: require(signer != address(0), "Invalid signature");
        
        // Check if hash has been used before
        require(!usedHashes[hash], "Hash already used");
        
        // Mark hash as used
        usedHashes[hash] = true;
        
        // Authorize the user
        authorizedUsers[user] = true;
          
        emit UserAuthorized(user, hash);
        
        // If signer is address(0), this indicates an invalid signature
        if (signer == address(0)) {
            emit InvalidSignatureUsed(signer, hash);
        }
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
     * @dev Get the signer from a signature (vulnerable version)
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
        // VULNERABILITY: No validation of ecrecover result
        address signer = ecrecover(hash, v, r, s);
        return signer; // This can return address(0) for invalid signatures
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
