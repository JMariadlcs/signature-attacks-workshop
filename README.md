# Signature-Related Attacks Workshop

This workshop demonstrates a critical vulnerability in smart contract signature verification systems and how to properly secure them.

## Vulnerability: Missing Validation in ecrecover

### Overview

The `ecrecover` function in Solidity is used to recover the signer's address from a digital signature. However, when `ecrecover` encounters invalid signature parameters, it returns `address(0)` instead of reverting. If this return value is not properly validated, attackers can exploit the system by providing invalid signatures.

### The Problem

```solidity
function recover(uint8 v, bytes32 r, bytes32 s, bytes32 hash) external {
    address signer = ecrecover(hash, v, r, s);
    // VULNERABILITY: No validation of signer address
    // Do more stuff with the hash
}
```

**What happens:**
- When `ecrecover` receives invalid signature parameters, it returns `address(0)`
- Without validation, the contract continues execution as if the signature was valid
- Attackers can provide arbitrary invalid signatures and still pass authorization checks

### Attack Scenarios

1. **Invalid Signature Components**: Using `v=0`, `r=0`, `s=0` causes `ecrecover` to return `address(0)`
2. **Malformed Signatures**: Using invalid `v` values (not 27 or 28) or invalid `s` values
3. **Replay Attacks**: Reusing valid signatures multiple times (mitigated by hash tracking)

## Files in this Workshop

### Vulnerable Contract
- `src/SignatureAttacks.sol` - Contains `VulnerableSignatureContract` with the vulnerability

### Secure Contract
- `src/SecureSignatureContract.sol` - Contains `SecureSignatureContract` with proper validation

### Tests
- `test/SignatureAttacks.t.sol` - Demonstrates the vulnerability exploitation
- `test/SecureSignatureAttacks.t.sol` - Shows how the secure version prevents attacks

## Running the Workshop

### Prerequisites
- Foundry installed
- Basic understanding of Solidity and digital signatures

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd signature-attacks-workshop

# Install dependencies
forge install
```

### Running Tests

**Test the vulnerable contract:**
```bash
forge test --match-contract SignatureAttacksTest
```

**Test the secure contract:**
```bash
forge test --match-contract SecureSignatureAttacksTest
```

**Run all tests:**
```bash
forge test
```

## Vulnerability Demonstration

### Test Results - Vulnerable Contract
```
[PASS] testVulnerabilityWithInvalidSignature() 
[PASS] testVulnerabilityWithMalformedSignature()
```

These tests pass because the vulnerable contract accepts invalid signatures!

### Test Results - Secure Contract
```
[PASS] testRejectsInvalidSignature()
[PASS] testRejectsMalformedSignature()
```

These tests pass because the secure contract properly rejects invalid signatures.

## The Fix

### 1. Basic Validation
```solidity
function secureRecover(uint8 v, bytes32 r, bytes32 s, bytes32 hash) external {
    address signer = ecrecover(hash, v, r, s);
    require(signer != address(0), "Invalid signature");
    // Continue with valid signer
}
```

### 2. Recommended: Use OpenZeppelin's ECDSA Library
```solidity
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function secureRecoverWithECDSA(bytes memory signature, bytes32 hash) external {
    address signer = ECDSA.recover(hash, signature);
    // ECDSA.recover automatically reverts on invalid signatures
}
```

### 3. Additional Security Measures

**Handle Signature Malleability:**
```solidity
// Check s value is in the lower half of the curve order
if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
    revert("Invalid signature 's' value");
}

// Check v value is valid
if (v != 27 && v != 28) {
    revert("Invalid signature 'v' value");
}
```

**Prevent Replay Attacks:**
```solidity
mapping(bytes32 => bool) public usedHashes;

function authorizeUser(...) external {
    require(!usedHashes[hash], "Hash already used");
    usedHashes[hash] = true;
    // ... rest of function
}
```

## Key Takeaways

1. **Always validate `ecrecover` results** - Check that the returned address is not `address(0)`
2. **Use OpenZeppelin's ECDSA library** - It handles edge cases automatically
3. **Implement replay protection** - Track used hashes to prevent signature reuse
4. **Handle signature malleability** - Validate `v` and `s` values
5. **Test thoroughly** - Include tests for invalid signatures, malformed signatures, and replay attacks

## Real-World Impact

This vulnerability has been exploited in several real-world scenarios:
- Unauthorized access to privileged functions
- Bypassing authorization checks
- Gaining admin privileges in governance systems
- Exploiting token transfer mechanisms

## Additional Resources

- [OpenZeppelin ECDSA Documentation](https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA)
- [Consensys Smart Contract Best Practices](https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/)
- [SWC-117: Signature Malleability](https://swcregistry.io/docs/SWC-117)
# signature-attacks-workshop
