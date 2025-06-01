# Core Concepts

## What is ZCAP-LD?

ZCAP-LD (Authorization Capabilities for Linked Data) is a specification for implementing capability-based security using Linked Data. It enables fine-grained delegation of authority in decentralized systems.

## Key Components

### 1. Capability

A capability is a token that grants specific permissions to perform actions on a target resource. It contains:

- **Controller**: The entity that created and controls the capability
- **Invoker**: The entity allowed to use the capability
- **Target**: The resource the capability grants access to
- **Actions**: Permitted operations (e.g., read, write)
- **Proof**: Cryptographic proof of authenticity
- **Caveats**: Optional restrictions on usage

### 2. Delegation

Delegation allows a capability holder to create new capabilities with equal or reduced permissions. Key aspects:

- Delegated capabilities form a chain of trust
- Each delegation must be cryptographically signed
- Permissions can only be restricted, never expanded
- Delegation chain is verified during invocation

### 3. Invocation

Invocation is the process of using a capability to perform an action:

1. Present the capability
2. Verify the delegation chain
3. Check all proofs and signatures
4. Validate caveats and restrictions
5. Execute the requested action

### 4. Revocation

Capabilities can be revoked through several mechanisms:

- Explicit revocation by the controller
- Expiration (time-based caveat)
- Status registry checks
- Parent capability revocation

## JSON-LD Context

zcap uses JSON-LD for semantic interoperability:

```json
{
  "@context": [
    "https://w3id.org/security/v2",
    "https://w3id.org/zcap/v1"
  ]
}
```

## Security Model

The security model is based on:

1. **Cryptographic Proofs**: Ed25519 signatures
2. **Delegation Chains**: Verifiable proof of authority
3. **Caveats**: Runtime restrictions
4. **Revocation**: Multiple revocation strategies

For implementation details, see the [API Reference](api-reference.md). 