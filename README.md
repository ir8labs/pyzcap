# zcap - Python ZCAP-LD Implementation

A pure Python implementation of ZCAP-LD (Authorization Capabilities for Linked Data)
for decentralized indentity and access control. This library provides a complete
implementation of capability-based access control using the [ZCAP-LD specification](https://w3c-ccg.github.io/zcap-spec/).

> **⚠️ WARNING ⚠️**  
> zcap is currently in early development and is not suitable for production use.
> The library has not yet undergone an independent security review or audit.  
> Use at your own risk for experimental or research purposes only.

## Features

- **Capability Creation**: Generate JSON-LD capabilities with full structure:
  - Controller and invoker identification
  - Allowed actions with parameters
  - Target resource specification
  - Cryptographic proofs
  - Expiration and caveats

- **Delegation**: Chain capabilities via delegation with verifiable cryptographic proofs
  - Subset of parent actions
  - Additional caveats
  - Proof chain validation

- **Invocation**: Secure invocation flow with capability verification
  - Action validation
  - Proof verification
  - Caveat enforcement

- **Revocation**: In-memory tracking of revoked capabilities
  - Immediate effect on delegation chain
  - Prevents use of revoked capabilities

## Installation

```bash
pip install zcap
```

## Quick Start

```python
from zcap import create_capability, delegate_capability, invoke_capability
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate keys
alice_key = ed25519.Ed25519PrivateKey.generate()
bob_key = ed25519.Ed25519PrivateKey.generate()

# Create a capability
capability = create_capability(
    controller="did:example:alice",
    invoker="did:example:bob",
    actions=[{"name": "read"}],
    target={
        "id": "https://example.com/resource/123",
        "type": "Document"
    },
    controller_key=alice_key
)

# Delegate the capability
delegated = delegate_capability(
    parent_capability=capability,
    delegator_key=bob_key,
    new_invoker="did:example:charlie",
    actions=[{"name": "read"}]
)

# Invoke the capability
success = invoke_capability(
    capability=delegated,
    action="read",
    invoker_key=charlie_key
)
```

## Core Concepts

### Capabilities

A capability is a token that grants specific permissions to access a resource. It contains:

- **Controller**: The entity that created the capability
- **Invoker**: The entity allowed to use the capability
- **Actions**: The allowed operations
- **Target**: The resource the capability applies to
- **Proof**: Cryptographic proof of authenticity
- **Caveats**: Additional constraints

### Delegation

Capabilities can be delegated, creating a chain of trust:

- A capability holder can delegate a subset of their permissions
- Each delegation adds to the proof chain
- Delegated capabilities can add more restrictive caveats
- Revocation affects the entire delegation chain

### Cryptographic Proofs

The library uses Ed25519 signatures for capability proofs:

- Capabilities are signed by their controller
- Delegations are signed by the delegator
- Invocations verify the entire proof chain
- JSON-LD normalization ensures consistent signing

### Caveats

Caveats are constraints that limit when and how a capability can be used. They are a powerful mechanism for fine-grained authorization control:

- **Evaluation Time**: Caveats are evaluated during both verification and invocation
- **Delegation Chain**: All caveats in the entire delegation chain are enforced
- **Extensible**: The caveat system is designed to be extensible with custom caveat types

#### Supported Caveat Types

1. **Time-based Caveats**
   - `ValidUntil`: The capability is only valid until a specific time
   - `ValidAfter`: The capability is only valid after a specific time
   - Example: `{"type": "ValidUntil", "date": "2023-12-31T23:59:59Z"}`

2. **Action-specific Caveats**
   - `AllowedAction`: Restricts which actions can be performed
   - `RequireParameter`: Requires specific parameter values for actions
   - Example: `{"type": "AllowedAction", "actions": ["read"]}`

3. **Conditional Caveats**
   - `ValidWhileTrue`: The capability is valid as long as a condition remains true
   - Example: `{"type": "ValidWhileTrue", "conditionId": "condition:example:active"}`

4. **Usage Caveats**
   - `MaxUses`: Limits the number of times a capability can be used
   - Example: `{"type": "MaxUses", "limit": 5}`

5. **Network Caveats**
   - `AllowedNetwork`: Restricts capability use to specific networks
   - Example: `{"type": "AllowedNetwork", "networks": ["192.168.1.0/24"]}`

#### Example: Combining Caveats

```python
# Create a capability with multiple caveats
capability = create_capability(
    controller="did:example:alice",
    invoker="did:example:bob",
    actions=[{"name": "read"}, {"name": "write"}],
    target={"id": "https://example.com/resource/123", "type": "Document"},
    controller_key=alice_key,
    caveats=[
        {"type": "ValidUntil", "date": (datetime.utcnow() + timedelta(days=30)).isoformat()},
        {"type": "AllowedAction", "actions": ["read"]},
        {"type": "ValidWhileTrue", "conditionId": "subscription:active"}
    ]
)
```

#### Adding Caveats During Delegation

```python
# Add more restrictive caveats during delegation
delegated = delegate_capability(
    parent_capability=capability,
    delegator_key=bob_key,
    new_invoker="did:example:charlie",
    caveats=[
        {"type": "RequireParameter", "parameter": "mode", "value": "secure"},
        {"type": "MaxUses", "limit": 3}
    ]
)
```

## Examples

The `examples/` directory contains detailed examples:

- `basic_usage.py`: Simple capability creation and usage
- `document_sharing.py`: Document sharing system with delegation
- `crypto_operations.py`: Detailed cryptographic operations

## API Reference

### Creating Capabilities

```python
def create_capability(
    controller: str,
    invoker: str,
    actions: List[Dict[str, Any]],
    target: Dict[str, Any],
    controller_key: ed25519.Ed25519PrivateKey,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None
) -> Capability:
    """Create a new capability with the specified parameters."""
```

### Delegating Capabilities

```python
def delegate_capability(
    parent_capability: Capability,
    delegator_key: ed25519.Ed25519PrivateKey,
    new_invoker: str,
    actions: Optional[List[Dict[str, Any]]] = None,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None
) -> Capability:
    """Create a delegated capability from a parent capability."""
```

### Invoking Capabilities

```python
def invoke_capability(
    capability: Capability,
    action: str,
    invoker_key: ed25519.Ed25519PrivateKey,
    parameters: Optional[Dict[str, Any]] = None
) -> bool:
    """Invoke a capability to perform an action."""
```

### Verifying Capabilities

```python
def verify_capability(capability: Capability) -> bool:
    """Verify a capability and its entire delegation chain."""
```

### Revoking Capabilities

```python
def revoke_capability(capability_id: str) -> None:
    """Revoke a capability by its ID."""
```

## Development

Requirements:
- Python 3.10+
- PDM (Python package manager)

Setup:
```bash
pdm install
```

Run tests:
```bash
pdm run pytest
```

## Security Considerations

1. **Key Management**: Securely store and manage private keys
2. **Proof Verification**: Always verify the complete delegation chain
3. **Expiration**: Use appropriate expiration times
4. **Caveats**: Implement and enforce appropriate constraints
5. **Revocation**: Consider using external revocation registries for production

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 