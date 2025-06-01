# Examples

## Basic Usage

### Creating and Using a Simple Capability

```python
from zcap import create_capability, invoke_capability
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate keys for controller and invoker
controller_key = ed25519.Ed25519PrivateKey.generate()
invoker_key = ed25519.Ed25519PrivateKey.generate()

# Create a capability for reading a document
capability = create_capability(
    controller="did:example:alice",
    invoker="did:example:bob",
    actions=[{"name": "read"}],
    target={
        "id": "https://example.com/documents/123",
        "type": "Document"
    },
    controller_key=controller_key
)

# Use the capability
success = invoke_capability(capability, "read", invoker_key)
```

## Document Sharing Example

### Multi-Level Delegation

```python
from zcap import create_capability, delegate_capability, invoke_capability

# Initial capability (Alice → Bob)
doc_capability = create_capability(
    controller="did:example:alice",
    invoker="did:example:bob",
    actions=[
        {"name": "read"},
        {"name": "write"}
    ],
    target={
        "id": "https://docs.example.com/shared/123",
        "type": "Document",
        "format": "markdown"
    },
    controller_key=alice_key
)

# Bob delegates to Charlie (read-only)
delegated_capability = delegate_capability(
    capability=doc_capability,
    new_invoker="did:example:charlie",
    delegator_key=bob_key,
    restricted_actions=[{"name": "read"}]
)

# Charlie uses the delegated capability
success = invoke_capability(
    capability=delegated_capability,
    action="read",
    invoker_key=charlie_key
)
```

## Advanced Usage

### Using Caveats

```python
from datetime import datetime, timedelta

# Create a capability with time-based caveat
capability_with_expiry = create_capability(
    controller="did:example:alice",
    invoker="did:example:bob",
    actions=[{"name": "access"}],
    target={
        "id": "https://api.example.com/resource/456",
        "type": "APIEndpoint"
    },
    controller_key=alice_key,
    caveats=[{
        "type": "ExpiryCaveat",
        "condition": {
            "expires": (datetime.now() + timedelta(hours=24)).isoformat()
        }
    }]
)
```

### Revocation Example

```python
from zcap import create_capability, revoke_capability

# Create a capability
capability = create_capability(
    controller="did:example:alice",
    invoker="did:example:bob",
    actions=[{"name": "access"}],
    target={
        "id": "https://example.com/resource/789",
        "type": "Resource"
    },
    controller_key=alice_key
)

# Later, revoke the capability
revocation = revoke_capability(
    capability=capability,
    controller_key=alice_key,
    reason="Access no longer required"
)
```

## Cryptographic Operations

### Working with Key Pairs

```python
from zcap.crypto import generate_key_pair, key_to_did

# Generate a key pair
private_key, public_key = generate_key_pair()

# Convert public key to DID
did = key_to_did(public_key)

# Create a capability using the keys
capability = create_capability(
    controller=did,
    invoker="did:example:recipient",
    actions=[{"name": "access"}],
    target={"id": "resource", "type": "Service"},
    controller_key=private_key
)
```

### Verification Example

```python
from zcap import verify_capability_chain, verify_proof

# Verify a delegation chain
chain_valid = verify_capability_chain(delegated_capability)

# Verify a specific proof
proof_valid = verify_proof(capability, public_key)
```

## JSON-LD Structure

### Example Capability Document

```python
# The resulting capability document structure
{
    "@context": [
        "https://w3id.org/security/v2",
        "https://w3id.org/zcap/v1"
    ],
    "id": "urn:uuid:5c21d335-9f3f-4f56-8f39-e33a951d5a87",
    "controller": "did:example:alice",
    "invoker": "did:example:bob",
    "target": {
        "id": "https://example.com/resource/123",
        "type": "Document"
    },
    "actions": [
        {"name": "read"}
    ],
    "proof": {
        "type": "Ed25519Signature2020",
        "created": "2024-03-20T10:00:00Z",
        "verificationMethod": "did:example:alice#key-1",
        "proofPurpose": "capabilityDelegation",
        "proofValue": "z3FoR9..."
    }
}
``` 