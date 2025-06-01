# ZCAP-LD - Python Implementation

A pure Python implementation of ZCAP-LD (Authorization Capabilities for Linked Data)
for decentralized identity and access control. This library provides an implementation
of capability-based access control with full chain of delegation, using the [ZCAP-LD specification](https://w3c-ccg.github.io/zcap-spec/).

> **⚠️ WARNING ⚠️**
> zcap is currently in early development and is not suitable for production use.
> The library has not yet undergone an independent security review or audit.

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

- **Revocation**: Client-managed revocation. The library checks a client-provided set of revoked capability IDs.
  - Immediate effect on delegation chain
  - Prevents use of revoked capabilities

- **Error Handling**: Uses specific exceptions for different error conditions (e.g., `SignatureVerificationError`, `CaveatEvaluationError`, `InvocationError`).

## Installation

```bash
pip install zcap
```

## Deviations from the specification

The `zcap` library faithfully implements the core principles of ZCAP-LD as described
in the specification document. The data structures, cryptographic mechanisms,
and processes for delegation, invocation, and caveat evaluation are consistent
with the spec's intent.

### Signature Types

The specification's examples sometimes use older signature types like Ed25519Signature2018 or RsaSignature2016.
This library defaults to Ed25519Signature2020 in its models, which is a more recent standard but conceptually the same. 

### Capability Types

The spec's example proof includes a capabilityChain array. The library's Proof
model doesn't explicitly have this, but the chain is implicitly represented by
the `parentCapability` links and is traversed during verification. 
The `verify_capability` function recursively checks this chain.

### Revocation Mechanism

The spec mentions caveats as a mechanism for revocation (e.g., `ValidWhileTrue`).
The library supports this by allowing evaluate_caveat to check against a revoked_ids set.
The library's general approach of client-managed revoked_capabilities is a practical
way to implement the effect of such a caveat.

### Explicit target field

While the spec example for a root capability mentions parentCapability pointing to
the target, this library (and common ZCAP practice) includes an explicit target field
within the capability document itself, making it self-contained in describing what it's
for. This is generally an improvement for clarity.

### Expiration

The spec mentions expiration as a mechanism for revocation (e.g., `ValidUntil`).
The library supports this by allowing the client to pass an expires datetime to create_capability.

## Quick Start

```python
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability, delegate_capability, invoke_capability, verify_capability,
    Capability, # ZCAP Model
    ZCAPException, # Base ZCAP exception
    DIDKeyNotFoundError, CapabilityNotFoundError, InvocationError
)

# --- 1. Setup: Keys and Client-Managed Stores ---
# Generate keys for Alice (controller), Bob (invoker), and Charlie (delegatee)
alice_key = ed25519.Ed25519PrivateKey.generate()
bob_key = ed25519.Ed25519PrivateKey.generate()
charlie_key = ed25519.Ed25519PrivateKey.generate()

alice_did = "did:example:alice"
bob_did = "did:example:bob"
charlie_did = "did:example:charlie"

# Create a temporary did_key_store (only for demonstration)
did_key_store = {
    alice_did: alice_key.public_key(),
    bob_did: bob_key.public_key(),
    charlie_did: charlie_key.public_key(),
}
capability_store = {}
revoked_capabilities = set()
used_invocation_nonces = set()
nonce_timestamps = {}

# --- 2. Alice creates a capability for Bob ---
try:
    # Note: controller_did, invoker_did, target_info are used
    cap_for_bob = create_capability(
        controller_did=alice_did,
        invoker_did=bob_did,
        actions=[{"name": "read"}],
        target_info={
            "id": "https://example.com/resource/123",
            "type": "Document"
        },
        controller_key=alice_key
    )
    # Client stores the capability
    capability_store[cap_for_bob.id] = cap_for_bob
    print(f"Capability created by Alice for Bob: {cap_for_bob.id}")

except ZCAPException as e:
    print(f"Error creating capability: {e}")
    # Exit or handle error appropriately

# --- 3. Bob delegates the capability to Charlie ---
try:
    if cap_for_bob: # Check if previous step succeeded
        delegated_to_charlie = delegate_capability(
            parent_capability=cap_for_bob,
            delegator_key=bob_key, # Bob (invoker of cap_for_bob) is delegating
            new_invoker_did=charlie_did,
            actions=[{"name": "read"}], # Can be a subset of parent's actions
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities
        )
        # Client stores the delegated capability
        capability_store[delegated_to_charlie.id] = delegated_to_charlie
        print(f"Capability delegated by Bob to Charlie: {delegated_to_charlie.id}")

except ZCAPException as e:
    print(f"Error delegating capability: {e}")

# --- 4. Charlie invokes the delegated capability ---
try:
    if 'delegated_to_charlie' in locals() and delegated_to_charlie: # Check if previous step succeeded
        # Pass all required stores to invoke_capability
        invocation_proof = invoke_capability(
            capability=delegated_to_charlie,
            action_name="read",
            invoker_key=charlie_key,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps
            # parameters can be added if the action requires them
        )
        print(f"Invocation by Charlie successful! Proof ID: {invocation_proof['id']}")
        # The target system would then typically verify this invocation_proof
        # using verify_invocation(...)
except (InvocationError, DIDKeyNotFoundError, CapabilityNotFoundError, ZCAPException) as e:
    print(f"Error invoking capability: {e}")

# --- 5. Revoking a capability (client-side) ---
# To revoke cap_for_bob (and thus implicitly delegated_to_charlie):
if cap_for_bob:
    revoked_capabilities.add(cap_for_bob.id)
    print(f"Capability {cap_for_bob.id} added to revocation list.")

    # Attempting to use delegated_to_charlie would now fail if verified/invoked
    # as its parent is in revoked_capabilities.
    try:
        if 'delegated_to_charlie' in locals() and delegated_to_charlie:
            verify_capability(
                delegated_to_charlie,
                did_key_store,
                revoked_capabilities,
                capability_store
            )
            print("Verification of delegated_to_charlie succeeded (UNEXPECTED after parent revocation)")
    except ZCAPException as e:
        print(f"Verification of delegated_to_charlie failed as expected: {e}")

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
- Revocation of a parent capability (by adding its ID to the client-managed `revoked_capabilities` set) affects the entire delegation chain stemming from it.

### Cryptographic Proofs

The library uses Ed25519 signatures for capability proofs:

- Capabilities are signed by their controller
- Delegations are signed by the delegator (who is the invoker of the parent capability)
- Invocations verify the entire proof chain and relevant signatures
- JSON-LD normalization ensures consistent signing

### Caveats

Caveats are constraints that limit when and how a capability can be used. They are a powerful mechanism for fine-grained authorization control:

- **Evaluation Time**: Caveats are evaluated during capability verification and invocation.
- **Delegation Chain**: All caveats in the entire delegation chain are enforced.
- **Extensible**: The caveat system is designed to be extensible with custom caveat types. The `evaluate_caveat` function can be used directly or extended.

#### Supported Caveat Types (built-in evaluation logic)

1.  **Time-based Caveats**
    *   `ValidUntil`: The capability is only valid until a specific time.
    *   `ValidAfter`: The capability is only valid after a specific time.
    *   Example: `{"type": "ValidUntil", "date": "2023-12-31T23:59:59Z"}`

2.  **Action-specific Caveats**
    *   `AllowedAction`: Restricts which actions can be performed if an action is being invoked.
    *   `RequireParameter`: Requires specific parameter values for actions if an action is being invoked.
    *   Example: `{"type": "AllowedAction", "actions": ["read"]}`

3.  **Conditional Caveats**
    *   `ValidWhileTrue`: The capability is valid as long as a `conditionId` is NOT present in a client-provided set of revoked IDs (passed to `evaluate_caveat` or relevant ZCAP functions).
    *   Example: `{"type": "ValidWhileTrue", "conditionId": "condition:example:active"}`

Caveats like `MaxUses` or `AllowedNetwork` are recognized by structure but require client-side logic to enforce, as the library itself doesn't manage usage counts or client network information. The `evaluate_caveat` function will not error on these if present but also won't enforce them.

#### Example: Combining Caveats

```python
from datetime import datetime, timedelta
# Assume alice_key, alice_did, bob_did, did_key_store, capability_store are set up as in Quick Start

try:
    capability_with_caveats = create_capability(
        controller_did=alice_did,
        invoker_did=bob_did,
        actions=[{"name": "read"}, {"name": "write"}],
        target_info={"id": "https://example.com/resource/123", "type": "Document"},
        controller_key=alice_key,
        caveats=[
            {"type": "ValidUntil", "date": (datetime.utcnow() + timedelta(days=30)).isoformat()},
            {"type": "AllowedAction", "actions": ["read"]}, # Only 'read' will be allowed during invocation
            {"type": "ValidWhileTrue", "conditionId": "subscription:active"}
        ]
    )
    capability_store[capability_with_caveats.id] = capability_with_caveats
    print("Capability with combined caveats created.")
except ZCAPException as e:
    print(f"Error: {e}")
```

#### Adding Caveats During Delegation

```python
# Assume capability_with_caveats, bob_key, charlie_did,
# did_key_store, capability_store, revoked_capabilities are set up.

try:
    delegated_with_caveats = delegate_capability(
        parent_capability=capability_with_caveats,
        delegator_key=bob_key,
        new_invoker_did=charlie_did,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        caveats=[ # These are ADDED to any caveats from parent_capability
            {"type": "RequireParameter", "parameter": "mode", "value": "secure"},
            # {"type": "MaxUses", "limit": 3} # Client would need to track usage
        ]
    )
    capability_store[delegated_with_caveats.id] = delegated_with_caveats
    print("Delegated capability with additional caveats created.")
except ZCAPException as e:
    print(f"Error: {e}")
```

## Examples

The `examples/` directory contains detailed examples demonstrating the new stateless API:

- `basic_usage.py`: Simple capability creation, invocation, and state management.
- `document_sharing.py`: A conceptual document sharing system with delegation.
- `crypto_operations.py`: Focus on signature generation and verification.
- `caveat_examples.py`: Demonstrates various caveat types and their evaluation.

## API Reference

The client is responsible for managing several stateful stores and passing them to the relevant functions:
- `did_key_store: Dict[str, Ed25519PublicKey]`
- `capability_store: Dict[str, Capability]`
- `revoked_capabilities: Set[str]` (for IDs of revoked capabilities)
- `used_invocation_nonces: Set[str]`
- `nonce_timestamps: Dict[str, datetime]` (for nonce expiration)

All functions raise specific exceptions (subclasses of `ZCAPException`) on error.

### Creating Capabilities

```python
def create_capability(
    controller_did: str,
    invoker_did: str,
    actions: List[Dict[str, Any]],
    target_info: Dict[str, Any],
    controller_key: ed25519.Ed25519PrivateKey,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None
) -> Capability:
    """Create a new capability object and sign it."""
```

### Delegating Capabilities

```python
def delegate_capability(
    parent_capability: Capability,
    delegator_key: ed25519.Ed25519PrivateKey,
    new_invoker_did: str,
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
    actions: Optional[List[Dict[str, Any]]] = None,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None
) -> Capability:
    """Create a delegated capability object from a parent capability."""
```

### Invoking Capabilities

```python
def invoke_capability(
    capability: Capability,
    action_name: str,
    invoker_key: ed25519.Ed25519PrivateKey,
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
    used_invocation_nonces: Set[str],
    nonce_timestamps: Dict[str, datetime],
    parameters: Optional[Dict[str, Any]] = None,
    nonce_max_age_seconds: int = 3600
) -> Dict[str, Any]:
    """
    Invoke a capability to perform an action.
    Returns a signed JSON-LD invocation object on success.
    Raises InvocationError or other ZCAPException on failure.
    """
```

### Verifying Capabilities

```python
def verify_capability(
    capability: Capability,
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability]
) -> None:
    """
    Verify a capability and its entire delegation chain.
    Returns None on success, raises CapabilityVerificationError or other ZCAPException on failure.
    """
```

### Verifying Invocations

```python
def verify_invocation(
    invocation_doc: Dict[str, Any],
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability]
) -> None:
    """
    Verify a capability invocation object.
    Returns None on success, raises InvocationVerificationError or other ZCAPException on failure.
    """
```

### Revoking Capabilities (Client-Managed)

Revocation is handled by the client by adding the ID of the capability to be revoked to a `revoked_capabilities: Set[str]`. This set is then passed to functions like `verify_capability`, `invoke_capability`, and `delegate_capability`, which will check it.

### Helper Functions

```python
def sign_capability_document(
    capability_doc: Dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey
) -> str:
    """Sign a capability document (JSON-LD as dict) with an Ed25519 private key."""

def verify_signature(
    signature: str,
    message: str, # The normalized document that was signed
    public_key: ed25519.Ed25519PublicKey
) -> None:
    """Verify a signature. Raises SignatureVerificationError on failure."""

def evaluate_caveat(
    caveat: Dict[str, Any],
    action: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    revoked_ids: Optional[Set[str]] = None
) -> None:
    """Evaluate a caveat. Raises CaveatEvaluationError if not satisfied."""

def cleanup_expired_nonces(
    used_invocation_nonces: Set[str],
    nonce_timestamps: Dict[str, datetime],
    max_age_seconds: int = 3600
) -> None:
    """Remove expired nonces from the provided nonce tracking stores."""
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

1.  **Key Management**: Securely store and manage private keys. The library does not handle key storage.
2.  **Proof Verification**: Always ensure that `verify_capability` and `verify_invocation` are used correctly, passing the appropriate and up-to-date stores.
3.  **Expiration**: Use appropriate expiration times for capabilities.
4.  **Caveats**: Implement and enforce appropriate constraints. Understand which caveats require client-side logic for full enforcement (e.g., `MaxUses`).
5.  **Revocation**: Maintain the `revoked_capabilities` set accurately. For production systems, consider how this set is populated and distributed, possibly using external revocation registries or services.
6.  **Nonce Management**: Properly manage `used_invocation_nonces` and `nonce_timestamps` (including periodic cleanup with `cleanup_expired_nonces`) to prevent replay attacks.

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 