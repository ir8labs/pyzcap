# Examples

This section provides examples of how to use the `pyzcap` library. These examples assume you are managing the necessary stateful stores on the client-side. These stores include:

*   `did_key_store`: A dictionary mapping DIDs to their `Ed25519PublicKey` objects.
*   `capability_store`: A dictionary mapping capability IDs to `Capability` objects.
*   `revoked_capabilities`: A set of strings, where each string is the ID of a revoked capability.
*   `used_invocation_nonces`: A set of strings for used nonces to prevent replay attacks.
*   `nonce_timestamps`: A dictionary mapping nonces to their creation `datetime`.

Most functions in the library will raise specific exceptions (e.g., `CapabilityVerificationError`, `InvocationError`) upon failure, rather than returning boolean values.

## Basic Usage

### Creating and Using a Simple Capability

```python
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability, invoke_capability, 
    Capability, ZCAPException, InvocationError, DIDKeyNotFoundError
)

# --- Client-managed stores ---
did_key_store = {}
capability_store = {}
revoked_capabilities = set()
used_invocation_nonces = set()
nonce_timestamps = {}
# ---

# Generate keys for controller (Alice) and invoker (Bob)
alice_did = "did:example:alice"
alice_key = ed25519.Ed25519PrivateKey.generate()
did_key_store[alice_did] = alice_key.public_key()

bob_did = "did:example:bob"
bob_key = ed25519.Ed25519PrivateKey.generate()
did_key_store[bob_did] = bob_key.public_key()

# Alice creates a capability for Bob to read a document
try:
    # Note: controller_did and invoker_did are used
    cap_for_bob = create_capability(
        controller_did=alice_did,
        invoker_did=bob_did,
        actions=[{"name": "read"}],
        target_info={
            "id": "https://example.com/documents/123",
            "type": "Document"
        },
        controller_key=alice_key
    )
    # Client stores the capability object
    capability_store[cap_for_bob.id] = cap_for_bob
    print(f"Capability created: {cap_for_bob.id}")

except ZCAPException as e:
    print(f"Error creating capability: {e}")
    # Handle error appropriately

# Bob uses the capability
if cap_for_bob:
    try:
        # Pass all required stores to invoke_capability
        invocation_proof = invoke_capability(
            capability=cap_for_bob,
            action_name="read",
            invoker_key=bob_key,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps
        )
        print(f"Invocation successful! Proof ID: {invocation_proof['id']}")
        # The target system would then verify this invocation_proof
    except (InvocationError, DIDKeyNotFoundError, ZCAPException) as e:
        print(f"Error invoking capability: {e}")
```

## Document Sharing Example

### Multi-Level Delegation

```python
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability, delegate_capability, invoke_capability,
    Capability, ZCAPException, DelegationError, InvocationError, DIDKeyNotFoundError
)

# --- Client-managed stores (initialize as in Basic Usage) ---
did_key_store = {}
capability_store = {}
revoked_capabilities = set()
used_invocation_nonces = set()
nonce_timestamps = {}
# ---

# Keys and DIDs (replace with actual key generation and DID management)
alice_did = "did:example:alice"; alice_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[alice_did] = alice_key.public_key()
bob_did = "did:example:bob"; bob_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[bob_did] = bob_key.public_key()
charlie_did = "did:example:charlie"; charlie_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[charlie_did] = charlie_key.public_key()

root_capability = None
delegated_capability_for_charlie = None

# Alice creates initial capability for Bob
try:
    root_capability = create_capability(
        controller_did=alice_did,
        invoker_did=bob_did,
        actions=[
            {"name": "read"},
            {"name": "write"}
        ],
        target_info={
            "id": "https://docs.example.com/shared/123",
            "type": "Document",
            "format": "markdown"
        },
        controller_key=alice_key,
        expires=datetime.utcnow() + timedelta(days=30)
    )
    capability_store[root_capability.id] = root_capability
    print(f"Root capability for Bob created: {root_capability.id}")
except ZCAPException as e:
    print(f"Error creating root capability: {e}")

# Bob delegates read-only access to Charlie
if root_capability:
    try:
        delegated_capability_for_charlie = delegate_capability(
            parent_capability=root_capability,
            new_invoker_did=charlie_did,
            delegator_key=bob_key, # Bob (invoker of root_capability) delegates
            actions=[{"name": "read"}], # Explicitly restricting actions
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            expires=datetime.utcnow() + timedelta(days=7) # Can be shorter than parent
        )
        capability_store[delegated_capability_for_charlie.id] = delegated_capability_for_charlie
        print(f"Delegated capability for Charlie created: {delegated_capability_for_charlie.id}")
    except (DelegationError, ZCAPException) as e:
        print(f"Error delegating capability: {e}")

# Charlie uses the delegated capability
if delegated_capability_for_charlie:
    try:
        invocation_proof = invoke_capability(
            capability=delegated_capability_for_charlie,
            action_name="read",
            invoker_key=charlie_key,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps
        )
        print(f"Charlie's invocation successful! Proof ID: {invocation_proof['id']}")
    except (InvocationError, ZCAPException) as e:
        print(f"Charlie's invocation failed: {e}")
```

## Advanced Usage

### Using Caveats

```python
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import create_capability, ZCAPException, Capability

# --- Client-managed stores ---
did_key_store = {}
capability_store = {}
# ... (other stores as needed)
# ---

alice_did = "did:example:alice"; alice_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[alice_did] = alice_key.public_key()
bob_did = "did:example:bob"; # Bob doesn't need a key to be an invoker in a capability definition

# Create a capability with a time-based caveat (ValidUntil)
try:
    capability_with_expiry = create_capability(
        controller_did=alice_did,
        invoker_did=bob_did,
        actions=[{"name": "access"}],
        target_info={
            "id": "https://api.example.com/resource/456",
            "type": "APIEndpoint"
        },
        controller_key=alice_key,
        expires=datetime.utcnow() + timedelta(days=1), # This is one way to set expiry
        caveats=[{
            "type": "ValidUntil", # Specific ZCAP-LD caveat type
            "date": (datetime.utcnow() + timedelta(hours=12)).isoformat() # More restrictive than 'expires'
        }]
    )
    capability_store[capability_with_expiry.id] = capability_with_expiry
    print(f"Capability with ValidUntil caveat created: {capability_with_expiry.id}")
    # This capability will be invalid after 12 hours due to the caveat,
    # or after 1 day due to the main expires field, whichever is sooner.
except ZCAPException as e:
    print(f"Error creating capability with caveat: {e}")
```

### Revocation Example

Revocation is managed by the client by maintaining a list/set of revoked capability IDs. The library functions (`verify_capability`, `invoke_capability`, `delegate_capability`) check this set.

```python
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability, invoke_capability, verify_capability,
    Capability, ZCAPException, InvocationError, CapabilityVerificationError
)

# --- Client-managed stores ---
did_key_store = {}
capability_store = {}
revoked_capabilities = set() # This set holds revoked IDs
used_invocation_nonces = set()
nonce_timestamps = {}
# ---

alice_did = "did:example:alice"; alice_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[alice_did] = alice_key.public_key()
bob_did = "did:example:bob"; bob_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[bob_did] = bob_key.public_key()

# Create a capability
cap_to_revoke = None
try:
    cap_to_revoke = create_capability(
        controller_did=alice_did,
        invoker_did=bob_did,
        actions=[{"name": "access"}],
        target_info={
            "id": "https://example.com/resource/789",
            "type": "Resource"
        },
        controller_key=alice_key
    )
    capability_store[cap_to_revoke.id] = cap_to_revoke
    print(f"Capability created: {cap_to_revoke.id}")
except ZCAPException as e:
    print(f"Error creating capability: {e}")

# Later, Alice (or an authorized entity) decides to revoke the capability
if cap_to_revoke:
    print(f"Revoking capability: {cap_to_revoke.id}")
    revoked_capabilities.add(cap_to_revoke.id)
    print("Capability ID added to revocation list.")

    # Attempt to invoke or verify the revoked capability will now fail
    try:
        print("Attempting to verify revoked capability...")
        verify_capability(
            capability=cap_to_revoke,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities
        )
        print("Verification succeeded (UNEXPECTED for revoked capability)")
    except CapabilityVerificationError as e:
        print(f"Verification failed as expected: {e}")
    
    try:
        print("Attempting to invoke revoked capability...")
        invoke_capability(
            capability=cap_to_revoke, action_name="access", invoker_key=bob_key,
            did_key_store=did_key_store, capability_store=capability_store,
            revoked_capabilities=revoked_capabilities, 
            used_invocation_nonces=used_invocation_nonces, nonce_timestamps=nonce_timestamps
        )
        print("Invocation succeeded (UNEXPECTED for revoked capability)")
    except InvocationError as e: # Or CapabilityVerificationError if verify fails first
        print(f"Invocation failed as expected: {e}")
```

## Cryptographic Operations

### Working with Key Pairs

Key pair generation is handled by standard cryptographic libraries like `cryptography`.

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import create_capability, ZCAPException, Capability

# --- Client-managed stores ---
did_key_store = {}
capability_store = {}
# ---

# Generate a key pair for Alice (controller)
alice_did = "did:example:controller"
alice_private_key = ed25519.Ed25519PrivateKey.generate()
alice_public_key = alice_private_key.public_key()
did_key_store[alice_did] = alice_public_key

# Create a capability using the keys
try:
    capability = create_capability(
        controller_did=alice_did,
        invoker_did="did:example:recipient",
        actions=[{"name": "access"}],
        target_info={"id": "resource:xyz", "type": "Service"},
        controller_key=alice_private_key
    )
    capability_store[capability.id] = capability
    print(f"Capability created: {capability.id}")
except ZCAPException as e:
    print(f"Error: {e}")
```

### Verification Example

The `verify_capability` function checks the entire delegation chain, including individual proofs.
For more granular signature verification, `verify_signature` can be used (see API reference).

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    verify_capability, Capability, 
    ZCAPException, CapabilityVerificationError, DIDKeyNotFoundError
)

# Assume 'delegated_capability' is a Capability object from a previous step
# and all necessary stores ('did_key_store', 'capability_store', 'revoked_capabilities') are populated.

# Example: Verify a delegated capability (which implicitly verifies its chain)
# did_key_store, capability_store, revoked_capabilities must be populated

# if delegated_capability_for_charlie: # From Document Sharing example
#     try:
#         print(f"Verifying capability chain for: {delegated_capability_for_charlie.id}")
#         verify_capability(
#             capability=delegated_capability_for_charlie, 
#             did_key_store=did_key_store,
#             capability_store=capability_store, 
#             revoked_capabilities=revoked_capabilities
#         )
#         print("Capability chain is valid.")
#     except (CapabilityVerificationError, DIDKeyNotFoundError, ZCAPException) as e:
#         print(f"Capability chain verification failed: {e}")

# The detailed example for verification is shown in the Revocation Example above.
# The verify_capability function will raise an exception if any part of the chain is invalid.
print("See 'Revocation Example' for a try-except block with verify_capability.")
print("Or refer to the full example scripts in the /examples directory.")
```

## JSON-LD Structure

### Example Capability Document

A `Capability` object, when serialized (e.g., using its `to_json_ld()` method or `model_dump_json()`), might look like this:

```json
{
    "@context": [
        "https://w3id.org/security/v2",
        "https://w3id.org/zcap/v1"
    ],
    "id": "urn:uuid:some-unique-identifier",
    "type": "zcap",
    "controller": {
        "id": "did:example:alice",
        "type": "Ed25519VerificationKey2020"
    },
    "invoker": {
        "id": "did:example:bob",
        "type": "Ed25519VerificationKey2020"
    },
    "target": {
        "id": "https://example.com/resource/123",
        "type": "Document"
    },
    "action": [
        {"name": "read", "parameters": {}}
    ],
    "created": "2024-01-01T10:00:00Z",
    "expires": "2024-02-01T10:00:00Z",
    "caveats": [
        {"type": "ValidUntil", "date": "2024-01-15T10:00:00Z"}
    ],
    "proof": {
        "id": "urn:uuid:another-uuid",
        "type": "Ed25519Signature2020",
        "created": "2024-01-01T10:00:00Z",
        "verificationMethod": "did:example:alice#key-1",
        "proofPurpose": "capabilityDelegation",
        "proofValue": "z[...signature_value...]"
    }
}
```
Note: The exact output of `to_json_ld()` might vary slightly (e.g. order of keys, inclusion of optional empty fields). The example above illustrates the key components. 