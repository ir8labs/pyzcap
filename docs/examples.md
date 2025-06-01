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
import asyncio
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability, invoke_capability, verify_capability,
    Capability, ZCAPException, InvocationError, DIDKeyNotFoundError, CapabilityVerificationError
)

# --- Client-managed stores ---
did_key_store = {}
capability_store = {}
revoked_capabilities = set()
used_invocation_nonces = set()
nonce_timestamps = {}
# ---

async def basic_usage_example():
    # Generate keys for controller (Alice) and invoker (Bob)
    alice_did = "did:example:alice"
    alice_key = ed25519.Ed25519PrivateKey.generate()
    did_key_store[alice_did] = alice_key.public_key()

    bob_did = "did:example:bob"
    bob_key = ed25519.Ed25519PrivateKey.generate()
    did_key_store[bob_did] = bob_key.public_key()

    cap_for_bob = None
    # Alice creates a capability for Bob to read a document
    try:
        cap_for_bob = await create_capability(
            controller_did=alice_did,
            invoker_did=bob_did,
            actions=[{"name": "read"}],
            target_info={
                "id": "https://example.com/documents/123",
                "type": "Document"
            },
            controller_key=alice_key
        )
        capability_store[cap_for_bob.id] = cap_for_bob
        print(f"Capability created: {cap_for_bob.id}")

    except ZCAPException as e:
        print(f"Error creating capability: {e}")
        return

    # Optionally, Bob (or Alice, or a third party) verifies the capability
    try:
        await verify_capability(cap_for_bob, did_key_store, revoked_capabilities, capability_store)
        print(f"Capability {cap_for_bob.id} verified successfully.")
    except CapabilityVerificationError as e:
        print(f"Capability {cap_for_bob.id} failed verification: {e}")
        return

    # Bob uses the capability
    try:
        invocation_proof = await invoke_capability(
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
        # The target system would then verify this invocation_proof using verify_invocation
    except (InvocationError, DIDKeyNotFoundError, ZCAPException) as e:
        print(f"Error invoking capability: {e}")

if __name__ == "__main__":
    asyncio.run(basic_usage_example())

## Document Sharing Example

### Multi-Level Delegation

```python
import asyncio
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability, delegate_capability, invoke_capability, verify_capability,
    Capability, ZCAPException, DelegationError, InvocationError, DIDKeyNotFoundError, CapabilityVerificationError
)

# --- Client-managed stores (initialize as in Basic Usage) ---
did_key_store = {}
capability_store = {}
revoked_capabilities = set()
used_invocation_nonces = set()
nonce_timestamps = {}
# ---

async def document_sharing_example():
    # Keys and DIDs
    alice_did = "did:example:alice"; alice_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[alice_did] = alice_key.public_key()
    bob_did = "did:example:bob"; bob_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[bob_did] = bob_key.public_key()
    charlie_did = "did:example:charlie"; charlie_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[charlie_did] = charlie_key.public_key()

    root_capability = None
    delegated_capability_for_charlie = None

    # Alice creates initial capability for Bob
    try:
        root_capability = await create_capability(
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
        return
    
    # Verify root capability before delegation (good practice)
    try:
        await verify_capability(root_capability, did_key_store, revoked_capabilities, capability_store)
        print(f"Root capability {root_capability.id} verified.")
    except CapabilityVerificationError as e:
        print(f"Root capability {root_capability.id} invalid: {e}")
        return

    # Bob delegates read-only access to Charlie
    try:
        delegated_capability_for_charlie = await delegate_capability(
            parent_capability=root_capability,
            new_invoker_did=charlie_did,
            delegator_key=bob_key, 
            actions=[{"name": "read"}],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            expires=datetime.utcnow() + timedelta(days=7)
        )
        capability_store[delegated_capability_for_charlie.id] = delegated_capability_for_charlie
        print(f"Delegated capability for Charlie created: {delegated_capability_for_charlie.id}")
    except (DelegationError, ZCAPException) as e:
        print(f"Error delegating capability: {e}")
        return
    
    # Verify delegated capability
    try:
        await verify_capability(delegated_capability_for_charlie, did_key_store, revoked_capabilities, capability_store)
        print(f"Delegated capability {delegated_capability_for_charlie.id} verified.")
    except CapabilityVerificationError as e:
        print(f"Delegated capability {delegated_capability_for_charlie.id} invalid: {e}")
        return

    # Charlie uses the delegated capability
    try:
        invocation_proof = await invoke_capability(
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

if __name__ == "__main__":
    asyncio.run(document_sharing_example())

## Advanced Usage

### Using Caveats

```python
import asyncio
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import create_capability, ZCAPException, Capability, verify_capability, CapabilityVerificationError

# --- Client-managed stores ---
did_key_store = {}
capability_store = {}
revoked_capabilities = set()
# ... (other stores as needed)
# ---

async def caveat_example():
    alice_did = "did:example:alice"; alice_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[alice_did] = alice_key.public_key()
    bob_did = "did:example:bob"; 

    capability_with_expiry = None
    # Create a capability with a time-based caveat (ValidUntil)
    try:
        capability_with_expiry = await create_capability(
            controller_did=alice_did,
            invoker_did=bob_did,
            actions=[{"name": "access"}],
            target_info={
                "id": "https://api.example.com/resource/456",
                "type": "APIEndpoint"
            },
            controller_key=alice_key,
            expires=datetime.utcnow() + timedelta(days=1),
            caveats=[{
                "type": "ValidUntil",
                "date": (datetime.utcnow() + timedelta(hours=12)).isoformat()
            }]
        )
        capability_store[capability_with_expiry.id] = capability_with_expiry
        print(f"Capability with ValidUntil caveat created: {capability_with_expiry.id}")
    except ZCAPException as e:
        print(f"Error creating capability with caveat: {e}")
        return

    # Verify the capability with caveat
    if capability_with_expiry:
        try:
            await verify_capability(capability_with_expiry, did_key_store, revoked_capabilities, capability_store)
            print(f"Capability {capability_with_expiry.id} with caveat verified (should be valid now).")
        except CapabilityVerificationError as e:
            print(f"Capability {capability_with_expiry.id} with caveat failed verification: {e}")

if __name__ == "__main__":
    asyncio.run(caveat_example())

### Revocation Example

Revocation is managed by the client by maintaining a list/set of revoked capability IDs. The library functions (`verify_capability`, `invoke_capability`, `delegate_capability`) check this set.

```python
import asyncio
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability, invoke_capability, verify_capability,
    Capability, ZCAPException, InvocationError, CapabilityVerificationError
)

# --- Client-managed stores ---
did_key_store = {}
capability_store = {}
revoked_capabilities = set()
used_invocation_nonces = set()
nonce_timestamps = {}
# ---

async def revocation_example():
    alice_did = "did:example:alice"; alice_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[alice_did] = alice_key.public_key()
    bob_did = "did:example:bob"; bob_key = ed25519.Ed25519PrivateKey.generate(); did_key_store[bob_did] = bob_key.public_key()

    cap_to_revoke = None
    # Create a capability
    try:
        cap_to_revoke = await create_capability(
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
        return

    # Verify it (should be valid)
    try:
        await verify_capability(cap_to_revoke, did_key_store, revoked_capabilities, capability_store)
        print(f"Capability {cap_to_revoke.id} verified (pre-revocation).")
    except CapabilityVerificationError as e:
        print(f"Capability {cap_to_revoke.id} failed verification (pre-revocation): {e}")
        return

    # Bob invokes it (should succeed)
    try:
        await invoke_capability(
            cap_to_revoke, "access", bob_key, did_key_store, 
            capability_store, revoked_capabilities, 
            used_invocation_nonces, nonce_timestamps
        )
        print(f"Capability {cap_to_revoke.id} invoked successfully (pre-revocation).")
    except InvocationError as e:
        print(f"Invocation failed (pre-revocation): {e}")

    # Alice revokes the capability
    print(f"Revoking capability: {cap_to_revoke.id}")
    revoked_capabilities.add(cap_to_revoke.id)

    # Try to verify again (should fail)
    try:
        await verify_capability(cap_to_revoke, did_key_store, revoked_capabilities, capability_store)
        print(f"Capability {cap_to_revoke.id} verification SUCCEEDED (POST-REVOCATION - UNEXPECTED!)")
    except CapabilityVerificationError as e:
        print(f"Capability {cap_to_revoke.id} verification failed as expected (post-revocation): {e}")

    # Try to invoke again (should fail)
    try:
        await invoke_capability(
            cap_to_revoke, "access", bob_key, did_key_store, 
            capability_store, revoked_capabilities, 
            used_invocation_nonces, nonce_timestamps
        )
        print(f"Capability {cap_to_revoke.id} invocation SUCCEEDED (POST-REVOCATION - UNEXPECTED!)")
    except InvocationError as e: # Should fail, ideally due to verification step within invoke_capability
        print(f"Invocation of {cap_to_revoke.id} failed as expected (post-revocation): {e}")
    except CapabilityVerificationError as e: # invoke_capability also does verify_capability
         print(f"Invocation of {cap_to_revoke.id} failed verification step as expected (post-revocation): {e}")

if __name__ == "__main__":
    asyncio.run(revocation_example())

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