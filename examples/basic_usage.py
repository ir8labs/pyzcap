"""
Basic example demonstrating the core functionality of the PyZCAP library.
"""

from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from pyzcap import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    verify_invocation,
    revoke_capability,
    register_public_key,
)


def main():
    # Generate keys for our actors
    alice_key = ed25519.Ed25519PrivateKey.generate()
    bob_key = ed25519.Ed25519PrivateKey.generate()
    charlie_key = ed25519.Ed25519PrivateKey.generate()

    # Register public keys for DIDs
    register_public_key("did:example:alice", alice_key.public_key())
    register_public_key("did:example:bob", bob_key.public_key())
    register_public_key("did:example:charlie", charlie_key.public_key())

    # Create a root capability for a document
    root_capability = create_capability(
        controller="did:example:alice",
        invoker="did:example:bob",
        actions=[
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {"max_size": 1024}},
        ],
        target={"id": "https://example.com/documents/123", "type": "Document"},
        controller_key=alice_key,
        expires=datetime.utcnow() + timedelta(days=30),
    )

    print("Root capability created:")
    print(f"ID: {root_capability.id}")
    print(f"Controller: {root_capability.controller.id}")
    print(f"Invoker: {root_capability.invoker.id}")
    print(f"Actions: {[a.name for a in root_capability.actions]}")
    print()

    # Bob delegates read-only access to Charlie
    delegated_capability = delegate_capability(
        parent_capability=root_capability,
        delegator_key=bob_key,
        new_invoker="did:example:charlie",
        actions=[{"name": "read", "parameters": {}}],
        expires=datetime.utcnow() + timedelta(days=7),
        caveats=[{"type": "TimeSlot", "start": "09:00", "end": "17:00"}],
    )

    print("Delegated capability created:")
    print(f"ID: {delegated_capability.id}")
    print(f"Controller: {delegated_capability.controller.id}")
    print(f"Invoker: {delegated_capability.invoker.id}")
    print(f"Actions: {[a.name for a in delegated_capability.actions]}")
    print(f"Parent: {delegated_capability.parent_capability}")
    print()

    # Charlie tries to read the document
    invocation = invoke_capability(
        capability=delegated_capability, action="read", invoker_key=charlie_key
    )

    if invocation:
        print("Charlie's read invocation: Success")
        print("Invocation details:")
        print(f"  ID: {invocation['id']}")
        print(f"  Action: {invocation['action']}")
        print(f"  Capability: {invocation['capability']}")
        print(f"  Proof Type: {invocation['proof']['type']}")
        print(f"  Proof Purpose: {invocation['proof']['proofPurpose']}")

        # Verify the invocation
        print("\nVerifying the invocation object...")
        is_valid = verify_invocation(invocation, delegated_capability)
        print(f"Invocation valid: {is_valid}")
    else:
        print("Charlie's read invocation: Failed")
    print()

    # Verify the delegated capability
    is_valid = verify_capability(delegated_capability)
    print(f"Delegated capability valid: {is_valid}")
    print()

    # Bob revokes the delegated capability
    revoke_capability(delegated_capability.id)

    # Charlie tries to read again
    invocation = invoke_capability(
        capability=delegated_capability, action="read", invoker_key=charlie_key
    )

    if invocation:
        print("Charlie's read after revocation: Success (shouldn't happen)")
    else:
        print("Charlie's read after revocation: Failed (as expected)")


if __name__ == "__main__":
    main()
