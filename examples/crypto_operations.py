"""
Example demonstrating cryptographic operations in ZCAP-LD.

This example shows:
1. Key generation and management
2. Capability signing
3. Signature verification
4. Proof chain validation
"""

from datetime import datetime, timedelta
from base64 import b64encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from pyzcap import (
    create_capability,
    delegate_capability,
    verify_capability,
    register_public_key,
    models,
)


def generate_key_pair(
    name: str,
) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate an Ed25519 key pair and display the public key."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get the public key bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    print(f"{name}'s public key: {b64encode(public_bytes).decode()}")
    return private_key, public_key


def display_proof(proof: models.Proof) -> None:
    """Display the details of a capability proof."""
    print("Proof details:")
    print(f"  ID: {proof.id}")
    print(f"  Type: {proof.type}")
    print(f"  Created: {proof.created}")
    print(f"  Verification Method: {proof.verification_method}")
    print(f"  Purpose: {proof.proof_purpose}")
    print(f"  Value: {proof.proof_value[:32]}...")  # Show first 32 chars of proof
    if proof.domain:
        print(f"  Domain: {proof.domain}")
    if proof.nonce:
        print(f"  Nonce: {proof.nonce}")


def main():
    print("Generating key pairs for all actors...")
    alice_private, alice_public = generate_key_pair("Alice")
    bob_private, bob_public = generate_key_pair("Bob")
    charlie_private, charlie_public = generate_key_pair("Charlie")
    print()

    # Register public keys for DIDs
    print("Registering public keys...")
    register_public_key("did:example:alice", alice_public)
    register_public_key("did:example:bob", bob_public)
    register_public_key("did:example:charlie", charlie_public)
    print()

    # Create a root capability from Alice to Bob
    print("Creating root capability (Alice → Bob)...")
    root_cap = create_capability(
        controller="did:example:alice",
        invoker="did:example:bob",
        actions=[{"name": "read", "parameters": {}}],
        target={"id": "https://example.com/resource/123", "type": "Resource"},
        controller_key=alice_private,
        expires=datetime.utcnow() + timedelta(days=30),
    )

    print("Root capability created and signed")
    display_proof(root_cap.proof)
    print()

    # Bob delegates to Charlie
    print("Creating delegated capability (Bob → Charlie)...")
    delegated_cap = delegate_capability(
        parent_capability=root_cap,
        delegator_key=bob_private,
        new_invoker="did:example:charlie",
        actions=[{"name": "read", "parameters": {"rate_limit": "10/minute"}}],
        expires=datetime.utcnow() + timedelta(hours=24),
    )

    print("Delegated capability created and signed")
    display_proof(delegated_cap.proof)
    print()

    # Verify the delegation chain
    print("Verifying capability chain...")

    # First verify the root capability
    root_valid = verify_capability(root_cap)
    print(f"Root capability valid: {root_valid}")

    # Then verify the delegated capability
    delegated_valid = verify_capability(delegated_cap)
    print(f"Delegated capability valid: {delegated_valid}")

    # Show the complete chain
    print("\nCapability chain:")
    print(f"Root: {root_cap.id}")
    print(f"└── Delegated: {delegated_cap.id}")

    # Convert to JSON-LD and show the structure
    print("\nJSON-LD representation of delegated capability:")
    json_ld = delegated_cap.to_json_ld()
    print("Context:", json_ld["@context"])
    print("Type:", json_ld["type"])
    print("Controller:", json_ld["controller"]["id"])
    print("Invoker:", json_ld["invoker"]["id"])
    print("Parent:", json_ld.get("parentCapability"))
    print("Actions:", [a["name"] for a in json_ld["action"]])


if __name__ == "__main__":
    main()
