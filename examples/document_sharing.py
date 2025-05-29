"""
Example demonstrating document sharing with capability-based access control.

This example simulates a document sharing system where:
1. Alice owns a document
2. Alice grants Bob read/write access
3. Bob delegates read-only access to Charlie
4. Charlie tries various operations
5. Bob revokes Charlie's access
"""

from datetime import datetime, timedelta
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from pyzcap import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    revoke_capability,
    register_public_key,
)


class Document:
    """Simple document class to demonstrate capability-based access control."""

    def __init__(self, id: str, content: str, owner: str):
        self.id = id
        self.content = content
        self.owner = owner
        self.version = 1

    def read(self) -> str:
        return self.content

    def write(self, content: str) -> None:
        self.content = content
        self.version += 1


class DocumentSystem:
    """Document management system using capability-based access control."""

    def __init__(self):
        self.documents: Dict[str, Document] = {}

    def create_document(self, id: str, content: str, owner: str) -> Document:
        doc = Document(id, content, owner)
        self.documents[id] = doc
        return doc

    def read_document(self, doc_id: str, capability: Any, invoker_key: Any) -> str:
        """Read a document if the capability allows it."""
        # First verify the capability is valid
        if not verify_capability(capability):
            raise PermissionError("Invalid or expired capability")
        # Then check if we can invoke it
        invocation = invoke_capability(capability, "read", invoker_key)
        if not invocation:
            raise PermissionError("Access denied")
        return self.documents[doc_id].read()

    def write_document(
        self, doc_id: str, content: str, capability: Any, invoker_key: Any
    ) -> None:
        """Write to a document if the capability allows it."""
        # First verify the capability is valid
        if not verify_capability(capability):
            raise PermissionError("Invalid or expired capability")
        # Then check if we can invoke it
        invocation = invoke_capability(capability, "write", invoker_key)
        if not invocation:
            raise PermissionError("Access denied")
        self.documents[doc_id].write(content)


def main():
    # Initialize our document system
    doc_system = DocumentSystem()

    # Generate keys for our actors
    alice_key = ed25519.Ed25519PrivateKey.generate()
    bob_key = ed25519.Ed25519PrivateKey.generate()
    charlie_key = ed25519.Ed25519PrivateKey.generate()

    # Register public keys for DIDs
    register_public_key("did:example:alice", alice_key.public_key())
    register_public_key("did:example:bob", bob_key.public_key())
    register_public_key("did:example:charlie", charlie_key.public_key())

    # Alice creates a document
    doc = doc_system.create_document(
        "doc123", "Hello, this is a secret document.", "did:example:alice"
    )

    print("Document created by Alice:")
    print(f"ID: {doc.id}")
    print(f"Content: {doc.content}")
    print(f"Owner: {doc.owner}")
    print()

    # Alice creates a capability for Bob with read/write access
    bob_capability = create_capability(
        controller="did:example:alice",
        invoker="did:example:bob",
        actions=[
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {"max_size": 1024}},
        ],
        target={"id": f"https://example.com/documents/{doc.id}", "type": "Document"},
        controller_key=alice_key,
        expires=datetime.utcnow() + timedelta(days=30),
    )

    print("Bob's capability created")
    print(f"Actions: {[a.name for a in bob_capability.actions]}")
    print()

    # Bob reads the document
    try:
        content = doc_system.read_document(doc.id, bob_capability, bob_key)
        print(f"Bob reads the document: {content}")
    except PermissionError as e:
        print(f"Error: {e}")

    # Bob writes to the document
    try:
        doc_system.write_document(
            doc.id, "Hello, Bob has edited this document.", bob_capability, bob_key
        )
        print("Bob successfully wrote to the document")
    except PermissionError as e:
        print(f"Error: {e}")

    # Bob delegates read-only access to Charlie
    charlie_capability = delegate_capability(
        parent_capability=bob_capability,
        delegator_key=bob_key,
        new_invoker="did:example:charlie",
        actions=[{"name": "read", "parameters": {}}],
        expires=datetime.utcnow() + timedelta(days=7),
        caveats=[{"type": "TimeSlot", "start": "09:00", "end": "17:00"}],
    )

    print("\nCharlie's delegated capability created")
    print(f"Actions: {[a.name for a in charlie_capability.actions]}")
    print()

    # Charlie tries to read (should succeed)
    try:
        content = doc_system.read_document(doc.id, charlie_capability, charlie_key)
        print(f"Charlie reads the document: {content}")
    except PermissionError as e:
        print(f"Error: {e}")

    # Charlie tries to write (should fail)
    try:
        doc_system.write_document(
            doc.id, "Charlie trying to edit!", charlie_capability, charlie_key
        )
        print("Charlie wrote to the document (shouldn't happen)")
    except PermissionError as e:
        print(f"Charlie's write attempt failed: {e}")

    # Bob revokes Charlie's access
    print("\nBob revokes Charlie's capability")
    revoke_capability(charlie_capability.id)

    # Charlie tries to read again (should fail)
    try:
        content = doc_system.read_document(doc.id, charlie_capability, charlie_key)
        print(f"Charlie reads the document: {content}")
    except PermissionError as e:
        print(f"Charlie's read attempt after revocation failed: {e}")


if __name__ == "__main__":
    main()
