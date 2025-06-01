"""
Example demonstrating document sharing with capability-based access control.

This example simulates a document sharing system where:
1. Alice owns a document
2. Alice grants Bob read/write access
3. Bob delegates read-only access to Charlie
4. Charlie tries various operations
5. Bob revokes Charlie's access
"""

import time
from datetime import datetime, timedelta
from typing import Any, Dict, Set

from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from zcap import (
    CapabilityNotFoundError,
    CapabilityVerificationError,
    DelegationError,
    DIDKeyNotFoundError,
    InvocationError,
    InvocationVerificationError,
    ZCAPException,
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
)
from zcap.models import Capability


def simulate_processing(console, message, duration=0.3):
    """Simulate processing with a spinner animation."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(message, total=None)
        time.sleep(duration)


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

    def read_document(
        self, 
        doc_id: str, 
        capability_to_invoke: Capability, 
        invoker_key: ed25519.Ed25519PrivateKey, 
        did_key_store: Dict[str, ed25519.Ed25519PublicKey],
        capability_store: Dict[str, Capability],
        revoked_capabilities: Set[str],
        used_invocation_nonces: Set[str],
        nonce_timestamps: Dict[str, datetime]
    ) -> str:
        """Read a document if the capability allows it."""
        try:
            invoke_capability(
                capability_to_invoke, "read", invoker_key, 
                did_key_store, revoked_capabilities, capability_store, 
                used_invocation_nonces, nonce_timestamps
            )
            return self.documents[doc_id].read()
        except (InvocationError, CapabilityVerificationError, DIDKeyNotFoundError, CapabilityNotFoundError, ZCAPException) as e:
            raise PermissionError(f"Access denied to read document {doc_id}: {e}")

    def write_document(
        self, 
        doc_id: str, 
        content: str, 
        capability_to_invoke: Capability, 
        invoker_key: ed25519.Ed25519PrivateKey,
        did_key_store: Dict[str, ed25519.Ed25519PublicKey],
        capability_store: Dict[str, Capability],
        revoked_capabilities: Set[str],
        used_invocation_nonces: Set[str],
        nonce_timestamps: Dict[str, datetime]
    ) -> None:
        """Write to a document if the capability allows it."""
        try:
            invoke_capability(
                capability_to_invoke, "write", invoker_key, 
                did_key_store, revoked_capabilities, capability_store, 
                used_invocation_nonces, nonce_timestamps, 
                parameters={"content_length": len(content)}
            )
            self.documents[doc_id].write(content)
        except (InvocationError, CapabilityVerificationError, DIDKeyNotFoundError, CapabilityNotFoundError, ZCAPException) as e:
            raise PermissionError(f"Access denied to write document {doc_id}: {e}")


def main():
    console = Console()

    # Display header
    console.print(Panel.fit(
        "[bold cyan]zcap Document Sharing Demo[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    # Initialize stores
    did_key_store: Dict[str, ed25519.Ed25519PublicKey] = {}
    capability_store: Dict[str, Capability] = {}
    revoked_capabilities: Set[str] = set()
    used_invocation_nonces: Set[str] = set()
    nonce_timestamps: Dict[str, datetime] = {}

    # Initialize our document system
    console.print("[bold]Setting up document system...[/bold]")
    simulate_processing(console, "Initializing document management system...")
    doc_system = DocumentSystem()
    console.print("[green]✓[/green] Document system initialized\n")

    # Generate keys for our actors
    console.print("[bold]Generating cryptographic keys for actors...[/bold]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Generating keys...", total=3)
        alice_key = ed25519.Ed25519PrivateKey.generate(); progress.update(task, advance=1)
        bob_key = ed25519.Ed25519PrivateKey.generate(); progress.update(task, advance=1)
        charlie_key = ed25519.Ed25519PrivateKey.generate(); progress.update(task, advance=1)

    # Display actors
    actors_table = Table(title="Actors")
    actors_table.add_column("Name", style="cyan")
    actors_table.add_column("DID", style="green")
    actors_table.add_column("Role", style="magenta")

    actors_table.add_row("Alice", "did:example:alice", "Document Owner")
    actors_table.add_row("Bob", "did:example:bob", "Collaborator")
    actors_table.add_row("Charlie", "did:example:charlie", "Viewer")

    console.print(actors_table)
    console.print()

    # Populate DID key store
    console.print("[bold]STEP 1:[/bold] Populating DID key store")
    simulate_processing(console, "Adding keys to DID store...")
    did_key_store["did:example:alice"] = alice_key.public_key()
    did_key_store["did:example:bob"] = bob_key.public_key()
    did_key_store["did:example:charlie"] = charlie_key.public_key()
    console.print("[green]✓[/green] DID key store populated\n")

    # Alice creates a document
    console.print("[bold]STEP 2:[/bold] Alice creates a document")
    simulate_processing(console, "Creating document...")

    doc = doc_system.create_document(
        "doc123", "Hello, this is a secret document.", "did:example:alice"
    )

    doc_table = Table(title="Document Details")
    doc_table.add_column("Property", style="cyan")
    doc_table.add_column("Value", style="green")

    doc_table.add_row("ID", doc.id)
    doc_table.add_row("Content", doc.content)
    doc_table.add_row("Owner", doc.owner)
    doc_table.add_row("Version", str(doc.version))

    console.print(doc_table)
    console.print()

    # Alice creates a capability for Bob with read/write access
    console.print("[bold]STEP 3:[/bold] Alice grants Bob read/write access")
    simulate_processing(console, "Creating capability for Bob...")

    bob_capability = None
    try:
        bob_capability = create_capability(
            controller_did="did:example:alice", invoker_did="did:example:bob",
            actions=[{"name": "read"}, {"name": "write", "parameters": {"max_size": 1024}}],
            target_info={"id": f"https://example.com/documents/{doc.id}", "type": "Document"},
            controller_key=alice_key, expires=datetime.utcnow() + timedelta(days=30)
        )
        capability_store[bob_capability.id] = bob_capability
        console.print(f"[green]✓[/green] Capability for Bob created: {bob_capability.id}\n")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Failed to create Bob's capability: {e}"); return

    # Bob reads the document
    console.print("[bold]STEP 4:[/bold] Bob reads the document")
    simulate_processing(console, "Bob invoking read capability...")

    if bob_capability:
        try:
            content = doc_system.read_document(
                doc.id, bob_capability, bob_key, 
                did_key_store, capability_store, revoked_capabilities, 
                used_invocation_nonces, nonce_timestamps
            )
            console.print(f"[green]✓[/green] Bob reads: [italic]\"{content}\"[/italic]")
        except PermissionError as e:
            console.print(f"[red]✗[/red] Bob read failed: {e}")
    console.print()

    # Bob writes to the document
    console.print("\n[bold]STEP 5:[/bold] Bob writes to the document")
    simulate_processing(console, "Bob invoking write capability...")

    if bob_capability:
        try:
            new_content = "Hello, Bob has edited this document."
            doc_system.write_document(
                doc.id, new_content, bob_capability, bob_key, 
                did_key_store, capability_store, revoked_capabilities, 
                used_invocation_nonces, nonce_timestamps
            )
            console.print("[green]✓[/green] Bob successfully wrote to the document")
            console.print(Markdown(f"**Updated content:**\n\n> {doc_system.documents[doc.id].content}"))
        except PermissionError as e:
            console.print(f"[red]✗[/red] Bob write failed: {e}")
    console.print()

    # Bob delegates read-only access to Charlie
    console.print("\n[bold]STEP 6:[/bold] Bob delegates read-only access to Charlie")
    simulate_processing(console, "Creating delegated capability for Charlie...")

    charlie_capability = None
    if bob_capability:
        try:
            charlie_capability = delegate_capability(
                parent_capability=bob_capability, delegator_key=bob_key, new_invoker_did="did:example:charlie",
                actions=[{"name": "read"}], expires=datetime.utcnow() + timedelta(days=7),
                caveats=[{"type": "TimeSlot", "start": "09:00", "end": "17:00"}],
                did_key_store=did_key_store, revoked_capabilities=revoked_capabilities, capability_store=capability_store
            )
            capability_store[charlie_capability.id] = charlie_capability
            console.print(f"[green]✓[/green] Capability for Charlie created: {charlie_capability.id}\n")
        except (DelegationError, CapabilityVerificationError, ZCAPException) as e:
            console.print(f"[red]✗[/red] Failed to delegate to Charlie: {e}"); charlie_capability = None

    console.print("[bold]STEP 7:[/bold] Charlie attempts to read the document")
    simulate_processing(console, "Charlie invoking read capability...")

    if charlie_capability:
        try:
            content = doc_system.read_document(
                doc.id, charlie_capability, charlie_key, 
                did_key_store, capability_store, revoked_capabilities, 
                used_invocation_nonces, nonce_timestamps
            )
            console.print(f"[green]✓[/green] Charlie reads: [italic]\"{content}\"[/italic] (Assuming current time is within 09:00-17:00)")
        except PermissionError as e:
            console.print(f"[red]✗[/red] Charlie read failed: {e}")
    else:
        console.print("[yellow]![/yellow] Skipping Charlie's read attempt as their capability was not created.")
    console.print()

    console.print("[bold]STEP 8:[/bold] Charlie attempts to write to the document (should fail)")
    simulate_processing(console, "Charlie invoking write capability...")

    if charlie_capability:
        try:
            doc_system.write_document(
                doc.id, "Charlie tries to write.", charlie_capability, charlie_key, 
                did_key_store, capability_store, revoked_capabilities, 
                used_invocation_nonces, nonce_timestamps
            )
            console.print("[red]✗[/red] Charlie write: [bold red]Successful (UNEXPECTED)[/bold red]")
        except PermissionError as e:
            console.print(f"[green]✓[/green] Charlie write failed as expected: {e}")
    else:
        console.print("[yellow]![/yellow] Skipping Charlie's write attempt as their capability was not created.")
    console.print()

    console.print("[bold]STEP 9:[/bold] Bob revokes Charlie's capability (client-side)")
    if charlie_capability:
        simulate_processing(console, "Adding Charlie's capability ID to revocation list...")
        revoked_capabilities.add(charlie_capability.id)
        console.print(f"[yellow]![/yellow] Capability {charlie_capability.id} added to revocation list.")
    else:
        console.print("[yellow]![/yellow] Skipping revocation as Charlie's capability was not created.")
    console.print()

    console.print("[bold]STEP 10:[/bold] Charlie attempts to read again (should fail due to revocation)")
    simulate_processing(console, "Charlie invoking read with revoked capability...")

    if charlie_capability:
        try:
            content = doc_system.read_document(
                doc.id, charlie_capability, charlie_key, 
                did_key_store, capability_store, revoked_capabilities,
                used_invocation_nonces, nonce_timestamps
            )
            console.print(f"[red]✗[/red] Charlie read after revocation: [italic]\"{content}\"[/italic] [bold red](UNEXPECTED)[/bold red]")
        except PermissionError as e:
            console.print(f"[green]✓[/green] Charlie read after revocation failed as expected: {e}")
    else:
        console.print("[yellow]![/yellow] Skipping Charlie's read attempt as their capability was not created or already revoked.")
    console.print()

    console.print(Panel.fit(
        "[bold green]Document Sharing Demo Completed[/bold green]",
        border_style="green",
        padding=(1, 2)
    ))


if __name__ == "__main__":
    main()
