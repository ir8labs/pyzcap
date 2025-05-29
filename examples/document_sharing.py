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
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from pyzcap import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    revoke_capability,
    register_public_key,
)


def simulate_processing(console, message, duration=0.5):
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
    console = Console()

    # Display header
    console.print(Panel.fit(
        "[bold cyan]PyZCAP Document Sharing Demo[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    # Initialize our document system
    console.print("[bold]Setting up document system...[/bold]")
    simulate_processing(console, "Initializing document management system...", 0.8)
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
        progress.add_task("Generating cryptographic keys...", total=None)
        alice_key = ed25519.Ed25519PrivateKey.generate()
        time.sleep(0.5)
        bob_key = ed25519.Ed25519PrivateKey.generate()
        time.sleep(0.5)
        charlie_key = ed25519.Ed25519PrivateKey.generate()
        time.sleep(0.5)

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

    # Register public keys for DIDs
    console.print("[bold]STEP 1:[/bold] Registering identities")
    simulate_processing(console, "Registering DIDs...", 0.8)

    register_public_key("did:example:alice", alice_key.public_key())
    register_public_key("did:example:bob", bob_key.public_key())
    register_public_key("did:example:charlie", charlie_key.public_key())

    console.print("[green]✓[/green] All identities registered\n")

    # Alice creates a document
    console.print("[bold]STEP 2:[/bold] Alice creates a document")
    simulate_processing(console, "Creating document...", 0.8)

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
    simulate_processing(console, "Creating capability for Bob...", 1.0)

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

    cap_table = Table(title="Bob's Capability")
    cap_table.add_column("Property", style="cyan")
    cap_table.add_column("Value", style="green")

    cap_table.add_row("ID", bob_capability.id)
    cap_table.add_row("Controller", bob_capability.controller.id)
    cap_table.add_row("Invoker", bob_capability.invoker.id)
    cap_table.add_row("Actions", ", ".join([a.name for a in bob_capability.actions]))
    cap_table.add_row("Expires", str(bob_capability.expires))

    console.print(cap_table)
    console.print()

    # Bob reads the document
    console.print("[bold]STEP 4:[/bold] Bob reads the document")
    simulate_processing(console, "Bob invoking read capability...", 0.8)

    try:
        content = doc_system.read_document(doc.id, bob_capability, bob_key)
        console.print(f"[green]✓[/green] Bob reads: [italic]\"{content}\"[/italic]")
    except PermissionError as e:
        console.print(f"[red]✗[/red] Error: {e}")

    # Bob writes to the document
    console.print("\n[bold]STEP 5:[/bold] Bob writes to the document")
    simulate_processing(console, "Bob invoking write capability...", 0.8)

    try:
        doc_system.write_document(
            doc.id, "Hello, Bob has edited this document.", bob_capability, bob_key
        )
        console.print("[green]✓[/green] Bob successfully wrote to the document")

        # Show updated document
        doc_content = Markdown(f"**Updated document content:**\n\n> {doc.content}")
        console.print(doc_content)
        console.print(f"[dim]Document version: {doc.version}[/dim]")
    except PermissionError as e:
        console.print(f"[red]✗[/red] Error: {e}")

    # Bob delegates read-only access to Charlie
    console.print("\n[bold]STEP 6:[/bold] Bob delegates read-only access to Charlie")
    simulate_processing(console, "Creating delegated capability...", 1.0)

    charlie_capability = delegate_capability(
        parent_capability=bob_capability,
        delegator_key=bob_key,
        new_invoker="did:example:charlie",
        actions=[{"name": "read", "parameters": {}}],
        expires=datetime.utcnow() + timedelta(days=7),
        caveats=[{"type": "TimeSlot", "start": "09:00", "end": "17:00"}],
    )

    charlie_cap_table = Table(title="Charlie's Delegated Capability")
    charlie_cap_table.add_column("Property", style="cyan")
    charlie_cap_table.add_column("Value", style="green")

    charlie_cap_table.add_row("ID", charlie_capability.id)
    charlie_cap_table.add_row("Controller", charlie_capability.controller.id)
    charlie_cap_table.add_row("Invoker", charlie_capability.invoker.id)
    charlie_cap_table.add_row("Actions", ", ".join([a.name for a in charlie_capability.actions]))
    charlie_cap_table.add_row("Parent", charlie_capability.parent_capability)
    charlie_cap_table.add_row("Caveats", "TimeSlot: 09:00-17:00")
    charlie_cap_table.add_row("Expires", str(charlie_capability.expires))

    console.print(charlie_cap_table)
    console.print()

    # Charlie tries to read (should succeed)
    console.print("[bold]STEP 7:[/bold] Charlie tries to read the document")
    simulate_processing(console, "Charlie invoking read capability...", 0.8)

    try:
        content = doc_system.read_document(doc.id, charlie_capability, charlie_key)
        console.print(f"[green]✓[/green] Charlie reads: [italic]\"{content}\"[/italic]")
    except PermissionError as e:
        console.print(f"[red]✗[/red] Error: {e}")

    # Charlie tries to write (should fail)
    console.print("\n[bold]STEP 8:[/bold] Charlie tries to write to the document")
    simulate_processing(console, "Charlie attempting to write...", 0.8)

    try:
        doc_system.write_document(
            doc.id, "Charlie trying to edit!", charlie_capability, charlie_key
        )
        console.print("[red]![/red] Charlie wrote to the document (shouldn't happen)")
    except PermissionError as e:
        console.print(f"[green]✓[/green] Charlie's write attempt failed: [yellow]{e}[/yellow]")

    # Bob revokes Charlie's access
    console.print("\n[bold]STEP 9:[/bold] Bob revokes Charlie's capability")
    simulate_processing(console, "Revoking capability...", 1.0)

    revoke_capability(charlie_capability.id)
    console.print("[yellow]![/yellow] Capability has been [bold red]revoked[/bold red]")

    # Charlie tries to read again (should fail)
    console.print("\n[bold]STEP 10:[/bold] Charlie tries to read after revocation")
    simulate_processing(console, "Charlie attempting to read with revoked capability...", 0.8)

    try:
        content = doc_system.read_document(doc.id, charlie_capability, charlie_key)
        console.print(f"[red]![/red] Charlie reads: [italic]\"{content}\"[/italic] (shouldn't happen)")
    except PermissionError as e:
        console.print(f"[green]✓[/green] Charlie's read attempt after revocation failed: [yellow]{e}[/yellow]")

    console.print(Panel.fit(
        "[bold green]Document Sharing Demo Completed Successfully![/bold green]",
        border_style="green",
        padding=(1, 2)
    ))


if __name__ == "__main__":
    main()
