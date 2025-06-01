"""
Enhanced demo showcasing the core functionality of the zcap library.
"""

import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from zcap import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    verify_invocation,
    revoke_capability,
    register_public_key,
)


def simulate_processing(console, message, duration=1.0):
    """Simulate processing with a spinner animation."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(message, total=None)
        time.sleep(duration)


def main():
    console = Console()

    # Display header
    console.print(Panel.fit(
        "[bold cyan]zcap Capability-Based Security Demo[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    console.print("\n[bold]Setting up actors...[/bold]")

    # Generate keys for our actors with animation
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

    actors_table.add_row("Alice", "did:example:alice", "Resource Owner")
    actors_table.add_row("Bob", "did:example:bob", "Primary User")
    actors_table.add_row("Charlie", "did:example:charlie", "Secondary User")

    console.print(actors_table)
    console.print()

    # Register public keys for DIDs
    simulate_processing(console, "Registering DID public keys...")
    register_public_key("did:example:alice", alice_key.public_key())
    register_public_key("did:example:bob", bob_key.public_key())
    register_public_key("did:example:charlie", charlie_key.public_key())
    console.print("[green]✓[/green] DIDs registered successfully\n")

    # Create a root capability for a document
    console.print("[bold]STEP 1:[/bold] Alice creates a root capability")
    simulate_processing(console, "Creating root capability...", 1.2)

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


    # Show root capability details
    root_cap_table = Table(title="Root Capability Details")
    root_cap_table.add_column("Property", style="cyan")
    root_cap_table.add_column("Value", style="green")

    root_cap_table.add_row("ID", root_capability.id)
    root_cap_table.add_row("Controller", root_capability.controller.id)
    root_cap_table.add_row("Invoker", root_capability.invoker.id)
    root_cap_table.add_row("Actions", ", ".join([a.name for a in root_capability.actions]))
    root_cap_table.add_row("Expires", str(root_capability.expires))

    console.print(root_cap_table)
    console.print()

    # Bob delegates read-only access to Charlie
    console.print("[bold]STEP 2:[/bold] Bob delegates read-only access to Charlie")
    simulate_processing(console, "Delegating capability...", 1.2)

    delegated_capability = delegate_capability(
        parent_capability=root_capability,
        delegator_key=bob_key,
        new_invoker="did:example:charlie",
        actions=[{"name": "read", "parameters": {}}],
        expires=datetime.utcnow() + timedelta(days=7),
        caveats=[{"type": "TimeSlot", "start": "09:00", "end": "17:00"}],
    )

    # Show delegated capability details
    delegated_cap_table = Table(title="Delegated Capability Details")
    delegated_cap_table.add_column("Property", style="cyan")
    delegated_cap_table.add_column("Value", style="green")

    delegated_cap_table.add_row("ID", delegated_capability.id)
    delegated_cap_table.add_row("Controller", delegated_capability.controller.id)
    delegated_cap_table.add_row("Invoker", delegated_capability.invoker.id)
    delegated_cap_table.add_row("Actions", ", ".join([a.name for a in delegated_capability.actions]))
    delegated_cap_table.add_row("Parent", delegated_capability.parent_capability)
    delegated_cap_table.add_row("Caveats", "TimeSlot: 09:00-17:00")
    delegated_cap_table.add_row("Expires", str(delegated_capability.expires))

    console.print(delegated_cap_table)
    console.print()

    # Charlie tries to read the document
    console.print("[bold]STEP 3:[/bold] Charlie invokes the capability to read the document")
    simulate_processing(console, "Invoking capability...", 1.0)

    invocation = invoke_capability(
        capability=delegated_capability, action="read", invoker_key=charlie_key
    )

    if invocation:
        console.print("[green]✓[/green] Charlie's read invocation: [bold green]Success[/bold green]")

        invocation_table = Table(title="Invocation Details")
        invocation_table.add_column("Property", style="cyan")
        invocation_table.add_column("Value", style="green")

        invocation_table.add_row("ID", invocation['id'])
        invocation_table.add_row("Action", invocation['action'])
        invocation_table.add_row("Capability", invocation['capability'])
        invocation_table.add_row("Proof Type", invocation['proof']['type'])
        invocation_table.add_row("Proof Purpose", invocation['proof']['proofPurpose'])

        console.print(invocation_table)

        # Verify the invocation
        console.print("\n[bold]STEP 4:[/bold] Verifying the invocation")
        simulate_processing(console, "Verifying invocation signature...", 0.8)
        is_valid = verify_invocation(invocation, delegated_capability)

        if is_valid:
            console.print("[green]✓[/green] Invocation verification: [bold green]Valid[/bold green]")
        else:
            console.print("[red]✗[/red] Invocation verification: [bold red]Invalid[/bold red]")
    else:
        console.print("[red]✗[/red] Charlie's read invocation: [bold red]Failed[/bold red]")

    console.print()

    # Verify the delegated capability
    console.print("[bold]STEP 5:[/bold] Verifying the delegated capability")
    simulate_processing(console, "Verifying capability chain...", 1.0)

    is_valid = verify_capability(delegated_capability)

    if is_valid:
        console.print("[green]✓[/green] Capability verification: [bold green]Valid[/bold green]")
    else:
        console.print("[red]✗[/red] Capability verification: [bold red]Invalid[/bold red]")

    console.print()

    # Bob revokes the delegated capability
    console.print("[bold]STEP 6:[/bold] Bob revokes Charlie's capability")
    simulate_processing(console, "Revoking capability...", 1.0)

    revoke_capability(delegated_capability.id)
    console.print("[yellow]![/yellow] Capability has been [bold red]revoked[/bold red]")
    console.print()

    # Charlie tries to read again
    console.print("[bold]STEP 7:[/bold] Charlie attempts to use the revoked capability")
    simulate_processing(console, "Attempting invocation with revoked capability...", 1.0)

    invocation = invoke_capability(
        capability=delegated_capability, action="read", invoker_key=charlie_key
    )

    if invocation:
        console.print("[red]✗[/red] Charlie's read after revocation: [bold red]Success (unexpected!)[/bold red]")
    else:
        console.print("[green]✓[/green] Charlie's read after revocation: [bold green]Failed (as expected)[/bold green]")

    console.print(Panel.fit(
        "[bold green]Demo Completed Successfully![/bold green]",
        border_style="green",
        padding=(1, 2)
    ))


if __name__ == "__main__":
    main()
