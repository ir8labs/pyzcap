"""
Enhanced demo showcasing the core functionality of the zcap library.
"""

import time
from datetime import datetime, timedelta
import asyncio

from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
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
    # Removed: revoke_capability, register_public_key
    # Added exception imports if needed for specific handling, e.g.:
    ZCAPException,
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    verify_invocation,
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


async def main():
    console = Console()

    # Display header
    console.print(
        Panel.fit(
            "[bold cyan]zcap Capability-Based Security Demo[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    console.print("\n[bold]Setting up actors and stores...[/bold]")

    # Initialize stores (client-managed state)
    did_key_store = {}
    capability_store = {}
    revoked_capabilities = set()
    used_invocation_nonces = set()
    nonce_timestamps = {}

    # Generate keys for our actors
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Generating cryptographic keys...", total=None)
        alice_key = ed25519.Ed25519PrivateKey.generate()
        time.sleep(0.2)
        bob_key = ed25519.Ed25519PrivateKey.generate()
        time.sleep(0.2)
        charlie_key = ed25519.Ed25519PrivateKey.generate()
        time.sleep(0.2)

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

    # Register public keys for DIDs by adding them to the local store
    simulate_processing(console, "Populating DID key store...")
    did_key_store["did:example:alice"] = alice_key.public_key()
    did_key_store["did:example:bob"] = bob_key.public_key()
    did_key_store["did:example:charlie"] = charlie_key.public_key()
    console.print("[green]✓[/green] DID key store populated successfully\n")

    # Create a root capability for a document
    console.print("[bold]STEP 1:[/bold] Alice creates a root capability")
    simulate_processing(console, "Creating root capability...", 0.5)

    try:
        root_capability = await create_capability(
            controller_did="did:example:alice",
            invoker_did="did:example:bob",
            actions=[
                {"name": "read", "parameters": {}},
                {"name": "write", "parameters": {"max_size": 1024}},
            ],
            target_info={"id": "https://example.com/documents/123", "type": "Document"},
            controller_key=alice_key,
            expires=datetime.utcnow() + timedelta(days=30),
        )
        capability_store[root_capability.id] = (
            root_capability  # Client stores the capability
        )
        console.print(f"[green]✓[/green] Root capability created: {root_capability.id}")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Root capability creation failed: {e}")
        return

    # Show root capability details
    root_cap_table = Table(title="Root Capability Details")
    root_cap_table.add_column("Property", style="cyan")
    root_cap_table.add_column("Value", style="green")

    root_cap_table.add_row("ID", root_capability.id)
    root_cap_table.add_row("Controller", root_capability.controller.id)
    root_cap_table.add_row("Invoker", root_capability.invoker.id)
    root_cap_table.add_row(
        "Actions", ", ".join([a.name for a in root_capability.actions])
    )
    root_cap_table.add_row(
        "Expires",
        str(root_capability.expires.isoformat() if root_capability.expires else "None"),
    )

    console.print(root_cap_table)
    console.print()

    # Bob delegates read-only access to Charlie
    console.print("[bold]STEP 2:[/bold] Bob delegates read-only access to Charlie")
    simulate_processing(console, "Delegating capability...", 0.5)

    try:
        delegated_capability = await delegate_capability(
            parent_capability=root_capability,
            delegator_key=bob_key,  # Bob is invoker of root_capability, so he can delegate
            new_invoker_did="did:example:charlie",
            actions=[{"name": "read", "parameters": {}}],
            expires=datetime.utcnow() + timedelta(days=7),
            caveats=[{"type": "TimeSlot", "start": "09:00", "end": "17:00"}],
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,
            capability_store=capability_store,
        )
        capability_store[delegated_capability.id] = (
            delegated_capability  # Client stores delegated cap
        )
        console.print(
            f"[green]✓[/green] Delegated capability created: {delegated_capability.id}"
        )
    except (
        DelegationError,
        CapabilityVerificationError,
        DIDKeyNotFoundError,
        CapabilityNotFoundError,
    ) as e:
        console.print(f"[red]✗[/red] Capability delegation failed: {e}")
        return

    # Show delegated capability details
    delegated_cap_table = Table(title="Delegated Capability Details")
    delegated_cap_table.add_column("Property", style="cyan")
    delegated_cap_table.add_column("Value", style="green")

    delegated_cap_table.add_row("ID", delegated_capability.id)
    delegated_cap_table.add_row("Controller", delegated_capability.controller.id)
    delegated_cap_table.add_row("Invoker", delegated_capability.invoker.id)
    delegated_cap_table.add_row(
        "Actions", ", ".join([a.name for a in delegated_capability.actions])
    )
    delegated_cap_table.add_row("Parent", delegated_capability.parent_capability)
    delegated_cap_table.add_row("Caveats", "TimeSlot: 09:00-17:00")
    delegated_cap_table.add_row(
        "Expires",
        str(
            delegated_capability.expires.isoformat()
            if delegated_capability.expires
            else "None"
        ),
    )

    console.print(delegated_cap_table)
    console.print()

    # Charlie tries to read the document
    console.print(
        "[bold]STEP 3:[/bold] Charlie invokes the capability to read the document"
    )
    simulate_processing(console, "Invoking capability...", 0.5)
    invocation = None
    try:
        invocation = await invoke_capability(
            capability=delegated_capability,
            action_name="read",
            invoker_key=charlie_key,
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,
            capability_store=capability_store,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )
        console.print(
            "[green]✓[/green] Charlie's read invocation: [bold green]Successful attempt[/bold green]"
        )

        invocation_table = Table(title="Invocation Details")
        invocation_table.add_column("Property", style="cyan")
        invocation_table.add_column("Value", style="green")

        invocation_table.add_row("ID", invocation["id"])
        invocation_table.add_row("Action", invocation["action"])
        invocation_table.add_row("Capability ID", invocation["capability"])
        invocation_table.add_row("Proof Type", invocation["proof"]["type"])
        invocation_table.add_row("Proof Purpose", invocation["proof"]["proofPurpose"])
        console.print(invocation_table)

    except (
        InvocationError,
        CapabilityVerificationError,
        DIDKeyNotFoundError,
        CapabilityNotFoundError,
        ZCAPException,
    ) as e:
        console.print(f"[red]✗[/red] Charlie's read invocation attempt failed: {e}")

    console.print()

    # Verify the invocation if it was created
    if invocation:
        console.print("[bold]STEP 4:[/bold] Verifying the invocation")
        simulate_processing(console, "Verifying invocation...", 0.5)
        try:
            await verify_invocation(
                invocation_doc=invocation,
                did_key_store=did_key_store,
                revoked_capabilities=revoked_capabilities,
                capability_store=capability_store,
            )
            console.print(
                "[green]✓[/green] Invocation verification: [bold green]Valid[/bold green]"
            )
        except (
            InvocationVerificationError,
            CapabilityVerificationError,
            DIDKeyNotFoundError,
            CapabilityNotFoundError,
            ZCAPException,
        ) as e:
            console.print(f"[red]✗[/red] Invocation verification failed: {e}")
    else:
        console.print(
            "[yellow]![/yellow] Skipping invocation verification as invocation failed or was not created."
        )

    console.print()

    # Verify the delegated capability
    console.print("[bold]STEP 5:[/bold] Verifying the delegated capability")
    simulate_processing(console, "Verifying capability chain...", 0.5)
    try:
        await verify_capability(
            capability=delegated_capability,
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,
            capability_store=capability_store,
        )
        console.print(
            "[green]✓[/green] Delegated capability verification: [bold green]Valid[/bold green]"
        )
    except (
        CapabilityVerificationError,
        DIDKeyNotFoundError,
        CapabilityNotFoundError,
        ZCAPException,
    ) as e:
        console.print(f"[red]✗[/red] Delegated capability verification failed: {e}")

    console.print()

    # Simulate Bob revoking Charlie's capability by adding its ID to the revoked set
    console.print("[bold]STEP 6:[/bold] Bob revokes Charlie's capability (client-side)")
    simulate_processing(console, "Marking capability as revoked...", 0.5)
    revoked_capabilities.add(delegated_capability.id)
    console.print(
        f"[yellow]![/yellow] Capability {delegated_capability.id} has been added to revocation list."
    )
    console.print()

    # Charlie tries to read again with the (now) revoked capability
    console.print("[bold]STEP 7:[/bold] Charlie attempts to use the revoked capability")
    simulate_processing(
        console, "Attempting invocation with revoked capability...", 0.5
    )
    try:
        invocation_after_revoke = await invoke_capability(
            capability=delegated_capability,
            action_name="read",
            invoker_key=charlie_key,
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,  # This set now contains the revoked ID
            capability_store=capability_store,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )
        # If we reach here, the invocation surprisingly succeeded. This indicates a logic flaw or missed check.
        console.print(
            f"[red]✗[/red] Charlie's read after revocation: Attempt returned an invocation object (ID: {invocation_after_revoke['id'] if invocation_after_revoke else 'N/A'}). Expected failure."
        )
    except InvocationError as e:
        console.print(
            f"[green]✓[/green] Charlie's read after revocation: Failed as expected. Reason: {e}"
        )
    except ZCAPException as e:  # Catch other potential ZCAP errors
        console.print(
            f"[red]✗[/red] Charlie's read after revocation failed with an unexpected error: {e}"
        )

    console.print(
        Panel.fit(
            "[bold green]Demo Completed![/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
