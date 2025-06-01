"""
Example demonstrating cryptographic operations in ZCAP-LD.

This example shows:
1. Key generation and management
2. Capability signing
3. Signature verification
4. Proof chain validation
"""

import time
from base64 import b64encode
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import serialization
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
    ZCAPException,
    create_capability,
    delegate_capability,
    models,
    verify_capability,
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


def generate_key_pair(
    console: Console, name: str
) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate an Ed25519 key pair and display the public key."""
    simulate_processing(console, f"Generating {name}'s key pair...")

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    console.print(f"[cyan]{name}[/cyan]'s public key (base64): [green]{b64encode(public_bytes).decode()}[/green]")
    return private_key, public_key


def display_proof(console: Console, proof: models.Proof) -> None:
    """Display the details of a capability proof."""
    proof_table = Table(title="Proof Details")
    proof_table.add_column("Property", style="cyan")
    proof_table.add_column("Value", style="green")

    proof_table.add_row("ID", str(proof.id))
    proof_table.add_row("Type", proof.type)
    proof_table.add_row("Created", proof.created.isoformat() if isinstance(proof.created, datetime) else str(proof.created))
    proof_table.add_row("Verification Method", proof.verification_method)
    proof_table.add_row("Purpose", proof.proof_purpose)
    proof_table.add_row("Value (first 32 chars)", f"{proof.proof_value[:32]}...")

    if proof.domain:
        proof_table.add_row("Domain", proof.domain)
    if proof.nonce:
        proof_table.add_row("Nonce", proof.nonce)

    console.print(proof_table)


def main():
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]zcap Cryptographic Operations Demo[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    # Initialize client-side stores
    did_key_store = {}
    capability_store = {}
    revoked_capabilities = set()

    console.print("\n[bold]Generating key pairs for all actors...[/bold]")
    alice_private, alice_public = generate_key_pair(console, "Alice")
    bob_private, bob_public = generate_key_pair(console, "Bob")
    charlie_private, charlie_public = generate_key_pair(console, "Charlie")
    console.print()

    console.print("[bold]STEP 1:[/bold] Populating DID key store")
    simulate_processing(console, "Adding keys to local DID key store...")
    did_key_store["did:example:alice"] = alice_public
    did_key_store["did:example:bob"] = bob_public
    did_key_store["did:example:charlie"] = charlie_public
    console.print("[green]✓[/green] DID key store populated successfully")
    console.print()

    root_cap = None
    delegated_cap = None

    console.print("[bold]STEP 2:[/bold] Creating root capability (Alice → Bob)")
    simulate_processing(console, "Creating and signing capability...")
    try:
        root_cap = create_capability(
            controller_did="did:example:alice",
            invoker_did="did:example:bob",
            actions=[{"name": "read"}],
            target_info={"id": "https://example.com/resource/123", "type": "Resource"},
            controller_key=alice_private,
            expires=datetime.utcnow() + timedelta(days=30),
        )
        capability_store[root_cap.id] = root_cap
        console.print(f"[green]✓[/green] Root capability created: {root_cap.id}")
        if root_cap.proof:
            display_proof(console, root_cap.proof)
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Root capability creation failed: {e}")
        return
    console.print()

    console.print("[bold]STEP 3:[/bold] Creating delegated capability (Bob → Charlie)")
    simulate_processing(console, "Delegating capability...")
    if root_cap:
        try:
            delegated_cap = delegate_capability(
                parent_capability=root_cap,
                delegator_key=bob_private,
                new_invoker_did="did:example:charlie",
                actions=[{"name": "read", "parameters": {"rate_limit": "10/minute"}}],
                expires=datetime.utcnow() + timedelta(hours=24),
                did_key_store=did_key_store,
                revoked_capabilities=revoked_capabilities,
                capability_store=capability_store
            )
            capability_store[delegated_cap.id] = delegated_cap
            console.print(f"[green]✓[/green] Delegated capability created: {delegated_cap.id}")
            if delegated_cap.proof:
                display_proof(console, delegated_cap.proof)
        except (DelegationError, CapabilityVerificationError, DIDKeyNotFoundError, CapabilityNotFoundError, ZCAPException) as e:
            console.print(f"[red]✗[/red] Delegation failed: {e}")
    console.print()

    console.print("[bold]STEP 4:[/bold] Verifying capability chain")
    simulate_processing(console, "Verifying capability signatures...")

    if root_cap:
        console.print("Verifying root capability...")
        try:
            verify_capability(root_cap, did_key_store, revoked_capabilities, capability_store)
            console.print("[green]✓[/green] Root capability verification: [bold green]Valid[/bold green]")
        except (CapabilityVerificationError, DIDKeyNotFoundError, CapabilityNotFoundError, ZCAPException) as e:
            console.print(f"[red]✗[/red] Root capability verification failed: {e}")
    else:
        console.print("[yellow]![/yellow] Skipping root capability verification (not created).")

    if delegated_cap:
        console.print("Verifying delegated capability...")
        try:
            verify_capability(delegated_cap, did_key_store, revoked_capabilities, capability_store)
            console.print("[green]✓[/green] Delegated capability verification: [bold green]Valid[/bold green]")
        except (CapabilityVerificationError, DIDKeyNotFoundError, CapabilityNotFoundError, ZCAPException) as e:
            console.print(f"[red]✗[/red] Delegated capability verification failed: {e}")
    else:
        console.print("[yellow]![/yellow] Skipping delegated capability verification (not created or delegation failed).")

    if root_cap and delegated_cap:
        console.print("\n[bold]Capability chain:[/bold]")
        console.print(f"[cyan]Root:[/cyan] {root_cap.id}")
        console.print(f"[cyan]└── Delegated:[/cyan] {delegated_cap.id} (parent: {delegated_cap.parent_capability})")

    console.print("\n[bold]STEP 5:[/bold] Examining JSON-LD representation of delegated capability")
    if delegated_cap:
        simulate_processing(console, "Generating JSON-LD representation...")
        json_ld = delegated_cap.to_json_ld()

        json_table = Table(title="Delegated Capability JSON-LD")
        json_table.add_column("Property", style="cyan")
        json_table.add_column("Value", style="green")

        json_table.add_row("Context", str(json_ld.get("@context")))
        json_table.add_row("ID", str(json_ld.get("id")))
        json_table.add_row("Type", str(json_ld.get("type")))
        if isinstance(json_ld.get("controller"), dict):
            json_table.add_row("Controller", str(json_ld["controller"].get("id")))
        if isinstance(json_ld.get("invoker"), dict):
            json_table.add_row("Invoker", str(json_ld["invoker"].get("id")))
        json_table.add_row("Parent Capability", str(json_ld.get("parentCapability")))
        if isinstance(json_ld.get("action"), list):
             json_table.add_row("Actions", str([a.get("name") for a in json_ld["action"]]))
        if isinstance(json_ld.get("proof"), dict):
            json_table.add_row("Proof Type", str(json_ld["proof"].get("type")))

        console.print(json_table)
    else:
        console.print("[yellow]![/yellow] Skipping JSON-LD representation (delegated capability not available).")

    console.print(Panel.fit(
        "[bold green]Crypto Operations Demo Completed[/bold green]",
        border_style="green",
        padding=(1, 2)
    ))


if __name__ == "__main__":
    main()
