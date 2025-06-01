"""
Example demonstrating cryptographic operations in ZCAP-LD.

This example shows:
1. Key generation and management
2. Capability signing
3. Signature verification
4. Proof chain validation
"""

import time
from datetime import datetime, timedelta
from base64 import b64encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from zcap import (
    create_capability,
    delegate_capability,
    verify_capability,
    register_public_key,
    models,
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


def generate_key_pair(
    console: Console, name: str
) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate an Ed25519 key pair and display the public key."""
    simulate_processing(console, f"Generating {name}'s key pair...", 0.7)
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get the public key bytes
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    console.print(f"[cyan]{name}[/cyan]'s public key: [green]{b64encode(public_bytes).decode()}[/green]")
    return private_key, public_key


def display_proof(console: Console, proof: models.Proof) -> None:
    """Display the details of a capability proof."""
    proof_table = Table(title="Proof Details")
    proof_table.add_column("Property", style="cyan")
    proof_table.add_column("Value", style="green")
    
    proof_table.add_row("ID", proof.id)
    proof_table.add_row("Type", proof.type)
    proof_table.add_row("Created", str(proof.created))
    proof_table.add_row("Verification Method", proof.verification_method)
    proof_table.add_row("Purpose", proof.proof_purpose)
    proof_table.add_row("Value", f"{proof.proof_value[:32]}...")  # Show first 32 chars of proof
    
    if proof.domain:
        proof_table.add_row("Domain", proof.domain)
    if proof.nonce:
        proof_table.add_row("Nonce", proof.nonce)
        
    console.print(proof_table)


def main():
    console = Console()
    
    # Display header
    console.print(Panel.fit(
        "[bold cyan]zcap Cryptographic Operations Demo[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    console.print("\n[bold]Generating key pairs for all actors...[/bold]")
    alice_private, alice_public = generate_key_pair(console, "Alice")
    bob_private, bob_public = generate_key_pair(console, "Bob")
    charlie_private, charlie_public = generate_key_pair(console, "Charlie")
    console.print()

    # Register public keys for DIDs
    console.print("[bold]STEP 1:[/bold] Registering public keys")
    simulate_processing(console, "Registering DIDs in the key registry...", 0.8)
    
    register_public_key("did:example:alice", alice_public)
    register_public_key("did:example:bob", bob_public)
    register_public_key("did:example:charlie", charlie_public)
    
    console.print("[green]✓[/green] All DIDs registered successfully")
    console.print()

    # Create a root capability from Alice to Bob
    console.print("[bold]STEP 2:[/bold] Creating root capability (Alice → Bob)")
    simulate_processing(console, "Creating and signing capability...", 1.0)
    
    root_cap = create_capability(
        controller="did:example:alice",
        invoker="did:example:bob",
        actions=[{"name": "read", "parameters": {}}],
        target={"id": "https://example.com/resource/123", "type": "Resource"},
        controller_key=alice_private,
        expires=datetime.utcnow() + timedelta(days=30),
    )

    console.print("[green]✓[/green] Root capability created and signed")
    display_proof(console, root_cap.proof)
    console.print()

    # Bob delegates to Charlie
    console.print("[bold]STEP 3:[/bold] Creating delegated capability (Bob → Charlie)")
    simulate_processing(console, "Delegating capability...", 1.0)
    
    delegated_cap = delegate_capability(
        parent_capability=root_cap,
        delegator_key=bob_private,
        new_invoker="did:example:charlie",
        actions=[{"name": "read", "parameters": {"rate_limit": "10/minute"}}],
        expires=datetime.utcnow() + timedelta(hours=24),
    )

    console.print("[green]✓[/green] Delegated capability created and signed")
    display_proof(console, delegated_cap.proof)
    console.print()

    # Verify the delegation chain
    console.print("[bold]STEP 4:[/bold] Verifying capability chain")
    simulate_processing(console, "Verifying capability signatures...", 1.2)

    # First verify the root capability
    root_valid = verify_capability(root_cap)
    
    if root_valid:
        console.print("[green]✓[/green] Root capability verification: [bold green]Valid[/bold green]")
    else:
        console.print("[red]✗[/red] Root capability verification: [bold red]Invalid[/bold red]")

    # Then verify the delegated capability
    delegated_valid = verify_capability(delegated_cap)
    
    if delegated_valid:
        console.print("[green]✓[/green] Delegated capability verification: [bold green]Valid[/bold green]")
    else:
        console.print("[red]✗[/red] Delegated capability verification: [bold red]Invalid[/bold red]")

    # Show the complete chain
    console.print("\n[bold]Capability chain:[/bold]")
    console.print(f"[cyan]Root:[/cyan] {root_cap.id}")
    console.print(f"[cyan]└── Delegated:[/cyan] {delegated_cap.id}")

    # Convert to JSON-LD and show the structure
    console.print("\n[bold]STEP 5:[/bold] Examining JSON-LD representation")
    simulate_processing(console, "Generating JSON-LD representation...", 0.8)
    
    json_ld = delegated_cap.to_json_ld()
    
    json_table = Table(title="JSON-LD Representation")
    json_table.add_column("Property", style="cyan")
    json_table.add_column("Value", style="green")
    
    json_table.add_row("Context", str(json_ld["@context"]))
    json_table.add_row("Type", str(json_ld["type"]))
    json_table.add_row("Controller", json_ld["controller"]["id"])
    json_table.add_row("Invoker", json_ld["invoker"]["id"])
    json_table.add_row("Parent", str(json_ld.get("parentCapability")))
    json_table.add_row("Actions", str([a["name"] for a in json_ld["action"]]))
    
    console.print(json_table)
    
    console.print(Panel.fit(
        "[bold green]Demo Completed Successfully![/bold green]",
        border_style="green",
        padding=(1, 2)
    ))


if __name__ == "__main__":
    main()
