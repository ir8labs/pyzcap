"""
Example script to demonstrate creating and signing a ZCAP-LD capability.
"""

import asyncio
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from zcap.capability import create_capability
from zcap.models import Capability # Assuming Capability model might be useful for type hinting or direct use
import json # For pretty printing


async def main():
    console = Console()

    # --- 1. Setup: Generate Keys and Define DIDs ---
    console.print(Panel("[bold cyan]1. Setup: Generating Keys and Defining DIDs[/bold cyan]"))

    # Generate a private key for the controller of the capability
    # In a real scenario, this key would be securely stored and loaded.
    controller_private_key = ed25519.Ed25519PrivateKey.generate()
    controller_public_key = controller_private_key.public_key()

    # Define DIDs (Decentralized Identifiers) for controller and invoker
    # These are example DIDs. In a real system, they would be resolvable.
    controller_did = "did:example:controller123"
    invoker_did = "did:example:invoker456"
    resource_id = "urn:example:resource789"

    console.print(f"Controller DID: [green]{controller_did}[/green]")
    console.print(f"Invoker DID:    [green]{invoker_did}[/green]")
    console.print(f"Target Resource ID: [green]{resource_id}[/green]")
    console.print("[green]✓[/green] Setup complete.")

    # --- 2. Define Capability Parameters ---
    console.print(Panel("[bold cyan]2. Defining Capability Parameters[/bold cyan]"))

    actions = [{"name": "read"}, {"name": "write"}]
    target_info = {"id": resource_id, "type": "Document"} # Added type for target
    expires_at = datetime.utcnow() + timedelta(days=30)
    # No caveats for this basic example, but they could be added:
    # caveats = [{"type": "ValidUntil", "date": expires_at.isoformat()}] 

    console.print(f"Actions: {actions}")
    console.print(f"Target Info: {target_info}")
    console.print(f"Expires at: {expires_at.isoformat()}")
    console.print("[green]✓[/green] Parameters defined.")

    # --- 3. Create and Sign the Capability ---
    console.print(Panel("[bold cyan]3. Creating and Signing the Capability[/bold cyan]"))
    
    try:
        new_capability: Capability = await create_capability(
            controller_did=controller_did,
            invoker_did=invoker_did,
            actions=actions,
            target_info=target_info,
            controller_key=controller_private_key,
            expires=expires_at,
            # caveats=caveats # Uncomment if you add caveats
        )
        console.print("[green]✓[/green] Capability created and signed successfully!")

        # --- 4. Display the Signed Capability ---
        console.print(Panel("[bold cyan]4. Displaying the Signed Capability (JSON-LD)[/bold cyan]"))

        capability_json_ld = new_capability.to_json_ld()
        
        # Pretty print the JSON-LD
        pretty_json = json.dumps(capability_json_ld, indent=2)
        console.print(Syntax(pretty_json, "json", theme="native", line_numbers=True))

        console.print(f"\nCapability ID: [bold yellow]{new_capability.id}[/bold yellow]")
        if new_capability.proof:
            console.print(f"Proof Value (Signature): [bold yellow]{new_capability.proof.proof_value}[/bold yellow]")

    except Exception as e:
        console.print(f"[bold red]Error creating capability:[/bold red] {e}")


if __name__ == "__main__":
    asyncio.run(main())
