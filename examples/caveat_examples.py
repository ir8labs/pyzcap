"""
Examples demonstrating the use of different ZCAP-LD caveat types.
"""

import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from pyzcap.capability import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    register_public_key,
    revoke_capability,
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


def setup_environment(console):
    """Set up keys and identities for the examples."""
    # Generate keys for different parties
    console.print("[bold]Setting up test environment[/bold]")
    simulate_processing(console, "Generating cryptographic keys...", 0.8)

    service_key = ed25519.Ed25519PrivateKey.generate()
    admin_key = ed25519.Ed25519PrivateKey.generate()
    user_key = ed25519.Ed25519PrivateKey.generate()

    # Register the public keys
    simulate_processing(console, "Registering identities...", 0.5)
    register_public_key("did:example:service", service_key.public_key())
    register_public_key("did:example:admin", admin_key.public_key())
    register_public_key("did:example:user", user_key.public_key())

    console.print("[green]✓[/green] Environment setup complete")

    return service_key, admin_key, user_key


def time_based_caveats_example():
    """Demonstrate time-based caveats."""
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]Time-based Caveats Example[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    service_key, admin_key, user_key = setup_environment(console)

    # Create a resource target
    target = {"id": "https://example.com/api/resource/123", "type": "ApiResource"}

    # Create a capability with time-based caveats
    # This capability is valid for 24 hours
    expiry = datetime.utcnow() + timedelta(hours=24)

    console.print(f"\n[bold]STEP 1:[/bold] Creating capability valid until: [green]{expiry.isoformat()}[/green]")
    simulate_processing(console, "Creating capability with expiry...", 0.8)

    capability = create_capability(
        controller="did:example:service",
        invoker="did:example:admin",
        actions=[
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {}},
        ],
        target=target,
        controller_key=service_key,
        caveats=[{"type": "ValidUntil", "date": expiry.isoformat()}],
    )

    # Verify the capability is currently valid
    console.print("\n[bold]STEP 2:[/bold] Verifying capability is currently valid")
    simulate_processing(console, "Verifying capability...", 0.8)

    is_valid = verify_capability(capability)

    if is_valid:
        console.print("[green]✓[/green] Capability valid now? [bold green]Yes[/bold green]")
    else:
        console.print("[red]✗[/red] Capability valid now? [bold red]No[/bold red]")

    # Try to invoke the capability
    console.print("\n[bold]STEP 3:[/bold] Invoking capability")
    simulate_processing(console, "Invoking capability...", 0.8)

    invocation = invoke_capability(capability, "read", admin_key)

    if invocation:
        console.print("[green]✓[/green] Capability invocation: [bold green]Successful[/bold green]")

        invoke_table = Table(title="Invocation Details")
        invoke_table.add_column("Property", style="cyan")
        invoke_table.add_column("Value", style="green")

        invoke_table.add_row("ID", invocation['id'])
        invoke_table.add_row("Proof Purpose", invocation['proof']['proofPurpose'])

        console.print(invoke_table)
    else:
        console.print("[red]✗[/red] Capability invocation: [bold red]Failed[/bold red]")

    # Create a capability that will be valid in the future
    future_start = datetime.utcnow() + timedelta(hours=2)

    console.print(f"\n[bold]STEP 4:[/bold] Creating capability valid after: [green]{future_start.isoformat()}[/green]")
    simulate_processing(console, "Creating future-valid capability...", 0.8)

    future_capability = create_capability(
        controller="did:example:service",
        invoker="did:example:admin",
        actions=[{"name": "read", "parameters": {}}],
        target=target,
        controller_key=service_key,
        caveats=[{"type": "ValidAfter", "date": future_start.isoformat()}],
    )

    # Verify the capability (should fail as it's not valid yet)
    console.print("\n[bold]STEP 5:[/bold] Verifying future capability")
    simulate_processing(console, "Verifying future capability...", 0.8)

    is_valid = verify_capability(future_capability)

    if is_valid:
        console.print("[red]![/red] Future capability valid now? [bold green]Yes[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Future capability valid now? [bold red]No[/bold red] (as expected)")


def action_restriction_caveats_example():
    """Demonstrate action restriction caveats."""
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]Action Restriction Caveats Example[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    service_key, admin_key, user_key = setup_environment(console)

    # Create a resource target
    target = {"id": "https://example.com/documents/report.pdf", "type": "Document"}

    # Create a capability with all actions
    console.print("\n[bold]STEP 1:[/bold] Creating root capability with all actions")
    simulate_processing(console, "Creating root capability...", 0.8)

    capability = create_capability(
        controller="did:example:service",
        invoker="did:example:admin",
        actions=[
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {}},
            {"name": "delete", "parameters": {}},
        ],
        target=target,
        controller_key=service_key,
    )

    cap_table = Table(title="Root Capability")
    cap_table.add_column("Property", style="cyan")
    cap_table.add_column("Value", style="green")

    cap_table.add_row("Controller", "did:example:service")
    cap_table.add_row("Invoker", "did:example:admin")
    cap_table.add_row("Actions", "read, write, delete")

    console.print(cap_table)

    # Delegate to a user with restricted actions
    console.print("\n[bold]STEP 2:[/bold] Delegating capability with restricted actions (read-only)")
    simulate_processing(console, "Creating delegated capability...", 0.8)

    delegated = delegate_capability(
        parent_capability=capability,
        delegator_key=admin_key,
        new_invoker="did:example:user",
        caveats=[{"type": "AllowedAction", "actions": ["read"]}],
    )

    del_cap_table = Table(title="Delegated Capability")
    del_cap_table.add_column("Property", style="cyan")
    del_cap_table.add_column("Value", style="green")

    del_cap_table.add_row("Controller", "did:example:admin")
    del_cap_table.add_row("Invoker", "did:example:user")
    del_cap_table.add_row("Actions", "read")
    del_cap_table.add_row("Caveats", "AllowedAction: [read]")

    console.print(del_cap_table)

    # Try to invoke with allowed action
    console.print("\n[bold]STEP 3:[/bold] User tries to invoke with allowed 'read' action")
    simulate_processing(console, "Invoking with 'read' action...", 0.8)

    read_invocation = invoke_capability(delegated, "read", user_key)

    if read_invocation:
        console.print("[green]✓[/green] Read action invocation: [bold green]Successful[/bold green]")
    else:
        console.print("[red]✗[/red] Read action invocation: [bold red]Failed[/bold red]")

    # Try to invoke with prohibited action
    console.print("\n[bold]STEP 4:[/bold] User tries to invoke with prohibited 'write' action")
    simulate_processing(console, "Invoking with 'write' action...", 0.8)

    write_invocation = invoke_capability(delegated, "write", user_key)

    if write_invocation:
        console.print("[red]![/red] Write action invocation: [bold green]Successful[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Write action invocation: [bold red]Failed[/bold red] (as expected)")


def parameter_restriction_example():
    """Demonstrate parameter restriction caveats."""
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]Parameter Restriction Caveats Example[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    service_key, admin_key, user_key = setup_environment(console)

    # Create a resource target
    target = {"id": "https://example.com/api/data", "type": "ApiEndpoint"}

    # Create a capability
    console.print("\n[bold]STEP 1:[/bold] Creating root capability")
    simulate_processing(console, "Creating capability...", 0.8)

    capability = create_capability(
        controller="did:example:service",
        invoker="did:example:admin",
        actions=[{"name": "query", "parameters": {"mode": "any"}}],
        target=target,
        controller_key=service_key,
    )

    # Delegate with parameter restrictions
    console.print("\n[bold]STEP 2:[/bold] Delegating capability with parameter restrictions")
    simulate_processing(console, "Creating delegated capability...", 0.8)

    delegated = delegate_capability(
        parent_capability=capability,
        delegator_key=admin_key,
        new_invoker="did:example:user",
        caveats=[
            {"type": "RequireParameter", "parameter": "mode", "value": "readonly"}
        ],
    )

    # Try to invoke with correct parameter
    console.print("\n[bold]STEP 3:[/bold] Invoking with correct parameter (mode=readonly)")
    simulate_processing(console, "Invoking capability...", 0.8)

    correct_params = {"mode": "readonly"}
    success1 = invoke_capability(delegated, "query", user_key, correct_params)

    if success1:
        console.print("[green]✓[/green] Invocation with correct parameter: [bold green]Successful[/bold green]")
        console.print(f"  Parameter value: [cyan]mode=[/cyan][green]{success1['parameters']['mode']}[/green]")
    else:
        console.print("[red]✗[/red] Invocation with correct parameter: [bold red]Failed[/bold red]")

    # Try to invoke with wrong parameter
    console.print("\n[bold]STEP 4:[/bold] Invoking with wrong parameter (mode=readwrite)")
    simulate_processing(console, "Invoking capability...", 0.8)

    wrong_params = {"mode": "readwrite"}
    success2 = invoke_capability(delegated, "query", user_key, wrong_params)

    if success2:
        console.print("[red]![/red] Invocation with wrong parameter: [bold green]Successful[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Invocation with wrong parameter: [bold red]Failed[/bold red] (as expected)")

    # Try to invoke with missing parameter
    console.print("\n[bold]STEP 5:[/bold] Invoking with missing parameter")
    simulate_processing(console, "Invoking capability...", 0.8)

    success3 = invoke_capability(delegated, "query", user_key)

    if success3:
        console.print("[red]![/red] Invocation with missing parameter: [bold green]Successful[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Invocation with missing parameter: [bold red]Failed[/bold red] (as expected)")


def conditional_caveat_example():
    """Demonstrate conditional caveats (ValidWhileTrue)."""
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]Conditional Caveats Example[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    service_key, admin_key, user_key = setup_environment(console)

    # Create a resource target
    target = {"id": "https://example.com/subscription/premium", "type": "Subscription"}

    # Create a condition ID for this example
    condition_id = "condition:subscription:active"

    # Create a capability with ValidWhileTrue caveat
    console.print(f"\n[bold]STEP 1:[/bold] Creating capability valid while condition '{condition_id}' is true")
    simulate_processing(console, "Creating conditional capability...", 0.8)

    capability = create_capability(
        controller="did:example:service",
        invoker="did:example:user",
        actions=[{"name": "access", "parameters": {}}],
        target=target,
        controller_key=service_key,
        caveats=[{"type": "ValidWhileTrue", "conditionId": condition_id}],
    )

    # Verify and invoke while condition is true
    console.print("\n[bold]STEP 2:[/bold] Verifying capability with active condition")
    simulate_processing(console, "Verifying capability...", 0.8)

    is_valid = verify_capability(capability)

    if is_valid:
        console.print("[green]✓[/green] Capability valid with active condition? [bold green]Yes[/bold green]")
    else:
        console.print("[red]✗[/red] Capability valid with active condition? [bold red]No[/bold red]")

    console.print("\n[bold]STEP 3:[/bold] Invoking capability with active condition")
    simulate_processing(console, "Invoking capability...", 0.8)

    invocation = invoke_capability(capability, "access", user_key)

    if invocation:
        console.print("[green]✓[/green] Invocation successful with active condition")

        invoke_table = Table(title="Invocation Details")
        invoke_table.add_column("Property", style="cyan")
        invoke_table.add_column("Value", style="green")

        invoke_table.add_row("ID", invocation['id'])
        invoke_table.add_row("Action", invocation['action'])

        console.print(invoke_table)
    else:
        console.print("[red]✗[/red] Invocation failed with active condition")

    # Now revoke the condition (e.g., subscription ended)
    console.print("\n[bold]STEP 4:[/bold] Revoking the condition (e.g., subscription ended)")
    simulate_processing(console, "Revoking condition...", 0.8)

    revoke_capability(condition_id)
    console.print("[yellow]![/yellow] Condition has been [bold red]revoked[/bold red]")

    # Verify and invoke after condition is false
    console.print("\n[bold]STEP 5:[/bold] Verifying capability after condition is revoked")
    simulate_processing(console, "Verifying capability...", 0.8)

    is_valid = verify_capability(capability)

    if is_valid:
        console.print("[red]![/red] Capability valid after condition revoked? [bold green]Yes[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Capability valid after condition revoked? [bold red]No[/bold red] (as expected)")

    console.print("\n[bold]STEP 6:[/bold] Invoking capability with revoked condition")
    simulate_processing(console, "Attempting invocation...", 0.8)

    invocation = invoke_capability(capability, "access", user_key)

    if invocation:
        console.print("[red]![/red] Invocation successful after condition revoked? [bold green]Yes[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Invocation failed after condition revoked (as expected)")


def delegation_chain_caveats_example():
    """Demonstrate how caveats accumulate through a delegation chain."""
    console = Console()

    console.print(Panel.fit(
        "[bold cyan]Delegation Chain Caveats Example[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

    service_key, admin_key, user_key = setup_environment(console)

    console.print("\n[bold]Setting up additional actor...[/bold]")
    simulate_processing(console, "Generating guest key...", 0.5)

    guest_key = ed25519.Ed25519PrivateKey.generate()
    register_public_key("did:example:guest", guest_key.public_key())
    console.print("[green]✓[/green] Registered guest identity: [cyan]did:example:guest[/cyan]")

    # Create a resource target
    target = {"id": "https://example.com/dashboard", "type": "Dashboard"}

    # Root capability with time-based caveat
    expiry = datetime.utcnow() + timedelta(days=30)
    console.print("\n[bold]STEP 1:[/bold] Creating root capability with 30-day expiry")
    simulate_processing(console, "Creating root capability...", 0.8)

    root = create_capability(
        controller="did:example:service",
        invoker="did:example:admin",
        actions=[
            {"name": "view", "parameters": {}},
            {"name": "edit", "parameters": {}},
            {"name": "share", "parameters": {}},
        ],
        target=target,
        controller_key=service_key,
        caveats=[{"type": "ValidUntil", "date": expiry.isoformat()}],
    )

    root_table = Table(title="Root Capability")
    root_table.add_column("Property", style="cyan")
    root_table.add_column("Value", style="green")

    root_table.add_row("Actions", "view, edit, share")
    root_table.add_row("Caveats", f"ValidUntil: {expiry.isoformat()}")

    console.print(root_table)

    # First delegation with action restrictions
    console.print("\n[bold]STEP 2:[/bold] First delegation: admin to user with action restrictions")
    simulate_processing(console, "Creating first delegation...", 0.8)

    first_delegation = delegate_capability(
        parent_capability=root,
        delegator_key=admin_key,
        new_invoker="did:example:user",
        caveats=[{"type": "AllowedAction", "actions": ["view", "share"]}],
    )

    first_table = Table(title="First Delegation (User)")
    first_table.add_column("Property", style="cyan")
    first_table.add_column("Value", style="green")

    first_table.add_row("Allowed Actions", "view, share")
    first_table.add_row("Caveats", "AllowedAction: [view, share]")
    first_table.add_row("Original Caveats", f"ValidUntil: {expiry.isoformat()}")

    console.print(first_table)

    # Second delegation with parameter restrictions
    console.print("\n[bold]STEP 3:[/bold] Second delegation: user to guest with parameter restrictions")
    simulate_processing(console, "Creating second delegation...", 0.8)

    second_delegation = delegate_capability(
        parent_capability=first_delegation,
        delegator_key=user_key,
        new_invoker="did:example:guest",
        caveats=[{"type": "RequireParameter", "parameter": "mode", "value": "basic"}],
    )

    second_table = Table(title="Second Delegation (Guest)")
    second_table.add_column("Property", style="cyan")
    second_table.add_column("Value", style="green")

    second_table.add_row("Allowed Actions", "view, share")
    second_table.add_row("Required Parameters", "mode=basic")
    second_table.add_row("Accumulated Caveats", "ValidUntil + AllowedAction + RequireParameter")

    console.print(second_table)

    # Test invocations
    # Try to invoke with allowed action but missing parameter
    console.print("\n[bold]STEP 4:[/bold] Guest invocation with missing parameter")
    simulate_processing(console, "Invoking with missing parameter...", 0.8)

    invocation1 = invoke_capability(second_delegation, "view", guest_key)

    if invocation1:
        console.print("[red]![/red] Guest invocation with missing parameter: [bold green]Successful[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Guest invocation with missing parameter: [bold red]Failed[/bold red] (as expected)")

    # Try with correct parameter but prohibited action
    console.print("\n[bold]STEP 5:[/bold] Guest invocation with prohibited action")
    simulate_processing(console, "Invoking with prohibited action...", 0.8)

    invocation2 = invoke_capability(
        second_delegation, "edit", guest_key, {"mode": "basic"}
    )

    if invocation2:
        console.print("[red]![/red] Guest invocation with prohibited action: [bold green]Successful[/bold green] (unexpected)")
    else:
        console.print("[green]✓[/green] Guest invocation with prohibited action: [bold red]Failed[/bold red] (as expected)")

    # Try with allowed action and correct parameter
    console.print("\n[bold]STEP 6:[/bold] Guest invocation with correct action and parameter")
    simulate_processing(console, "Invoking with correct configuration...", 0.8)

    invocation3 = invoke_capability(
        second_delegation, "view", guest_key, {"mode": "basic"}
    )

    if invocation3:
        console.print("[green]✓[/green] Guest invocation with correct action and parameter: [bold green]Successful[/bold green]")

        final_table = Table(title="Successful Invocation")
        final_table.add_column("Property", style="cyan")
        final_table.add_column("Value", style="green")

        final_table.add_row("ID", invocation3['id'])
        final_table.add_row("Action", invocation3['action'])
        final_table.add_row("Parameter", f"mode={invocation3['parameters']['mode']}")

        console.print(final_table)
    else:
        console.print("[red]✗[/red] Guest invocation with correct action and parameter: [bold red]Failed[/bold red]")


if __name__ == "__main__":
    console = Console()

    time_based_caveats_example()

    console.print("\n\n")

    action_restriction_caveats_example()

    console.print("\n\n")

    parameter_restriction_example()

    console.print("\n\n")

    conditional_caveat_example()

    console.print("\n\n")

    delegation_chain_caveats_example()

    console.print(Panel.fit(
        "[bold green]Caveat Examples Completed Successfully![/bold green]",
        border_style="green",
        padding=(1, 2)
    ))
