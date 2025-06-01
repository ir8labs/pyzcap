"""
Examples demonstrating the use of different ZCAP-LD caveat types.
"""

import time
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ed25519
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from zcap.capability import (
    CapabilityVerificationError,
    InvocationError,
    ZCAPException,
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
)


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


def setup_environment(console):
    """Set up keys, DIDs, and client-side stores for the examples."""
    console.print("[bold]Setting up test environment[/bold]")
    simulate_processing(console, "Generating cryptographic keys...")

    service_key = ed25519.Ed25519PrivateKey.generate()
    admin_key = ed25519.Ed25519PrivateKey.generate()
    user_key = ed25519.Ed25519PrivateKey.generate()
    guest_key = ed25519.Ed25519PrivateKey.generate() # For delegation chain example

    # Initialize client-side stores
    did_key_store = {
        "did:example:service": service_key.public_key(),
        "did:example:admin": admin_key.public_key(),
        "did:example:user": user_key.public_key(),
        "did:example:guest": guest_key.public_key(),
    }
    capability_store = {}
    revoked_capabilities = set()
    used_invocation_nonces = set()
    nonce_timestamps = {}

    console.print("[green]✓[/green] Environment (keys & stores) setup complete")
    return service_key, admin_key, user_key, guest_key, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps


def time_based_caveats_example():
    """Demonstrate time-based caveats."""
    console = Console()
    console.print(Panel.fit("[bold cyan]Time-based Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    service_key, admin_key, _, _, did_key_store, capability_store, revoked_caps, nonces, nonce_ts = setup_environment(console)

    target = {"id": "https://example.com/api/resource/time_locked", "type": "ApiResource"}
    expiry_time = datetime.utcnow() + timedelta(seconds=3) # Short expiry for demo
    future_start_time = datetime.utcnow() + timedelta(hours=1) # For ValidAfter

    console.print(f"\n[bold]STEP 1:[/bold] Creating capability valid until: [green]{expiry_time.isoformat()}[/green]")
    try:
        cap_valid_until = create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "read"}], target_info=target, controller_key=service_key,
            caveats=[{"type": "ValidUntil", "date": expiry_time.isoformat()}]
        )
        capability_store[cap_valid_until.id] = cap_valid_until
        console.print(f"[green]✓[/green] Capability {cap_valid_until.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return

    console.print("\n[bold]STEP 2:[/bold] Verifying capability (should be valid now)")
    try:
        verify_capability(cap_valid_until, did_key_store, revoked_caps, capability_store)
        console.print("[green]✓[/green] Verification: [bold green]Valid[/bold green] (as expected)")
    except CapabilityVerificationError as e:
        console.print(f"[red]✗[/red] Verification failed: {e}")

    console.print("\n[bold]STEP 3:[/bold] Invoking capability (should succeed now)")
    try:
        invocation = invoke_capability(cap_valid_until, "read", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print(f"[green]✓[/green] Invocation successful. ID: {invocation['id']}")
    except InvocationError as e:
        console.print(f"[red]✗[/red] Invocation failed: {e}")

    console.print(f"\n[bold]STEP 4:[/bold] Waiting for capability to expire (approx {expiry_time - datetime.utcnow()})...")
    time.sleep(max(0, (expiry_time - datetime.utcnow()).total_seconds() + 0.5)) # Wait past expiry

    console.print("\n[bold]STEP 5:[/bold] Verifying capability (should be expired)")
    try:
        verify_capability(cap_valid_until, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification: [bold green]Valid[/bold green] (UNEXPECTED, should be expired)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification failed as expected: {e}")

    console.print("\n[bold]STEP 6:[/bold] Invoking capability (should fail due to expiry)")
    try:
        invoke_capability(cap_valid_until, "read", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Invocation successful (UNEXPECTED, should be expired)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] Invocation failed as expected: {e}")

    console.print(f"\n[bold]STEP 7:[/bold] Creating capability valid after: [green]{future_start_time.isoformat()}[/green]")
    try:
        cap_valid_after = create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "access"}], target_info=target, controller_key=service_key,
            caveats=[{"type": "ValidAfter", "date": future_start_time.isoformat()}]
        )
        capability_store[cap_valid_after.id] = cap_valid_after
        console.print(f"[green]✓[/green] Capability {cap_valid_after.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return

    console.print("\n[bold]STEP 8:[/bold] Verifying 'ValidAfter' capability (should not be valid yet)")
    try:
        verify_capability(cap_valid_after, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification: [bold green]Valid[/bold green] (UNEXPECTED, not active yet)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification failed as expected: {e}")
    console.print("--- Time-based Caveats Example Complete ---\n")


def action_restriction_caveats_example():
    """Demonstrate action restriction caveats."""
    console = Console()
    console.print(Panel.fit("[bold cyan]Action Restriction Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    service_key, admin_key, user_key, _, did_key_store, capability_store, revoked_caps, nonces, nonce_ts = setup_environment(console)

    target = {"id": "https://example.com/documents/report.pdf", "type": "Document"}

    console.print("\n[bold]STEP 1:[/bold] Creating root capability with actions: read, write, delete")
    try:
        root_cap = create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "read"}, {"name": "write"}, {"name": "delete"}],
            target_info=target, controller_key=service_key
        )
        capability_store[root_cap.id] = root_cap
        console.print(f"[green]✓[/green] Root capability {root_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return

    console.print("\n[bold]STEP 2:[/bold] Delegating to user with caveat: AllowedAction: [read]")
    try:
        delegated_cap = delegate_capability(
            parent_capability=root_cap, delegator_key=admin_key, new_invoker_did="did:example:user",
            # Actions are inherited if not specified, caveat will restrict invocation.
            # To explicitly narrow actions at delegation time (good practice):
            # actions=[{"name": "read"}],
            caveats=[{"type": "AllowedAction", "actions": ["read"]}],
            did_key_store=did_key_store, revoked_capabilities=revoked_caps, capability_store=capability_store
        )
        capability_store[delegated_cap.id] = delegated_cap
        console.print(f"[green]✓[/green] Delegated capability {delegated_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Delegation failed: {e}")
        return

    console.print("\n[bold]STEP 3:[/bold] User invokes with allowed 'read' action")
    try:
        invoke_capability(delegated_cap, "read", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[green]✓[/green] 'read' invocation: [bold green]Successful[/bold green]")
    except InvocationError as e:
        console.print(f"[red]✗[/red] 'read' invocation failed: {e}")

    console.print("\n[bold]STEP 4:[/bold] User invokes with disallowed 'write' action")
    try:
        invoke_capability(delegated_cap, "write", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] 'write' invocation: [bold green]Successful[/bold green] (UNEXPECTED)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] 'write' invocation failed as expected: {e}")
    console.print("--- Action Restriction Caveats Example Complete ---\n")


def parameter_restriction_example():
    """Demonstrate parameter restriction caveats."""
    console = Console()
    console.print(Panel.fit("[bold cyan]Parameter Restriction Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    service_key, admin_key, user_key, _, did_key_store, capability_store, revoked_caps, nonces, nonce_ts = setup_environment(console)
    target = {"id": "https://example.com/api/data/items", "type": "ApiEndpoint"}

    console.print("\n[bold]STEP 1:[/bold] Creating capability with 'update' action")
    try:
        root_cap = create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "update"}], target_info=target, controller_key=service_key
        )
        capability_store[root_cap.id] = root_cap
        console.print(f"[green]✓[/green] Root capability {root_cap.id} created for 'update' action.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return

    console.print("\n[bold]STEP 2:[/bold] Delegating with caveat: RequireParameter: {parameter: 'itemId', value: 'item-42'}")
    try:
        delegated_cap = delegate_capability(
            parent_capability=root_cap, delegator_key=admin_key, new_invoker_did="did:example:user",
            caveats=[{"type": "RequireParameter", "parameter": "itemId", "value": "item-42"}],
            did_key_store=did_key_store, revoked_capabilities=revoked_caps, capability_store=capability_store
        )
        capability_store[delegated_cap.id] = delegated_cap
        console.print(f"[green]✓[/green] Delegated capability {delegated_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Delegation failed: {e}")
        return

    console.print("\n[bold]STEP 3:[/bold] User invokes 'update' with correct parameter: {itemId: 'item-42'}")
    try:
        invoke_capability(delegated_cap, "update", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts, parameters={"itemId": "item-42", "data": "new_value"})
        console.print("[green]✓[/green] Invocation with correct param: [bold green]Successful[/bold green]")
    except InvocationError as e:
        console.print(f"[red]✗[/red] Invocation with correct param failed: {e}")

    console.print("\n[bold]STEP 4:[/bold] User invokes 'update' with incorrect parameter value: {itemId: 'item-99'}")
    try:
        invoke_capability(delegated_cap, "update", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts, parameters={"itemId": "item-99", "data": "other_value"})
        console.print("[red]![/red] Invocation with incorrect param value: [bold green]Successful[/bold green] (UNEXPECTED)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] Invocation with incorrect param value failed as expected: {e}")

    console.print("\n[bold]STEP 5:[/bold] User invokes 'update' with missing required parameter")
    try:
        invoke_capability(delegated_cap, "update", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts, parameters={"data": "some_data"})
        console.print("[red]![/red] Invocation with missing param: [bold green]Successful[/bold green] (UNEXPECTED)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] Invocation with missing param failed as expected: {e}")
    console.print("--- Parameter Restriction Caveats Example Complete ---\n")


def conditional_caveat_example(): # ValidWhileTrue
    """Demonstrate conditional caveats like ValidWhileTrue."""
    console = Console()
    console.print(Panel.fit("[bold cyan]Conditional Caveat (ValidWhileTrue) Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    service_key, admin_key, user_key, _, did_key_store, capability_store, revoked_caps, nonces, nonce_ts = setup_environment(console)
    target = {"id": "https://example.com/features/beta_feature", "type": "ExperimentalFeature"}
    condition_id_for_caveat = "condition:feature_enabled_globally"

    console.print(f"\n[bold]STEP 1:[/bold] Creating capability with caveat: ValidWhileTrue: {{conditionId: '{condition_id_for_caveat}'}}")
    try:
        cap_conditional = create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "access"}], target_info=target, controller_key=service_key,
            caveats=[{"type": "ValidWhileTrue", "conditionId": condition_id_for_caveat}]
        )
        capability_store[cap_conditional.id] = cap_conditional
        console.print(f"[green]✓[/green] Conditional capability {cap_conditional.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return

    console.print("\n[bold]STEP 2:[/bold] Verifying/Invoking when condition is TRUE (not in revoked_caps)")
    # 'revoked_caps' here acts as the store of things that make conditions FALSE
    try:
        verify_capability(cap_conditional, did_key_store, revoked_caps, capability_store)
        console.print("[green]✓[/green] Verification (condition TRUE): [bold green]Valid[/bold green]")
        invoke_capability(cap_conditional, "access", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[green]✓[/green] Invocation (condition TRUE): [bold green]Successful[/bold green]")
    except (CapabilityVerificationError, InvocationError) as e:
        console.print(f"[red]✗[/red] Verification/Invocation failed (condition TRUE): {e}")

    console.print(f"\n[bold]STEP 3:[/bold] Simulating condition becoming FALSE (add '{condition_id_for_caveat}' to revoked_caps)")
    revoked_caps.add(condition_id_for_caveat) # Simulate the condition becoming false
    console.print(f"[yellow]![/yellow] '{condition_id_for_caveat}' added to 'revoked_caps' set.")

    console.print("\n[bold]STEP 4:[/bold] Verifying/Invoking when condition is FALSE")
    try:
        verify_capability(cap_conditional, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification (condition FALSE): [bold green]Valid[/bold green] (UNEXPECTED)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification (condition FALSE) failed as expected: {e}")

    try:
        invoke_capability(cap_conditional, "access", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Invocation (condition FALSE): [bold green]Successful[/bold green] (UNEXPECTED)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] Invocation (condition FALSE) failed as expected: {e}")
    console.print("--- Conditional Caveat Example Complete ---\n")


def delegation_chain_caveats_example():
    """Demonstrate how caveats accumulate and are checked in a delegation chain."""
    console = Console()
    console.print(Panel.fit("[bold cyan]Delegation Chain Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    service_key, admin_key, user_key, guest_key, did_key_store, capability_store, revoked_caps, nonces, nonce_ts = setup_environment(console)
    target = {"id": "https://example.com/project/files/confidential.doc", "type": "ProjectFile"}

    console.print("\n[bold]STEP 1:[/bold] Service creates root capability for Admin (expires in 1 day)")
    root_expiry = datetime.utcnow() + timedelta(days=1)
    try:
        root_cap = create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "read"}, {"name": "comment"}], target_info=target, controller_key=service_key,
            expires=root_expiry,
            caveats=[{"type": "AllowedNetwork", "networks": ["corp_vpn"]}] # Client must evaluate this
        )
        capability_store[root_cap.id] = root_cap
        console.print(f"[green]✓[/green] Root capability {root_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return

    console.print("\n[bold]STEP 2:[/bold] Admin delegates to User (expires in 12 hours, TimeSlot caveat)")
    user_expiry = datetime.utcnow() + timedelta(hours=12)
    try:
        user_delegated_cap = delegate_capability(
            parent_capability=root_cap, delegator_key=admin_key, new_invoker_did="did:example:user",
            actions=[{"name": "read"}], # Narrowing actions
            expires=user_expiry, # Narrowing expiry
            caveats=[{"type": "TimeSlot", "start": "08:00", "end": "18:00"}],
            did_key_store=did_key_store, revoked_capabilities=revoked_caps, capability_store=capability_store
        )
        capability_store[user_delegated_cap.id] = user_delegated_cap
        console.print(f"[green]✓[/green] User delegated capability {user_delegated_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] User delegation failed: {e}")
        return

    console.print("\n[bold]STEP 3:[/bold] User delegates to Guest (expires in 1 hour, no new action caveats, parent caveats apply)")
    guest_expiry = datetime.utcnow() + timedelta(hours=1)
    try:
        guest_delegated_cap = delegate_capability(
            parent_capability=user_delegated_cap, delegator_key=user_key, new_invoker_did="did:example:guest",
            # Actions inherited from user_delegated_cap ('read')
            expires=guest_expiry, # Further narrowing expiry
            # No new caveats, but inherits TimeSlot and AllowedNetwork from parents
            did_key_store=did_key_store, revoked_capabilities=revoked_caps, capability_store=capability_store
        )
        capability_store[guest_delegated_cap.id] = guest_delegated_cap
        console.print(f"[green]✓[/green] Guest delegated capability {guest_delegated_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Guest delegation failed: {e}")
        return

    console.print("\n[bold]STEP 4:[/bold] Verify Guest's capability (checks entire chain)")
    try:
        verify_capability(guest_delegated_cap, did_key_store, revoked_caps, capability_store)
        console.print("[green]✓[/green] Guest capability verification: [bold green]Valid[/bold green] (assuming current time is within 08:00-18:00 and on corp_vpn)")
    except CapabilityVerificationError as e:
        console.print(f"[red]✗[/red] Guest capability verification failed: {e}")

    console.print("\n[bold]STEP 5:[/bold] Guest attempts to invoke 'read' action")
    # This will pass if current time is within 08:00-18:00 (from user_delegated_cap)
    # and AllowedNetwork caveat (from root_cap) is considered met (client-side check)
    try:
        invoke_capability(guest_delegated_cap, "read", guest_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[green]✓[/green] Guest invocation: [bold green]Successful[/bold green] (caveats met)")
    except InvocationError as e:
        console.print(f"[red]✗[/red] Guest invocation failed: {e}")

    console.print("\n[bold]STEP 6:[/bold] Simulate revoking Admin's capability (root_cap)")
    revoked_caps.add(root_cap.id)
    console.print(f"[yellow]![/yellow] Root capability {root_cap.id} added to revoked set.")

    console.print("\n[bold]STEP 7:[/bold] Guest attempts to invoke 'read' action again (should fail due to revoked parent)")
    try:
        invoke_capability(guest_delegated_cap, "read", guest_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Guest invocation after parent revoke: [bold green]Successful[/bold green] (UNEXPECTED)")
    except (InvocationError, CapabilityVerificationError) as e:
        console.print(f"[green]✓[/green] Guest invocation after parent revoke failed as expected: {e}")
    console.print("--- Delegation Chain Caveats Example Complete ---\n")


def unknown_and_unevaluatable_caveats_example():
    """Demonstrate how unknown or client-side evaluatable caveats are handled."""
    console = Console()
    console.print(Panel.fit("[bold cyan]Unknown & Client-Side Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    service_key, admin_key, _, _, did_key_store, capability_store, revoked_caps, nonces, nonce_ts = setup_environment(console)
    target = {"id": "https://example.com/resource/special", "type": "SpecialResource"}

    console.print("\n[bold]STEP 1:[/bold] Creating capability with an 'UnknownCaveatType' and 'AllowedNetwork'")
    try:
        cap_with_unknown = create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "use"}], target_info=target, controller_key=service_key,
            caveats=[
                {"type": "UnknownCaveatType", "detail": "some custom rule"},
                {"type": "AllowedNetwork", "networks": ["192.168.1.0/24"]}
            ]
        )
        capability_store[cap_with_unknown.id] = cap_with_unknown
        console.print(f"[green]✓[/green] Capability {cap_with_unknown.id} created with unknown/client-side caveats.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return

    console.print("\n[bold]STEP 2:[/bold] Verifying capability with 'UnknownCaveatType' (should fail by default)")
    try:
        verify_capability(cap_with_unknown, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification with unknown caveat: [bold green]Valid[/bold green] (UNEXPECTED - unknown caveats should cause failure)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification with unknown caveat failed as expected: {e}")

    console.print("\n[bold]STEP 3:[/bold] Invoking capability (should also fail due to unknown caveat during verification path)")
    # Even if AllowedNetwork is met client-side, the UnknownCaveatType should prevent invocation via verify_capability failing.
    try:
        invoke_capability(cap_with_unknown, "use", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Invocation with unknown caveat: [bold green]Successful[/bold green] (UNEXPECTED)")
    except (InvocationError, CapabilityVerificationError) as e:
        # The error might be CapabilityVerificationError if verify_capability is called internally first and fails
        console.print(f"[green]✓[/green] Invocation with unknown caveat failed as expected: {e}")

    console.print("\nNote: 'AllowedNetwork' type caveats are skipped by the library's evaluate_caveat function ")
    console.print("as they require client-side context (e.g., request IP). The client application is responsible")
    console.print("for evaluating such caveats before or after library calls if they are critical.")
    console.print("The library fails on *unknown* caveat types by default.")
    console.print("--- Unknown & Client-Side Caveats Example Complete ---\n")


if __name__ == "__main__":
    time_based_caveats_example()
    action_restriction_caveats_example()
    parameter_restriction_example()
    conditional_caveat_example()
    delegation_chain_caveats_example()
    unknown_and_unevaluatable_caveats_example()
