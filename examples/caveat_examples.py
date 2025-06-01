"""
Examples demonstrating the use of different ZCAP-LD caveat types.
"""

import asyncio
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
    evaluate_caveat,
    CaveatEvaluationError
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

    service_key_priv = ed25519.Ed25519PrivateKey.generate()
    admin_key_priv = ed25519.Ed25519PrivateKey.generate()
    user_key_priv = ed25519.Ed25519PrivateKey.generate()
    guest_key_priv = ed25519.Ed25519PrivateKey.generate()

    did_key_store = {
        "did:example:service": service_key_priv.public_key(),
        "did:example:admin": admin_key_priv.public_key(),
        "did:example:user": user_key_priv.public_key(),
        "did:example:guest": guest_key_priv.public_key(),
    }
    capability_store = {}
    revoked_capabilities = set()
    used_invocation_nonces = set()
    nonce_timestamps = {}

    console.print("[green]✓[/green] Environment (keys & stores) setup complete")
    # Return private keys as well for operations
    return (
        service_key_priv, admin_key_priv, user_key_priv, guest_key_priv,
        did_key_store, capability_store, revoked_capabilities,
        used_invocation_nonces, nonce_timestamps
    )


async def time_based_caveats_example_async(console, service_key, admin_key, did_key_store, capability_store, revoked_caps, nonces, nonce_ts):
    """Demonstrate time-based caveats."""
    console.print(Panel.fit("[bold cyan]Time-based Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))

    target = {"id": "https://example.com/api/resource/time_locked", "type": "ApiResource"}
    expiry_time = datetime.utcnow() + timedelta(seconds=3)
    future_start_time = datetime.utcnow() + timedelta(hours=1)

    console.print(f"\n[bold]STEP 1:[/bold] Creating capability valid until: [green]{expiry_time.isoformat()}[/green]")
    cap_valid_until = None
    try:
        cap_valid_until = await create_capability(
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
        await verify_capability(cap_valid_until, did_key_store, revoked_caps, capability_store)
        console.print("[green]✓[/green] Verification: [bold green]Valid[/bold green] (as expected)")
    except CapabilityVerificationError as e:
        console.print(f"[red]✗[/red] Verification failed: {e}")

    console.print("\n[bold]STEP 3:[/bold] Invoking capability (should succeed now)")
    try:
        invocation = await invoke_capability(cap_valid_until, "read", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print(f"[green]✓[/green] Invocation successful. ID: {invocation['id']}")
    except InvocationError as e:
        console.print(f"[red]✗[/red] Invocation failed: {e}")

    console.print(f"\n[bold]STEP 4:[/bold] Waiting for capability to expire (approx {expiry_time - datetime.utcnow()})...")
    await asyncio.sleep(max(0, (expiry_time - datetime.utcnow()).total_seconds() + 0.5))

    console.print("\n[bold]STEP 5:[/bold] Verifying capability (should be expired)")
    try:
        await verify_capability(cap_valid_until, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification: [bold green]Valid[/bold green] (UNEXPECTED, should be expired)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification failed as expected: {e}")

    console.print("\n[bold]STEP 6:[/bold] Invoking capability (should fail due to expiry)")
    try:
        await invoke_capability(cap_valid_until, "read", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Invocation successful (UNEXPECTED, should be expired)")
    except (InvocationError, CapabilityVerificationError) as e:
        console.print(f"[green]✓[/green] Invocation failed as expected: {e}")

    console.print(f"\n[bold]STEP 7:[/bold] Creating capability valid after: [green]{future_start_time.isoformat()}[/green]")
    cap_valid_after = None
    try:
        cap_valid_after = await create_capability(
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
        await verify_capability(cap_valid_after, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification: [bold green]Valid[/bold green] (UNEXPECTED, not active yet)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification failed as expected: {e}")
    console.print("--- Time-based Caveats Example Complete ---\n")


async def action_restriction_caveats_example_async(console, service_key, admin_key, user_key, did_key_store, capability_store, revoked_caps, nonces, nonce_ts):
    """Demonstrate action restriction caveats."""
    console.print(Panel.fit("[bold cyan]Action Restriction Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))

    target = {"id": "https://example.com/documents/report.pdf", "type": "Document"}
    root_cap = None
    console.print("\n[bold]STEP 1:[/bold] Creating root capability with actions: read, write, delete")
    try:
        root_cap = await create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "read"}, {"name": "write"}, {"name": "delete"}],
            target_info=target, controller_key=service_key
        )
        capability_store[root_cap.id] = root_cap
        console.print(f"[green]✓[/green] Root capability {root_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return
    delegated_cap = None
    console.print("\n[bold]STEP 2:[/bold] Delegating to user with caveat: AllowedAction: [read]")
    try:
        delegated_cap = await delegate_capability(
            parent_capability=root_cap, delegator_key=admin_key, new_invoker_did="did:example:user",
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
        await invoke_capability(delegated_cap, "read", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[green]✓[/green] 'read' invocation: [bold green]Successful[/bold green]")
    except InvocationError as e:
        console.print(f"[red]✗[/red] 'read' invocation failed: {e}")

    console.print("\n[bold]STEP 4:[/bold] User invokes with disallowed 'write' action")
    try:
        await invoke_capability(delegated_cap, "write", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] 'write' invocation: [bold green]Successful[/bold green] (UNEXPECTED)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] 'write' invocation failed as expected: {e}")
    console.print("--- Action Restriction Caveats Example Complete ---\n")


async def parameter_restriction_example_async(console, service_key, admin_key, user_key, did_key_store, capability_store, revoked_caps, nonces, nonce_ts):
    """Demonstrate parameter restriction caveats."""
    console.print(Panel.fit("[bold cyan]Parameter Restriction Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    target = {"id": "https://example.com/api/data/items", "type": "ApiEndpoint"}
    root_cap = None
    console.print("\n[bold]STEP 1:[/bold] Creating capability with 'update' action")
    try:
        root_cap = await create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "update"}], target_info=target, controller_key=service_key
        )
        capability_store[root_cap.id] = root_cap
        console.print(f"[green]✓[/green] Root capability {root_cap.id} created for 'update' action.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return
    delegated_cap = None
    console.print("\n[bold]STEP 2:[/bold] Delegating with caveat: RequireParameter: {parameter: 'itemId', value: 'item-42'}")
    try:
        delegated_cap = await delegate_capability(
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
        await invoke_capability(delegated_cap, "update", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts, parameters={"itemId": "item-42", "data": "new_value"})
        console.print("[green]✓[/green] Invocation with correct param: [bold green]Successful[/bold green]")
    except InvocationError as e:
        console.print(f"[red]✗[/red] Invocation with correct param failed: {e}")

    console.print("\n[bold]STEP 4:[/bold] User invokes 'update' with incorrect parameter value: {itemId: 'item-99'}")
    try:
        await invoke_capability(delegated_cap, "update", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts, parameters={"itemId": "item-99", "data": "other_value"})
        console.print("[red]![/red] Invocation with incorrect param value: [bold green]Successful[/bold green] (UNEXPECTED)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] Invocation with incorrect param value failed as expected: {e}")

    console.print("\n[bold]STEP 5:[/bold] User invokes 'update' with missing required parameter")
    try:
        await invoke_capability(delegated_cap, "update", user_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts, parameters={"data": "some_data"})
        console.print("[red]![/red] Invocation with missing param: [bold green]Successful[/bold green] (UNEXPECTED)")
    except InvocationError as e:
        console.print(f"[green]✓[/green] Invocation with missing param failed as expected: {e}")
    console.print("--- Parameter Restriction Caveats Example Complete ---\n")


async def conditional_caveat_example_async(console, service_key, admin_key, user_key, did_key_store, capability_store, revoked_caps, nonces, nonce_ts):
    """Demonstrate conditional caveats like ValidWhileTrue."""
    console.print(Panel.fit("[bold cyan]Conditional Caveat (ValidWhileTrue) Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    target = {"id": "https://example.com/features/beta_feature", "type": "ExperimentalFeature"}
    condition_id_for_caveat = "condition:feature_enabled_globally"
    cap_conditional = None
    console.print(f"\n[bold]STEP 1:[/bold] Creating capability with caveat: ValidWhileTrue: {{conditionId: '{condition_id_for_caveat}'}}")
    try:
        cap_conditional = await create_capability(
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
    try:
        await verify_capability(cap_conditional, did_key_store, revoked_caps, capability_store)
        console.print("[green]✓[/green] Verification (condition TRUE): [bold green]Valid[/bold green]")
        await invoke_capability(cap_conditional, "access", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[green]✓[/green] Invocation (condition TRUE): [bold green]Successful[/bold green]")
    except (CapabilityVerificationError, InvocationError) as e:
        console.print(f"[red]✗[/red] Verification/Invocation failed (condition TRUE): {e}")

    console.print(f"\n[bold]STEP 3:[/bold] Simulating condition becoming FALSE (add '{condition_id_for_caveat}' to revoked_caps)")
    revoked_caps.add(condition_id_for_caveat)
    console.print(f"[yellow]![/yellow] '{condition_id_for_caveat}' added to 'revoked_caps' set.")

    console.print("\n[bold]STEP 4:[/bold] Verifying/Invoking when condition is FALSE")
    try:
        await verify_capability(cap_conditional, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification (condition FALSE): [bold green]Valid[/bold green] (UNEXPECTED)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification (condition FALSE) failed as expected: {e}")

    try:
        await invoke_capability(cap_conditional, "access", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Invocation (condition FALSE): [bold green]Successful[/bold green] (UNEXPECTED)")
    except (InvocationError, CapabilityVerificationError) as e:
        console.print(f"[green]✓[/green] Invocation (condition FALSE) failed as expected: {e}")
    console.print("--- Conditional Caveat Example Complete ---\n")


async def delegation_chain_caveats_example_async(console, service_key, admin_key, user_key, guest_key, did_key_store, capability_store, revoked_caps, nonces, nonce_ts):
    """Demonstrate how caveats accumulate and are checked in a delegation chain."""
    console.print(Panel.fit("[bold cyan]Delegation Chain Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    target = {"id": "https://example.com/project/files/confidential.doc", "type": "ProjectFile"}
    root_cap = None
    console.print("\n[bold]STEP 1:[/bold] Service creates root capability for Admin (expires in 1 day)")
    root_expiry = datetime.utcnow() + timedelta(days=1)
    try:
        root_cap = await create_capability(
            controller_did="did:example:service", invoker_did="did:example:admin",
            actions=[{"name": "read"}, {"name": "comment"}], target_info=target, controller_key=service_key,
            expires=root_expiry,
            caveats=[{"type": "AllowedNetwork", "networks": ["corp_vpn"]}]
        )
        capability_store[root_cap.id] = root_cap
        console.print(f"[green]✓[/green] Root capability {root_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Creation failed: {e}")
        return
    user_delegated_cap = None
    console.print("\n[bold]STEP 2:[/bold] Admin delegates to User (expires in 12 hours, TimeSlot caveat)")
    user_expiry = datetime.utcnow() + timedelta(hours=12)
    try:
        user_delegated_cap = await delegate_capability(
            parent_capability=root_cap, delegator_key=admin_key, new_invoker_did="did:example:user",
            actions=[{"name": "read"}],
            expires=user_expiry,
            caveats=[{"type": "TimeSlot", "start": "08:00", "end": "18:00"}],
            did_key_store=did_key_store, revoked_capabilities=revoked_caps, capability_store=capability_store
        )
        capability_store[user_delegated_cap.id] = user_delegated_cap
        console.print(f"[green]✓[/green] User delegated capability {user_delegated_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] User delegation failed: {e}")
        return
    guest_delegated_cap = None
    console.print("\n[bold]STEP 3:[/bold] User delegates to Guest (expires in 1 hour, no new action caveats, parent caveats apply)")
    guest_expiry = datetime.utcnow() + timedelta(hours=1)
    try:
        guest_delegated_cap = await delegate_capability(
            parent_capability=user_delegated_cap, delegator_key=user_key, new_invoker_did="did:example:guest",
            expires=guest_expiry,
            did_key_store=did_key_store, revoked_capabilities=revoked_caps, capability_store=capability_store
        )
        capability_store[guest_delegated_cap.id] = guest_delegated_cap
        console.print(f"[green]✓[/green] Guest delegated capability {guest_delegated_cap.id} created.")
    except ZCAPException as e:
        console.print(f"[red]✗[/red] Guest delegation failed: {e}")
        return

    console.print("\n[bold]STEP 4:[/bold] Verify Guest's capability (checks entire chain)")
    try:
        await verify_capability(guest_delegated_cap, did_key_store, revoked_caps, capability_store)
        console.print("[green]✓[/green] Guest capability verification: [bold green]Valid[/bold green] (assuming current time is within 08:00-18:00 and on corp_vpn)")
    except CapabilityVerificationError as e:
        console.print(f"[red]✗[/red] Guest capability verification failed: {e}")

    console.print("\n[bold]STEP 5:[/bold] Guest attempts to invoke 'read' action")
    try:
        await invoke_capability(guest_delegated_cap, "read", guest_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[green]✓[/green] Guest invocation: [bold green]Successful[/bold green] (caveats met)")
    except InvocationError as e:
        console.print(f"[red]✗[/red] Guest invocation failed: {e}")

    console.print("\n[bold]STEP 6:[/bold] Simulate revoking Admin's capability (root_cap)")
    revoked_caps.add(root_cap.id)
    console.print(f"[yellow]![/yellow] Root capability {root_cap.id} added to revoked set.")

    console.print("\n[bold]STEP 7:[/bold] Guest attempts to invoke 'read' action again (should fail due to revoked parent)")
    try:
        await invoke_capability(guest_delegated_cap, "read", guest_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Guest invocation after parent revoke: [bold green]Successful[/bold green] (UNEXPECTED)")
    except (InvocationError, CapabilityVerificationError) as e:
        console.print(f"[green]✓[/green] Guest invocation after parent revoke failed as expected: {e}")
    console.print("--- Delegation Chain Caveats Example Complete ---\n")


async def unknown_and_unevaluatable_caveats_example_async(console, service_key, admin_key, did_key_store, capability_store, revoked_caps, nonces, nonce_ts):
    """Demonstrate how unknown or client-side evaluatable caveats are handled."""
    console.print(Panel.fit("[bold cyan]Unknown & Client-Side Caveats Example[/bold cyan]", border_style="cyan", padding=(1, 2)))
    target = {"id": "https://example.com/resource/special", "type": "SpecialResource"}
    cap_with_unknown = None
    console.print("\n[bold]STEP 1:[/bold] Creating capability with an 'UnknownCaveatType' and 'AllowedNetwork'")
    try:
        cap_with_unknown = await create_capability(
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
        await verify_capability(cap_with_unknown, did_key_store, revoked_caps, capability_store)
        console.print("[red]![/red] Verification with unknown caveat: [bold green]Valid[/bold green] (UNEXPECTED - unknown caveats should cause failure)")
    except CapabilityVerificationError as e:
        console.print(f"[green]✓[/green] Verification with unknown caveat failed as expected: {e}")

    console.print("\n[bold]STEP 3:[/bold] Invoking capability (should also fail due to unknown caveat during verification path)")
    try:
        await invoke_capability(cap_with_unknown, "use", admin_key, did_key_store, revoked_caps, capability_store, nonces, nonce_ts)
        console.print("[red]![/red] Invocation with unknown caveat: [bold green]Successful[/bold green] (UNEXPECTED)")
    except (InvocationError, CapabilityVerificationError) as e:
        console.print(f"[green]✓[/green] Invocation with unknown caveat failed as expected: {e}")

    console.print("\nNote: 'AllowedNetwork' type caveats are skipped by the library's evaluate_caveat function ")
    console.print("as they require client-side context (e.g., request IP). The client application is responsible")
    console.print("for evaluating such caveats before or after library calls if they are critical.")
    console.print("The library fails on *unknown* caveat types by default.")
    console.print("--- Unknown & Client-Side Caveats Example Complete ---\n")


def print_test_result(test_name, success, details=""):
    status = "PASSED" if success else "FAILED"
    color_status = "\033[92m" + status + "\033[0m" if success else "\033[91m" + status + "\033[0m"
    print(f"Test: {test_name} - {color_status}")
    if details:
        print(f"  Details: {details}")
    print("---")


async def run_caveat_evaluation_tests():
    print("\n=== Testing Direct Caveat Evaluation ===")
    # ... (rest of this function remains the same as it's self-contained and synchronous)
    # ValidUntil
    try:
        evaluate_caveat({"type": "ValidUntil", "date": (datetime.utcnow() + timedelta(days=1)).isoformat()})
        print_test_result("ValidUntil - Active", True)
    except CaveatEvaluationError as e:
        print_test_result("ValidUntil - Active", False, e)
    try:
        evaluate_caveat({"type": "ValidUntil", "date": (datetime.utcnow() - timedelta(days=1)).isoformat()})
        print_test_result("ValidUntil - Expired", False, "Exception not raised as expected for expired caveat.")
    except CaveatEvaluationError:
        print_test_result("ValidUntil - Expired", True, "Correctly failed for expired caveat.")

    # ValidAfter
    try:
        evaluate_caveat({"type": "ValidAfter", "date": (datetime.utcnow() - timedelta(days=1)).isoformat()})
        print_test_result("ValidAfter - Active", True)
    except CaveatEvaluationError as e:
        print_test_result("ValidAfter - Active", False, e)
    try:
        evaluate_caveat({"type": "ValidAfter", "date": (datetime.utcnow() + timedelta(days=1)).isoformat()})
        print_test_result("ValidAfter - Not Yet Active", False, "Exception not raised as expected.")
    except CaveatEvaluationError:
        print_test_result("ValidAfter - Not Yet Active", True, "Correctly failed as not yet active.")

    # ValidWhileTrue
    revoked_ids_for_vwt = {"condition:revoked"}
    try:
        evaluate_caveat({"type": "ValidWhileTrue", "conditionId": "condition:active"}, revoked_ids=revoked_ids_for_vwt)
        print_test_result("ValidWhileTrue - Active", True)
    except CaveatEvaluationError as e:
        print_test_result("ValidWhileTrue - Active", False, e)
    try:
        evaluate_caveat({"type": "ValidWhileTrue", "conditionId": "condition:revoked"}, revoked_ids=revoked_ids_for_vwt)
        print_test_result("ValidWhileTrue - Revoked", False, "Exception not raised as expected.")
    except CaveatEvaluationError:
        print_test_result("ValidWhileTrue - Revoked", True, "Correctly failed as condition is revoked.")

    # AllowedAction
    try:
        evaluate_caveat({"type": "AllowedAction", "actions": ["read", "update"]}, action="read")
        print_test_result("AllowedAction - Permitted", True)
    except CaveatEvaluationError as e:
        print_test_result("AllowedAction - Permitted", False, e)
    try:
        evaluate_caveat({"type": "AllowedAction", "actions": ["read"]}, action="update")
        print_test_result("AllowedAction - Denied", False, "Exception not raised as expected.")
    except CaveatEvaluationError:
        print_test_result("AllowedAction - Denied", True, "Correctly failed as action not allowed.")
    try: # No action context, should pass
        evaluate_caveat({"type": "AllowedAction", "actions": ["read"]})
        print_test_result("AllowedAction - No action context", True, "Caveat did not restrict as no action was being taken.")
    except CaveatEvaluationError as e:
        print_test_result("AllowedAction - No action context", False, f"Unexpected failure: {e}")


    # RequireParameter
    try:
        evaluate_caveat({"type": "RequireParameter", "parameter": "format", "value": "json"}, action="export", parameters={"format": "json"})
        print_test_result("RequireParameter - Satisfied", True)
    except CaveatEvaluationError as e:
        print_test_result("RequireParameter - Satisfied", False, e)
    try:
        evaluate_caveat({"type": "RequireParameter", "parameter": "format", "value": "json"}, action="export", parameters={"format": "xml"})
        print_test_result("RequireParameter - Wrong Value", False, "Exception not raised.")
    except CaveatEvaluationError:
        print_test_result("RequireParameter - Wrong Value", True, "Correctly failed.")
    try:
        evaluate_caveat({"type": "RequireParameter", "parameter": "format", "value": "json"}, action="export", parameters={})
        print_test_result("RequireParameter - Missing Param", False, "Exception not raised.")
    except CaveatEvaluationError:
        print_test_result("RequireParameter - Missing Param", True, "Correctly failed.")
    try: # No parameter context for action
        evaluate_caveat({"type": "RequireParameter", "parameter": "format", "value": "json"}, action="export")
        print_test_result("RequireParameter - No parameter context", False, "Exception not raised.")
    except CaveatEvaluationError:
        print_test_result("RequireParameter - No parameter context", True, "Correctly failed.")

    # MaxUses and AllowedNetwork (pass-through by evaluate_caveat)
    try:
        evaluate_caveat({"type": "MaxUses", "limit": 10})
        print_test_result("MaxUses - Pass-through", True)
    except CaveatEvaluationError as e:
        print_test_result("MaxUses - Pass-through", False, e)
    try:
        evaluate_caveat({"type": "AllowedNetwork", "cidr": "192.168.0.0/24"})
        print_test_result("AllowedNetwork - Pass-through", True)
    except CaveatEvaluationError as e:
        print_test_result("AllowedNetwork - Pass-through", False, e)

    # Unknown caveat type
    try:
        evaluate_caveat({"type": "SuperSecureCondition", "level": "max"})
        print_test_result("Unknown Caveat Type", False, "Exception not raised for unknown type.")
    except CaveatEvaluationError:
        print_test_result("Unknown Caveat Type", True, "Correctly failed for unknown type.")

async def run_caveats_in_capabilities_tests(service_key, admin_key, user_key, guest_key, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps):
    print("\n=== Testing Caveats within Capability Operations ===")
    # Removed global store initializations as they are now passed in

    # 1. Capability with ValidUntil caveat
    print("\nTest 1: Capability with ValidUntil (active and expired)")
    capability_store.clear()
    revoked_capabilities.clear()
    active_expiry = datetime.utcnow() + timedelta(days=1)
    cap_valid_until_active = None
    try:
        cap_valid_until_active = await create_capability(
            controller_did="did:example:service",
            invoker_did="did:example:admin",
            actions=[{"name": "read"}],
            target_info={"id": "urn:resource:valid_until_active", "type": "TestResource"},
            controller_key=service_key, # Use passed-in private key
            caveats=[{"type": "ValidUntil", "date": active_expiry.isoformat()}]
        )
        capability_store[cap_valid_until_active.id] = cap_valid_until_active
        await verify_capability(cap_valid_until_active, did_key_store, revoked_capabilities, capability_store)
        await invoke_capability(cap_valid_until_active, "read", admin_key, did_key_store, revoked_capabilities, capability_store, used_invocation_nonces, nonce_timestamps)
        print_test_result("Cap with ValidUntil (Active) - Verify & Invoke", True)
    except ZCAPException as e:
        print_test_result("Cap with ValidUntil (Active) - Verify & Invoke", False, e)

    expired_expiry = datetime.utcnow() - timedelta(days=1)
    cap_valid_until_expired = None # Define before try block
    try:
        cap_valid_until_expired = await create_capability(
            controller_did="did:example:service",
            invoker_did="did:example:admin",
            actions=[{"name": "read"}],
            target_info={"id": "urn:resource:valid_until_expired", "type": "TestResource"},
            controller_key=service_key, # Use passed-in private key
            caveats=[{"type": "ValidUntil", "date": expired_expiry.isoformat()}]
        )
        capability_store[cap_valid_until_expired.id] = cap_valid_until_expired
        await verify_capability(cap_valid_until_expired, did_key_store, revoked_capabilities, capability_store)
        print_test_result("Cap with ValidUntil (Expired) - Verification", False, "Verification should fail.")
    except CapabilityVerificationError:
        print_test_result("Cap with ValidUntil (Expired) - Verification", True, "Correctly failed verification.")
    except ZCAPException as e:
        print_test_result("Cap with ValidUntil (Expired) - Verification", False, f"Unexpected ZCAPException: {e}")

    # 2. Capability with AllowedAction caveat during invocation
    print("\nTest 2: Capability with AllowedAction during invocation")
    capability_store.clear()
    revoked_capabilities.clear()
    cap_allowed_action = None
    try:
        cap_allowed_action = await create_capability(
            controller_did="did:example:service",
            invoker_did="did:example:admin",
            actions=[{"name": "read"}, {"name": "write"}],
            target_info={"id": "urn:resource:allowed_action_test", "type": "TestResource"},
            controller_key=service_key, # Use passed-in private key
            caveats=[{"type": "AllowedAction", "actions": ["read"]}]
        )
        capability_store[cap_allowed_action.id] = cap_allowed_action
        await invoke_capability(cap_allowed_action, "read", admin_key, did_key_store, revoked_capabilities, capability_store, used_invocation_nonces, nonce_timestamps)
        print_test_result("AllowedAction - Invoke Permitted Action", True)
    except ZCAPException as e:
        print_test_result("AllowedAction - Invoke Permitted Action", False, e)
    
    if cap_allowed_action:
        try:
            await invoke_capability(cap_allowed_action, "write", admin_key, did_key_store, revoked_capabilities, capability_store, used_invocation_nonces, nonce_timestamps)
            print_test_result("AllowedAction - Invoke Denied Action", False, "Invocation should fail due to caveat.")
        except InvocationError as e:
             if "Caveat not satisfied" in str(e) or "Invocation failed due to caveat" in str(e):
                print_test_result("AllowedAction - Invoke Denied Action", True, "Correctly failed due to caveat.")
             else:
                 print_test_result("AllowedAction - Invoke Denied Action", False, f"Failed, but not due to expected caveat error: {e}")
        except ZCAPException as e:
            print_test_result("AllowedAction - Invoke Denied Action", False, f"Unexpected ZCAPException: {e}")

    # 3. Delegation with caveats
    print("\nTest 3: Delegation adding and respecting caveats")
    capability_store.clear()
    revoked_capabilities.clear()
    parent_cap_for_delegation = None
    delegated_cap_with_caveats = None
    try:
        parent_cap_for_delegation = await create_capability(
            controller_did="did:example:service",
            invoker_did="did:example:admin",
            actions=[{"name": "read"}, {"name": "admin"}],
            target_info={"id": "urn:resource:delegation_caveat_test", "type": "TestResource"},
            controller_key=service_key, # Use passed-in private key
            caveats=[{"type": "ValidUntil", "date": (datetime.utcnow() + timedelta(days=5)).isoformat()}]
        )
        capability_store[parent_cap_for_delegation.id] = parent_cap_for_delegation

        delegated_cap_with_caveats = await delegate_capability(
            parent_capability=parent_cap_for_delegation,
            delegator_key=admin_key, # Use passed-in private key for admin
            new_invoker_did="did:example:guest",
            actions=[{"name": "read"}],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            caveats=[
                {"type": "ValidAfter", "date": (datetime.utcnow() - timedelta(hours=1)).isoformat()},
                {"type": "RequireParameter", "parameter": "user_group", "value": "editors"} 
            ]
        )
        capability_store[delegated_cap_with_caveats.id] = delegated_cap_with_caveats
        print_test_result("Delegation with Additional Caveats - Creation", True)
    except ZCAPException as e:
        print_test_result("Delegation with Additional Caveats - Creation", False, e)
        return

    if delegated_cap_with_caveats:
        try:
            await invoke_capability(
                delegated_cap_with_caveats, 
                "read", 
                guest_key, # Use passed-in private key for guest
                did_key_store, 
                revoked_capabilities, 
                capability_store,   # Swapped with revoked_capabilities
                used_invocation_nonces, 
                nonce_timestamps,
                parameters={"user_group": "editors"}
            )
            print_test_result("Delegated Caveats - Invoke Success (Params Met)", True)
        except ZCAPException as e:
            print_test_result("Delegated Caveats - Invoke Success (Params Met)", False, e)

        try:
            await invoke_capability(
                delegated_cap_with_caveats, 
                "read", 
                guest_key, # Use passed-in private key for guest
                did_key_store, 
                revoked_capabilities,  # Swapped with capability_store
                capability_store,   # Swapped with revoked_capabilities
                used_invocation_nonces, 
                nonce_timestamps,
                parameters={"user_group": "viewers"}
            )
            print_test_result("Delegated Caveats - Invoke Fail (Param Mismatch)", False, "Invocation should fail.")
        except InvocationError as e:
             if "Caveat not satisfied" in str(e) or "Invocation failed due to caveat" in str(e):
                print_test_result("Delegated Caveats - Invoke Fail (Param Mismatch)", True, "Correctly failed due to RequireParameter caveat.")
             else:
                print_test_result("Delegated Caveats - Invoke Fail (Param Mismatch)", False, f"Failed, but not for expected caveat reason: {e}")
        except ZCAPException as e:
            print_test_result("Delegated Caveats - Invoke Fail (Param Mismatch)", False, f"Unexpected ZCAPException: {e}")
        
        if parent_cap_for_delegation:
            original_parent_caveats = parent_cap_for_delegation.caveats
            parent_cap_for_delegation.caveats = [{"type": "ValidUntil", "date": (datetime.utcnow() - timedelta(days=1)).isoformat()}]
            capability_store[parent_cap_for_delegation.id] = parent_cap_for_delegation
            try:
                await verify_capability(delegated_cap_with_caveats, did_key_store, revoked_capabilities, capability_store)
                print_test_result("Delegated Caveats - Parent Expired (Verification)", False, "Verification should fail due to expired parent caveat.")
            except CapabilityVerificationError as e:
                if "Caveat evaluation failed" in str(e):
                    print_test_result("Delegated Caveats - Parent Expired (Verification)", True, "Correctly failed due to expired parent caveat.")
                else:
                    print_test_result("Delegated Caveats - Parent Expired (Verification)", False, f"Verification failed, but not for expected parent caveat reason: {e}")     
            except ZCAPException as e:
                 print_test_result("Delegated Caveats - Parent Expired (Verification)", False, f"Unexpected ZCAPException: {e}")
            parent_cap_for_delegation.caveats = original_parent_caveats
            capability_store[parent_cap_for_delegation.id] = parent_cap_for_delegation


async def main():
    console = Console()
    print("--- ZCAP-LD Caveat Examples ---")
    
    # Setup environment once
    (
        service_key_priv, admin_key_priv, user_key_priv, guest_key_priv,
        did_key_store, capability_store, revoked_capabilities,
        used_invocation_nonces, nonce_timestamps
    ) = setup_environment(console)

    # Clear and reset stores for each example run to ensure isolation if needed, or manage state carefully.
    # For simplicity, these examples currently share and modify the same stores sequentially.
    # If true isolation is needed, each example function should re-initialize its stores.

    # Make example functions async and pass necessary parts of the environment
    # Note: The original example functions like time_based_caveats_example were synchronous
    # and called setup_environment themselves. They are now made async and get env passed.

    await time_based_caveats_example_async(console, service_key_priv, admin_key_priv, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps)
    # Reset stores for the next example if they are meant to be independent
    capability_store.clear()
    revoked_capabilities.clear()
    used_invocation_nonces.clear()
    nonce_timestamps.clear()

    await action_restriction_caveats_example_async(console, service_key_priv, admin_key_priv, user_key_priv, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps)
    capability_store.clear()
    revoked_capabilities.clear()
    used_invocation_nonces.clear()
    nonce_timestamps.clear()

    await parameter_restriction_example_async(console, service_key_priv, admin_key_priv, user_key_priv, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps)
    capability_store.clear()
    revoked_capabilities.clear()
    used_invocation_nonces.clear()
    nonce_timestamps.clear()

    await conditional_caveat_example_async(console, service_key_priv, admin_key_priv, user_key_priv, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps)
    capability_store.clear()
    revoked_capabilities.clear()
    used_invocation_nonces.clear()
    nonce_timestamps.clear()
    
    await delegation_chain_caveats_example_async(console, service_key_priv, admin_key_priv, user_key_priv, guest_key_priv, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps)
    capability_store.clear()
    revoked_capabilities.clear()
    used_invocation_nonces.clear()
    nonce_timestamps.clear()

    await unknown_and_unevaluatable_caveats_example_async(console, service_key_priv, admin_key_priv, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps)
    capability_store.clear()
    revoked_capabilities.clear()
    used_invocation_nonces.clear()
    nonce_timestamps.clear()

    # run_caveat_evaluation_tests is synchronous and self-contained for direct caveat logic testing.
    await run_caveat_evaluation_tests()
    
    # The run_caveats_in_capabilities_tests function needs to be integrated similarly or its logic tested via the above examples.
    # For now, let's call it by passing the fully initialized environment from main.
    # Reset stores before this specific test suite if it's meant to be clean.
    capability_store.clear()
    revoked_capabilities.clear()
    used_invocation_nonces.clear()
    nonce_timestamps.clear()
    await run_caveats_in_capabilities_tests(service_key_priv, admin_key_priv, user_key_priv, guest_key_priv, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps)

    print("\n--- Caveat Examples End ---")

if __name__ == "__main__":
    asyncio.run(main())
