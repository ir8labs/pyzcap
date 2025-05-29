"""
Examples demonstrating the use of different ZCAP-LD caveat types.
"""

from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from pyzcap.capability import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    register_public_key,
    revoke_capability,
)


def setup_environment():
    """Set up keys and identities for the examples."""
    # Generate keys for different parties
    service_key = ed25519.Ed25519PrivateKey.generate()
    admin_key = ed25519.Ed25519PrivateKey.generate()
    user_key = ed25519.Ed25519PrivateKey.generate()

    # Register the public keys
    register_public_key("did:example:service", service_key.public_key())
    register_public_key("did:example:admin", admin_key.public_key())
    register_public_key("did:example:user", user_key.public_key())

    return service_key, admin_key, user_key


def time_based_caveats_example():
    """Demonstrate time-based caveats."""
    print("\n=== Time-based Caveats Example ===")

    service_key, admin_key, user_key = setup_environment()

    # Create a resource target
    target = {"id": "https://example.com/api/resource/123", "type": "ApiResource"}

    # Create a capability with time-based caveats
    # This capability is valid for 24 hours
    expiry = datetime.utcnow() + timedelta(hours=24)

    print(f"Creating capability valid until: {expiry.isoformat()}")

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
    is_valid = verify_capability(capability)
    print(f"Capability valid now? {is_valid}")

    # Try to invoke the capability
    invocation = invoke_capability(capability, "read", admin_key)
    print(f"Capability invocation successful? {invocation is not None}")
    if invocation:
        print(f"  Invocation ID: {invocation['id']}")
        print(f"  Proof purpose: {invocation['proof']['proofPurpose']}")

    # Create a capability that will be valid in the future
    future_start = datetime.utcnow() + timedelta(hours=2)

    print(f"Creating capability valid after: {future_start.isoformat()}")

    future_capability = create_capability(
        controller="did:example:service",
        invoker="did:example:admin",
        actions=[{"name": "read", "parameters": {}}],
        target=target,
        controller_key=service_key,
        caveats=[{"type": "ValidAfter", "date": future_start.isoformat()}],
    )

    # Verify the capability (should fail as it's not valid yet)
    is_valid = verify_capability(future_capability)
    print(f"Future capability valid now? {is_valid}")


def action_restriction_caveats_example():
    """Demonstrate action restriction caveats."""
    print("\n=== Action Restriction Caveats Example ===")

    service_key, admin_key, user_key = setup_environment()

    # Create a resource target
    target = {"id": "https://example.com/documents/report.pdf", "type": "Document"}

    # Create a capability with all actions
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

    # Delegate to a user with restricted actions
    print("Delegating capability with restricted actions (read-only)")

    delegated = delegate_capability(
        parent_capability=capability,
        delegator_key=admin_key,
        new_invoker="did:example:user",
        caveats=[{"type": "AllowedAction", "actions": ["read"]}],
    )

    # Try to invoke with allowed action
    read_invocation = invoke_capability(delegated, "read", user_key)
    print(f"Read action invocation successful? {read_invocation is not None}")

    # Try to invoke with prohibited action
    write_invocation = invoke_capability(delegated, "write", user_key)
    print(f"Write action invocation successful? {write_invocation is not None}")


def parameter_restriction_example():
    """Demonstrate parameter restriction caveats."""
    print("\n=== Parameter Restriction Caveats Example ===")

    service_key, admin_key, user_key = setup_environment()

    # Create a resource target
    target = {"id": "https://example.com/api/data", "type": "ApiEndpoint"}

    # Create a capability
    capability = create_capability(
        controller="did:example:service",
        invoker="did:example:admin",
        actions=[{"name": "query", "parameters": {"mode": "any"}}],
        target=target,
        controller_key=service_key,
    )

    # Delegate with parameter restrictions
    print("Delegating capability with parameter restrictions")

    delegated = delegate_capability(
        parent_capability=capability,
        delegator_key=admin_key,
        new_invoker="did:example:user",
        caveats=[
            {"type": "RequireParameter", "parameter": "mode", "value": "readonly"}
        ],
    )

    # Try to invoke with correct parameter
    correct_params = {"mode": "readonly"}
    success1 = invoke_capability(delegated, "query", user_key, correct_params)
    print(
        f"Invocation with correct parameter (mode=readonly) successful? {success1 is not None}"
    )
    if success1:
        print(f"  Parameter value: {success1['parameters']['mode']}")

    # Try to invoke with wrong parameter
    wrong_params = {"mode": "readwrite"}
    success2 = invoke_capability(delegated, "query", user_key, wrong_params)
    print(
        f"Invocation with wrong parameter (mode=readwrite) successful? {success2 is not None}"
    )

    # Try to invoke with missing parameter
    success3 = invoke_capability(delegated, "query", user_key)
    print(f"Invocation with missing parameter successful? {success3 is not None}")


def conditional_caveat_example():
    """Demonstrate conditional caveats (ValidWhileTrue)."""
    print("\n=== Conditional Caveats Example ===")

    service_key, admin_key, user_key = setup_environment()

    # Create a resource target
    target = {"id": "https://example.com/subscription/premium", "type": "Subscription"}

    # Create a condition ID for this example
    condition_id = "condition:subscription:active"

    # Create a capability with ValidWhileTrue caveat
    print(f"Creating capability valid while condition '{condition_id}' is true")

    capability = create_capability(
        controller="did:example:service",
        invoker="did:example:user",
        actions=[{"name": "access", "parameters": {}}],
        target=target,
        controller_key=service_key,
        caveats=[{"type": "ValidWhileTrue", "conditionId": condition_id}],
    )

    # Verify and invoke while condition is true
    is_valid = verify_capability(capability)
    print(f"Capability valid with active condition? {is_valid}")

    invocation = invoke_capability(capability, "access", user_key)
    print(f"Invocation successful with active condition? {invocation is not None}")
    if invocation:
        print(f"  Invocation ID: {invocation['id']}")
        print(f"  Action: {invocation['action']}")

    # Now revoke the condition (e.g., subscription ended)
    print("Revoking the condition (e.g., subscription ended)")
    revoke_capability(condition_id)

    # Verify and invoke after condition is false
    is_valid = verify_capability(capability)
    print(f"Capability valid after condition revoked? {is_valid}")

    invocation = invoke_capability(capability, "access", user_key)
    print(f"Invocation successful after condition revoked? {invocation is not None}")


def delegation_chain_caveats_example():
    """Demonstrate how caveats accumulate through a delegation chain."""
    print("\n=== Delegation Chain Caveats Example ===")

    service_key, admin_key, user_key = setup_environment()
    guest_key = ed25519.Ed25519PrivateKey.generate()
    register_public_key("did:example:guest", guest_key.public_key())

    # Create a resource target
    target = {"id": "https://example.com/dashboard", "type": "Dashboard"}

    # Root capability with time-based caveat
    expiry = datetime.utcnow() + timedelta(days=30)
    print("Creating root capability with 30-day expiry")

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

    # First delegation with action restrictions
    print("First delegation: admin to user with action restrictions")
    first_delegation = delegate_capability(
        parent_capability=root,
        delegator_key=admin_key,
        new_invoker="did:example:user",
        caveats=[{"type": "AllowedAction", "actions": ["view", "share"]}],
    )

    # Second delegation with parameter restrictions
    print("Second delegation: user to guest with parameter restrictions")
    second_delegation = delegate_capability(
        parent_capability=first_delegation,
        delegator_key=user_key,
        new_invoker="did:example:guest",
        caveats=[{"type": "RequireParameter", "parameter": "mode", "value": "basic"}],
    )

    # Test invocations
    # Try to invoke with allowed action but missing parameter
    invocation1 = invoke_capability(second_delegation, "view", guest_key)
    print(
        f"Guest invocation with missing parameter successful? {invocation1 is not None}"
    )

    # Try with correct parameter but prohibited action
    invocation2 = invoke_capability(
        second_delegation, "edit", guest_key, {"mode": "basic"}
    )
    print(
        f"Guest invocation with prohibited action successful? {invocation2 is not None}"
    )

    # Try with allowed action and correct parameter
    invocation3 = invoke_capability(
        second_delegation, "view", guest_key, {"mode": "basic"}
    )
    print(
        f"Guest invocation with correct action and parameter successful? {invocation3 is not None}"
    )
    if invocation3:
        print(f"  Invocation ID: {invocation3['id']}")
        print(f"  Action: {invocation3['action']}")
        print(f"  Parameter: mode={invocation3['parameters']['mode']}")


if __name__ == "__main__":
    time_based_caveats_example()
    action_restriction_caveats_example()
    parameter_restriction_example()
    conditional_caveat_example()
    delegation_chain_caveats_example()
