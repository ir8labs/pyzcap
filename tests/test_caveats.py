"""
Test cases for ZCAP-LD caveat enforcement.
"""

from datetime import datetime, timedelta

import pytest  # type: ignore
import pytest_asyncio  # type: ignore
from cryptography.hazmat.primitives.asymmetric import ed25519

from zcap.capability import (
    CapabilityVerificationError,
    InvocationError,
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
)
from zcap.models import Capability


@pytest_asyncio.fixture
async def env_setup():
    """Set up test keys and identities and client-managed stores."""
    controller_private = ed25519.Ed25519PrivateKey.generate()
    controller_public = controller_private.public_key()
    controller_did = "did:key:controller"

    invoker_private = ed25519.Ed25519PrivateKey.generate()
    invoker_public = invoker_private.public_key()
    invoker_did = "did:key:invoker"

    delegate_private = ed25519.Ed25519PrivateKey.generate()
    delegate_public = delegate_private.public_key()
    delegate_did = "did:key:delegate"

    did_key_store = {
        controller_did: controller_public,
        invoker_did: invoker_public,
        delegate_did: delegate_public,
    }
    capability_store = {}
    revoked_capabilities = set()
    used_invocation_nonces = set()
    nonce_timestamps = {}

    target_info = {
        "id": "https://example.com/resource/1",
        "type": "ExampleResource",
    }
    actions = [
        {"name": "read", "parameters": {}},
        {"name": "write", "parameters": {}},
    ]
    return (
        controller_private,
        controller_did,
        invoker_private,
        invoker_did,
        delegate_private,
        delegate_did,
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
        target_info,
        actions,
    )


def _add_cap_to_store(capability_store, cap: Capability):  # Helper remains sync
    capability_store[cap.id] = cap


@pytest.mark.asyncio
async def test_time_based_caveats(env_setup):
    """Test time-based caveats (ValidUntil, ValidAfter)."""
    (
        controller_private,
        controller_did,
        invoker_private,
        invoker_did,
        _,
        _,  # delegate_private, delegate_did
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
        target_info,
        actions,
    ) = env_setup

    # Capability that is valid for 1 hour
    future = datetime.utcnow() + timedelta(hours=1)
    caveats1 = [{"type": "ValidUntil", "date": future.isoformat()}]

    cap1 = await create_capability(
        controller_did=controller_did,
        invoker_did=invoker_did,
        target_info=target_info,
        actions=actions,
        controller_key=controller_private,
        caveats=caveats1,
    )
    _add_cap_to_store(capability_store, cap1)

    # Should verify and invoke successfully
    try:
        await verify_capability(
            cap1, did_key_store, revoked_capabilities, capability_store
        )
    except CapabilityVerificationError as e:
        pytest.fail(f"Valid capability verification failed: {e}")

    invocation1 = await invoke_capability(
        capability=cap1,
        action_name="read",
        invoker_key=invoker_private,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert invocation1 is not None

    # Capability that is valid starting tomorrow
    tomorrow = datetime.utcnow() + timedelta(days=1)
    caveats2 = [{"type": "ValidAfter", "date": tomorrow.isoformat()}]

    cap2 = await create_capability(
        controller_did=controller_did,
        invoker_did=invoker_did,
        target_info=target_info,
        actions=actions,
        controller_key=controller_private,
        caveats=caveats2,
    )
    _add_cap_to_store(capability_store, cap2)

    # Should fail verification and invocation
    with pytest.raises(CapabilityVerificationError):
        await verify_capability(
            cap2, did_key_store, revoked_capabilities, capability_store
        )

    with pytest.raises(
        CapabilityVerificationError
    ):  # Invocation first verifies capability
        await invoke_capability(
            capability=cap2,
            action_name="read",
            invoker_key=invoker_private,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )


@pytest.mark.asyncio
async def test_action_specific_caveats(env_setup):
    """Test action-specific caveats."""
    (
        controller_private,
        controller_did,
        invoker_private,
        invoker_did,
        _,
        _,  # delegate_private, delegate_did
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
        target_info,
        actions,
    ) = env_setup

    caveats_allowed_action = [{"type": "AllowedAction", "actions": ["read"]}]

    cap_allowed = await create_capability(
        controller_did=controller_did,
        invoker_did=invoker_did,
        target_info=target_info,
        actions=actions,  # Main capability allows read and write
        controller_key=controller_private,
        caveats=caveats_allowed_action,
    )
    _add_cap_to_store(capability_store, cap_allowed)

    try:
        await verify_capability(
            cap_allowed, did_key_store, revoked_capabilities, capability_store
        )
    except CapabilityVerificationError as e:
        pytest.fail(f"AllowedAction cap verification failed: {e}")

    read_invocation = await invoke_capability(
        capability=cap_allowed,
        action_name="read",
        invoker_key=invoker_private,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert read_invocation is not None
    assert read_invocation["action"] == "read"

    with pytest.raises(InvocationError):  # Caveat restricts to 'read'
        await invoke_capability(
            capability=cap_allowed,
            action_name="write",
            invoker_key=invoker_private,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )

    caveats_req_param = [
        {"type": "RequireParameter", "parameter": "mode", "value": "secure"}
    ]
    cap_req_param = await create_capability(
        controller_did=controller_did,
        invoker_did=invoker_did,
        target_info=target_info,
        actions=actions,
        controller_key=controller_private,
        caveats=caveats_req_param,
    )
    _add_cap_to_store(capability_store, cap_req_param)

    with pytest.raises(InvocationError):  # Missing parameter
        await invoke_capability(
            capability=cap_req_param,
            action_name="read",
            invoker_key=invoker_private,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )

    with pytest.raises(InvocationError):  # Wrong parameter value
        await invoke_capability(
            capability=cap_req_param,
            action_name="read",
            invoker_key=invoker_private,
            parameters={"mode": "insecure"},
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )

    correct_param_invocation = await invoke_capability(
        capability=cap_req_param,
        action_name="read",
        invoker_key=invoker_private,
        parameters={"mode": "secure"},
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert correct_param_invocation is not None
    assert correct_param_invocation["action"] == "read"
    assert correct_param_invocation["parameters"]["mode"] == "secure"


@pytest.mark.asyncio
async def test_valid_while_true_caveat(env_setup):
    """Test ValidWhileTrue caveat type."""
    (
        controller_private,
        controller_did,
        invoker_private,
        invoker_did,
        _,
        _,  # delegate_private, delegate_did
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
        target_info,
        actions,
    ) = env_setup
    condition_id = "urn:uuid:some-revocable-condition-id"
    caveats = [{"type": "ValidWhileTrue", "conditionId": condition_id}]

    cap_vwt = await create_capability(
        controller_did=controller_did,
        invoker_did=invoker_did,
        target_info=target_info,
        actions=actions,
        controller_key=controller_private,
        caveats=caveats,
    )
    _add_cap_to_store(capability_store, cap_vwt)

    try:  # Initially not revoked
        await verify_capability(
            cap_vwt, did_key_store, revoked_capabilities, capability_store
        )
    except CapabilityVerificationError as e:
        pytest.fail(f"VWT cap initial verification failed: {e}")

    invocation_before_revoke = await invoke_capability(
        capability=cap_vwt,
        action_name="read",
        invoker_key=invoker_private,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert invocation_before_revoke is not None

    revoked_capabilities.add(condition_id)

    with pytest.raises(CapabilityVerificationError):
        await verify_capability(
            cap_vwt, did_key_store, revoked_capabilities, capability_store
        )

    with pytest.raises(
        CapabilityVerificationError
    ):  # Invocation first verifies capability
        await invoke_capability(
            capability=cap_vwt,
            action_name="read",
            invoker_key=invoker_private,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )


@pytest.mark.asyncio
async def test_delegation_with_caveats(env_setup):
    """Test that caveats are enforced throughout delegation chain."""
    (
        controller_private,
        controller_did,
        invoker_private,
        invoker_did,
        delegate_private,
        delegate_did,
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
        target_info,
        actions,
    ) = env_setup

    root_cap = await create_capability(
        controller_did=controller_did,
        invoker_did=invoker_did,
        target_info=target_info,
        actions=actions,
        controller_key=controller_private,
    )
    _add_cap_to_store(capability_store, root_cap)

    future = datetime.utcnow() + timedelta(hours=1)
    delegation_caveats = [{"type": "ValidUntil", "date": future.isoformat()}]

    delegated_cap = await delegate_capability(
        parent_capability=root_cap,
        delegator_key=invoker_private,
        new_invoker_did=delegate_did,
        caveats=delegation_caveats,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
    )
    _add_cap_to_store(capability_store, delegated_cap)

    try:
        await verify_capability(
            delegated_cap, did_key_store, revoked_capabilities, capability_store
        )
    except CapabilityVerificationError as e:
        pytest.fail(f"Delegated cap verification failed: {e}")

    invocation_delegated = await invoke_capability(
        capability=delegated_cap,
        action_name="read",
        invoker_key=delegate_private,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert invocation_delegated is not None

    action_caveat = [{"type": "AllowedAction", "actions": ["read"]}]
    sub_delegated_cap = await delegate_capability(
        parent_capability=delegated_cap,
        delegator_key=delegate_private,  # Key of invoker of delegated_cap (delegate_did)
        new_invoker_did=controller_did,  # Delegate back to controller
        caveats=action_caveat,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
    )
    _add_cap_to_store(capability_store, sub_delegated_cap)

    try:
        await verify_capability(
            sub_delegated_cap, did_key_store, revoked_capabilities, capability_store
        )
    except CapabilityVerificationError as e:
        pytest.fail(f"Sub-delegated cap verification failed: {e}")

    read_invocation_sub = await invoke_capability(
        capability=sub_delegated_cap,
        action_name="read",
        invoker_key=controller_private,
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert read_invocation_sub is not None

    with pytest.raises(
        InvocationError
    ):  # write should fail due to AllowedAction caveat in chain
        await invoke_capability(
            capability=sub_delegated_cap,
            action_name="write",
            invoker_key=controller_private,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )
