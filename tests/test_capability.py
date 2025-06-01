"""
Test suite for the ZCAP-LD implementation.
"""

from datetime import datetime, timedelta

import pytest  # type: ignore
import pytest_asyncio  # Import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import ed25519

from zcap import (
    CapabilityVerificationError,
    DelegationError,
    InvocationError,
    InvocationVerificationError,
    create_capability,
    delegate_capability,
    invoke_capability,
    models,
    verify_capability,
    verify_invocation,
)


@pytest.fixture  # Changed to regular fixture
def test_keys_and_stores():  # Changed to regular def
    """Generate test keys for different actors and initialize stores."""
    keys = {
        "alice": ed25519.Ed25519PrivateKey.generate(),
        "bob": ed25519.Ed25519PrivateKey.generate(),
        "charlie": ed25519.Ed25519PrivateKey.generate(),
        "dave": ed25519.Ed25519PrivateKey.generate(),
    }

    did_key_store = {
        "did:example:alice": keys["alice"].public_key(),
        "did:example:bob": keys["bob"].public_key(),
        "did:example:charlie": keys["charlie"].public_key(),
        "did:example:dave": keys["dave"].public_key(),
    }

    capability_store = {}
    revoked_capabilities = set()
    used_invocation_nonces = set()
    nonce_timestamps = {}

    return (
        keys,
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
    )


@pytest_asyncio.fixture  # Changed to async fixture
async def root_capability_fixture(test_keys_and_stores):  # Changed to async def
    """Create a root capability for testing."""
    keys, _, capability_store, _, _, _ = test_keys_and_stores  # No await here

    cap = await create_capability(  # await async call
        controller_did="did:example:alice",
        invoker_did="did:example:bob",
        actions=[
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {"max_size": 1024}},
        ],
        target_info={"id": "https://example.com/documents/123", "type": "Document"},
        controller_key=keys["alice"],
        expires=datetime.utcnow() + timedelta(days=30),
    )
    capability_store[cap.id] = cap  # Add to store
    return cap


@pytest.mark.asyncio  # Mark as async test
async def test_create_capability(test_keys_and_stores):  # Changed to async def
    """Test capability creation."""
    keys, _, capability_store, _, _, _ = test_keys_and_stores  # No await here
    capability = await create_capability(  # await async call
        controller_did="did:example:alice",
        invoker_did="did:example:bob",
        actions=[{"name": "read"}],
        target_info={"id": "https://example.com/resource", "type": "Document"},
        controller_key=keys["alice"],
    )
    capability_store[capability.id] = capability

    assert isinstance(capability, models.Capability)
    assert capability.controller.id == "did:example:alice"
    assert capability.invoker.id == "did:example:bob"
    assert len(capability.actions) == 1
    assert capability.actions[0].name == "read"
    assert capability.proof is not None


@pytest.mark.asyncio
async def test_delegate_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability delegation."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = (
        test_keys_and_stores  # No await
    )
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    delegated = await delegate_capability(
        parent_capability=root_cap,
        delegator_key=keys["bob"],
        new_invoker_did="did:example:charlie",
        actions=[{"name": "read"}],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
    )
    capability_store[delegated.id] = delegated

    assert isinstance(delegated, models.Capability)
    assert delegated.controller.id == "did:example:bob"
    assert delegated.invoker.id == "did:example:charlie"
    assert len(delegated.actions) == 1
    assert delegated.actions[0].name == "read"
    assert delegated.parent_capability == root_cap.id
    assert delegated.proof is not None


@pytest.mark.asyncio
async def test_delegate_invalid_action(root_capability_fixture, test_keys_and_stores):
    """Test delegation with invalid action fails."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = (
        test_keys_and_stores  # No await
    )
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    with pytest.raises(DelegationError):
        await delegate_capability(
            parent_capability=root_cap,
            delegator_key=keys["bob"],
            new_invoker_did="did:example:charlie",
            actions=[{"name": "delete"}],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
        )


@pytest.mark.asyncio
async def test_invoke_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability invocation."""
    (
        keys,
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
    ) = test_keys_and_stores  # No await
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    invocation_doc = await invoke_capability(
        capability=root_cap,
        action_name="read",
        invoker_key=keys["bob"],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert invocation_doc is not None
    assert "@context" in invocation_doc
    assert "proof" in invocation_doc
    assert invocation_doc["proof"]["proofPurpose"] == "capabilityInvocation"
    assert invocation_doc["action"] == "read"
    assert invocation_doc["capability"] == root_cap.id


@pytest.mark.asyncio
async def test_invoke_invalid_action(root_capability_fixture, test_keys_and_stores):
    """Test invocation with invalid action fails."""
    (
        keys,
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
    ) = test_keys_and_stores  # No await
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    with pytest.raises(InvocationError):
        await invoke_capability(
            capability=root_cap,
            action_name="delete",
            invoker_key=keys["bob"],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )


@pytest.mark.asyncio
async def test_verify_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability verification."""
    _, did_key_store, capability_store, revoked_capabilities, _, _ = (
        test_keys_and_stores  # No await
    )
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    try:
        await verify_capability(  # await async call
            capability=root_cap,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
        )
    except CapabilityVerificationError as e:
        pytest.fail(f"Verification failed unexpectedly: {e}")


@pytest.mark.asyncio
async def test_verify_expired_capability(test_keys_and_stores):
    """Test verification of expired capability fails."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = (
        test_keys_and_stores  # No await
    )

    expired_cap = await create_capability(  # await async call
        controller_did="did:example:alice",
        invoker_did="did:example:bob",
        actions=[{"name": "read"}],
        target_info={"id": "https://example.com/resource", "type": "Document"},
        controller_key=keys["alice"],
        expires=datetime.utcnow() - timedelta(days=1),
    )
    capability_store[expired_cap.id] = expired_cap

    with pytest.raises(CapabilityVerificationError):
        await verify_capability(  # await async call
            capability=expired_cap,
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
        )


@pytest.mark.asyncio
async def test_invoke_revoked_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability revocation and invocation attempt."""
    (
        keys,
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
    ) = test_keys_and_stores  # No await
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    invocation_doc = await invoke_capability(  # await async call
        capability=root_cap,
        action_name="read",
        invoker_key=keys["bob"],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert invocation_doc is not None

    revoked_capabilities.add(root_cap.id)

    with pytest.raises(InvocationError):
        await invoke_capability(  # await async call
            capability=root_cap,
            action_name="read",
            invoker_key=keys["bob"],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps,
        )


@pytest.mark.asyncio
async def test_delegation_chain_revocation(
    root_capability_fixture, test_keys_and_stores
):
    """Test that revoking a parent capability affects delegated capabilities."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = (
        test_keys_and_stores  # No await
    )
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    delegated = await delegate_capability(  # await async call
        parent_capability=root_cap,
        delegator_key=keys["bob"],
        new_invoker_did="did:example:charlie",
        actions=[{"name": "read"}],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
    )
    capability_store[delegated.id] = delegated

    revoked_capabilities.add(root_cap.id)

    with pytest.raises(DelegationError):
        await delegate_capability(  # await async call
            parent_capability=delegated,
            delegator_key=keys["charlie"],
            new_invoker_did="did:example:dave",
            actions=[{"name": "read"}],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
        )


@pytest.mark.asyncio
async def test_capability_json_ld(root_capability_fixture):  # Changed to async def
    """Test JSON-LD serialization of capabilities."""
    root_cap = root_capability_fixture  # REMOVED await
    json_ld = root_cap.to_json_ld()

    assert "@context" in json_ld
    assert isinstance(json_ld["@context"], list)
    assert "id" in json_ld
    assert "controller" in json_ld
    assert "invoker" in json_ld
    assert "action" in json_ld
    assert "target" in json_ld
    assert "proof" in json_ld


@pytest.mark.asyncio
async def test_verify_invocation(root_capability_fixture, test_keys_and_stores):
    """Test verification of invocation objects."""
    (
        keys,
        did_key_store,
        capability_store,
        revoked_capabilities,
        used_invocation_nonces,
        nonce_timestamps,
    ) = test_keys_and_stores  # No await
    root_cap = root_capability_fixture  # REMOVED await
    if root_cap.id not in capability_store:
        capability_store[root_cap.id] = root_cap

    invocation_doc = await invoke_capability(  # await async call
        capability=root_cap,
        action_name="read",
        invoker_key=keys["bob"],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps,
    )
    assert invocation_doc is not None

    try:
        await verify_invocation(  # await async call
            invocation_doc=invocation_doc,
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,
            capability_store=capability_store,
        )
    except InvocationVerificationError as e:
        pytest.fail(f"Valid invocation verification failed: {e}")

    tampered_invocation = invocation_doc.copy()
    tampered_invocation["action"] = "write"
    with pytest.raises(InvocationVerificationError):
        await verify_invocation(  # await async call
            invocation_doc=tampered_invocation,
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,
            capability_store=capability_store,
        )

    no_proof_invocation = invocation_doc.copy()
    del no_proof_invocation["proof"]
    with pytest.raises(InvocationVerificationError):
        await verify_invocation(  # await async call
            invocation_doc=no_proof_invocation,
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,
            capability_store=capability_store,
        )

    try:
        await verify_invocation(  # await async call
            invocation_doc=invocation_doc,
            did_key_store=did_key_store,
            revoked_capabilities=revoked_capabilities,
            capability_store=capability_store,
        )
    except InvocationVerificationError as e:
        pytest.fail(f"Invocation verification with capability lookup failed: {e}")
