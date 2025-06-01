"""
Test suite for the ZCAP-LD implementation.
"""

import pytest
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    verify_invocation,
    CapabilityVerificationError,
    DelegationError,
    InvocationError,
    InvocationVerificationError,
    models,
)


@pytest.fixture
def test_keys_and_stores():
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

    return keys, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps


@pytest.fixture
def root_capability_fixture(test_keys_and_stores):
    """Create a root capability for testing."""
    keys, did_key_store, capability_store, _, _, _ = test_keys_and_stores
    
    cap = create_capability(
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
    capability_store[cap.id] = cap # Add to store
    return cap


def test_create_capability(test_keys_and_stores):
    """Test capability creation."""
    keys, did_key_store, capability_store, _, _, _ = test_keys_and_stores
    capability = create_capability(
        controller_did="did:example:alice",
        invoker_did="did:example:bob",
        actions=[{"name": "read"}],
        target_info={"id": "https://example.com/resource", "type": "Document"},
        controller_key=keys["alice"],
    )
    capability_store[capability.id] = capability # Add to store for completeness, though not strictly needed for this test

    assert isinstance(capability, models.Capability)
    assert capability.controller.id == "did:example:alice"
    assert capability.invoker.id == "did:example:bob"
    assert len(capability.actions) == 1
    assert capability.actions[0].name == "read"
    assert capability.proof is not None


def test_delegate_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability delegation."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = test_keys_and_stores
    # Ensure root_capability_fixture is in capability_store if not already by its fixture def
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture
        
    delegated = delegate_capability(
        parent_capability=root_capability_fixture,
        delegator_key=keys["bob"], # Bob is invoker of root, so he delegates
        new_invoker_did="did:example:charlie",
        actions=[{"name": "read"}],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities
    )
    capability_store[delegated.id] = delegated # Add to store

    assert isinstance(delegated, models.Capability)
    assert delegated.controller.id == "did:example:bob" # Controller of delegated is invoker of parent
    assert delegated.invoker.id == "did:example:charlie"
    assert len(delegated.actions) == 1
    assert delegated.actions[0].name == "read"
    assert delegated.parent_capability == root_capability_fixture.id
    assert delegated.proof is not None


def test_delegate_invalid_action(root_capability_fixture, test_keys_and_stores):
    """Test delegation with invalid action fails."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = test_keys_and_stores
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture
        
    with pytest.raises(DelegationError): # Changed from ValueError
        delegate_capability(
            parent_capability=root_capability_fixture,
            delegator_key=keys["bob"],
            new_invoker_did="did:example:charlie",
            actions=[{"name": "delete"}],  # Action not in parent capability
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities
        )


def test_invoke_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability invocation."""
    keys, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps = test_keys_and_stores
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture

    invocation_doc = invoke_capability(
        capability=root_capability_fixture, 
        action_name="read", # Changed from action
        invoker_key=keys["bob"],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps
    )
    assert invocation_doc is not None
    assert "@context" in invocation_doc
    assert "proof" in invocation_doc
    assert invocation_doc["proof"]["proofPurpose"] == "capabilityInvocation"
    assert invocation_doc["action"] == "read"
    assert invocation_doc["capability"] == root_capability_fixture.id


def test_invoke_invalid_action(root_capability_fixture, test_keys_and_stores):
    """Test invocation with invalid action fails."""
    keys, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps = test_keys_and_stores
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture

    with pytest.raises(InvocationError): # Changed from assert result is None
        invoke_capability(
            capability=root_capability_fixture,
            action_name="delete",  # Action not in capability, changed from action
            invoker_key=keys["bob"],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps
        )


def test_verify_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability verification."""
    _, did_key_store, capability_store, revoked_capabilities, _, _ = test_keys_and_stores
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture
    
    try:
        verify_capability(
            capability=root_capability_fixture, 
            did_key_store=did_key_store, 
            capability_store=capability_store, 
            revoked_capabilities=revoked_capabilities
        )
    except CapabilityVerificationError as e:
        pytest.fail(f"Verification failed unexpectedly: {e}")


def test_verify_expired_capability(test_keys_and_stores):
    """Test verification of expired capability fails."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = test_keys_and_stores
    
    expired_cap = create_capability(
        controller_did="did:example:alice",
        invoker_did="did:example:bob",
        actions=[{"name": "read"}],
        target_info={"id": "https://example.com/resource", "type": "Document"},
        controller_key=keys["alice"],
        expires=datetime.utcnow() - timedelta(days=1),  # Expired
    )
    capability_store[expired_cap.id] = expired_cap

    with pytest.raises(CapabilityVerificationError): # Changed from assert is False
        verify_capability(
            capability=expired_cap, 
            did_key_store=did_key_store, 
            capability_store=capability_store, 
            revoked_capabilities=revoked_capabilities
        )


def test_invoke_revoked_capability(root_capability_fixture, test_keys_and_stores):
    """Test capability revocation and invocation attempt."""
    keys, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps = test_keys_and_stores
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture

    # First invocation should succeed
    invocation_doc = invoke_capability(
        capability=root_capability_fixture, 
        action_name="read", 
        invoker_key=keys["bob"],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps
    )
    assert invocation_doc is not None # Basic check for successful invocation

    # Revoke the capability by adding its ID to the client-managed set
    revoked_capabilities.add(root_capability_fixture.id)

    # Second invocation should fail
    with pytest.raises(InvocationError): # Changed from assert result is None
        invoke_capability(
            capability=root_capability_fixture, 
            action_name="read", 
            invoker_key=keys["bob"],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities,
            used_invocation_nonces=used_invocation_nonces,
            nonce_timestamps=nonce_timestamps
        )


def test_delegation_chain_revocation(root_capability_fixture, test_keys_and_stores):
    """Test that revoking a parent capability affects delegated capabilities."""
    keys, did_key_store, capability_store, revoked_capabilities, _, _ = test_keys_and_stores
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture

    # Create a delegation chain
    delegated = delegate_capability(
        parent_capability=root_capability_fixture,
        delegator_key=keys["bob"],
        new_invoker_did="did:example:charlie",
        actions=[{"name": "read"}],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities
    )
    capability_store[delegated.id] = delegated

    # Revoke the root capability
    revoked_capabilities.add(root_capability_fixture.id)

    # Attempt to create further delegation should fail because parent is revoked
    with pytest.raises(DelegationError): # Changed from ValueError
        delegate_capability(
            parent_capability=delegated, # This delegated capability's parent is now revoked
            delegator_key=keys["charlie"],
            new_invoker_did="did:example:dave",
            actions=[{"name": "read"}],
            did_key_store=did_key_store,
            capability_store=capability_store,
            revoked_capabilities=revoked_capabilities
        )


def test_capability_json_ld(root_capability_fixture):
    """Test JSON-LD serialization of capabilities."""
    json_ld = root_capability_fixture.to_json_ld()

    assert "@context" in json_ld
    assert isinstance(json_ld["@context"], list)
    # The Capability model now adds its own type if not present
    # assert json_ld["type"] == "zcap" # This might need adjustment based on model
    assert "id" in json_ld # id is part of the model
    assert "controller" in json_ld
    assert "invoker" in json_ld
    # The model uses "actions" not "action"
    assert "action" in json_ld # Corrected from actions to action, to match model.to_json_ld()
    assert "target" in json_ld
    assert "proof" in json_ld


def test_verify_invocation(root_capability_fixture, test_keys_and_stores):
    """Test verification of invocation objects."""
    keys, did_key_store, capability_store, revoked_capabilities, used_invocation_nonces, nonce_timestamps = test_keys_and_stores
    if root_capability_fixture.id not in capability_store:
        capability_store[root_capability_fixture.id] = root_capability_fixture

    # Create an invocation
    invocation_doc = invoke_capability(
        capability=root_capability_fixture, 
        action_name="read", 
        invoker_key=keys["bob"],
        did_key_store=did_key_store,
        capability_store=capability_store,
        revoked_capabilities=revoked_capabilities,
        used_invocation_nonces=used_invocation_nonces,
        nonce_timestamps=nonce_timestamps
    )
    assert invocation_doc is not None

    # Verify the invocation - should not raise error
    try:
        verify_invocation(
            invocation_doc=invocation_doc, 
            did_key_store=did_key_store, 
            revoked_capabilities=revoked_capabilities, 
            capability_store=capability_store
        )
    except InvocationVerificationError as e:
        pytest.fail(f"Valid invocation verification failed: {e}")

    # Test with invalid invocation (tampered action in main body, proof signedAction is the check)
    tampered_invocation = invocation_doc.copy()
    tampered_invocation["action"] = "write"  # Changed from "read"
    # Proof still contains "signedAction": "read" which verify_invocation checks against invocation_doc["action"]
    with pytest.raises(InvocationVerificationError):
        verify_invocation(
            invocation_doc=tampered_invocation, 
            did_key_store=did_key_store, 
            revoked_capabilities=revoked_capabilities, 
            capability_store=capability_store
        )

    # Test with invalid invocation (missing proof)
    no_proof_invocation = invocation_doc.copy()
    del no_proof_invocation["proof"]
    with pytest.raises(InvocationVerificationError):
        verify_invocation(
            invocation_doc=no_proof_invocation, 
            did_key_store=did_key_store, 
            revoked_capabilities=revoked_capabilities, 
            capability_store=capability_store
        )

    # Test with capability lookup by ID (verify_invocation uses capability_store)
    # This part implicitly tests if verify_invocation can find the capability in the store
    try:
        verify_invocation(
            invocation_doc=invocation_doc, 
            did_key_store=did_key_store, 
            revoked_capabilities=revoked_capabilities, 
            capability_store=capability_store # capability_store must contain the target_capability
        )
    except InvocationVerificationError as e:
        pytest.fail(f"Invocation verification with capability lookup failed: {e}")
