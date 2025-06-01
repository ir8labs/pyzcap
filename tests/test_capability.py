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
    revoke_capability,
    register_public_key,
    models,
    verify_invocation,
)


@pytest.fixture
def test_keys():
    """Generate test keys for different actors."""
    keys = {
        "alice": ed25519.Ed25519PrivateKey.generate(),
        "bob": ed25519.Ed25519PrivateKey.generate(),
        "charlie": ed25519.Ed25519PrivateKey.generate(),
    }

    # Register public keys for DIDs
    register_public_key("did:example:alice", keys["alice"].public_key())
    register_public_key("did:example:bob", keys["bob"].public_key())
    register_public_key("did:example:charlie", keys["charlie"].public_key())

    return keys


@pytest.fixture
def root_capability(test_keys):
    """Create a root capability for testing."""
    return create_capability(
        controller="did:example:alice",
        invoker="did:example:bob",
        actions=[
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {"max_size": 1024}},
        ],
        target={"id": "https://example.com/documents/123", "type": "Document"},
        controller_key=test_keys["alice"],
        expires=datetime.utcnow() + timedelta(days=30),
    )


def test_create_capability(test_keys):
    """Test capability creation."""
    capability = create_capability(
        controller="did:example:alice",
        invoker="did:example:bob",
        actions=[{"name": "read"}],
        target={"id": "https://example.com/resource", "type": "Document"},
        controller_key=test_keys["alice"],
    )

    assert isinstance(capability, models.Capability)
    assert capability.controller.id == "did:example:alice"
    assert capability.invoker.id == "did:example:bob"
    assert len(capability.actions) == 1
    assert capability.actions[0].name == "read"
    assert capability.proof is not None


def test_delegate_capability(root_capability, test_keys):
    """Test capability delegation."""
    delegated = delegate_capability(
        parent_capability=root_capability,
        delegator_key=test_keys["bob"],
        new_invoker="did:example:charlie",
        actions=[{"name": "read"}],
    )

    assert isinstance(delegated, models.Capability)
    assert delegated.controller.id == "did:example:bob"
    assert delegated.invoker.id == "did:example:charlie"
    assert len(delegated.actions) == 1
    assert delegated.actions[0].name == "read"
    assert delegated.parent_capability == root_capability.id
    assert delegated.proof is not None


def test_delegate_invalid_action(root_capability, test_keys):
    """Test delegation with invalid action fails."""
    with pytest.raises(ValueError):
        delegate_capability(
            parent_capability=root_capability,
            delegator_key=test_keys["bob"],
            new_invoker="did:example:charlie",
            actions=[{"name": "delete"}],  # Action not in parent capability
        )


def test_invoke_capability(root_capability, test_keys):
    """Test capability invocation."""
    result = invoke_capability(
        capability=root_capability, action="read", invoker_key=test_keys["bob"]
    )
    assert result is not None
    assert "@context" in result
    assert "proof" in result
    assert result["proof"]["proofPurpose"] == "capabilityInvocation"
    assert result["action"] == "read"
    assert result["capability"] == root_capability.id


def test_invoke_invalid_action(root_capability, test_keys):
    """Test invocation with invalid action fails."""
    result = invoke_capability(
        capability=root_capability,
        action="delete",  # Action not in capability
        invoker_key=test_keys["bob"],
    )
    assert result is None


def test_verify_capability(root_capability):
    """Test capability verification."""
    assert verify_capability(root_capability) is True


def test_verify_expired_capability(test_keys):
    """Test verification of expired capability fails."""
    capability = create_capability(
        controller="did:example:alice",
        invoker="did:example:bob",
        actions=[{"name": "read"}],
        target={"id": "https://example.com/resource", "type": "Document"},
        controller_key=test_keys["alice"],
        expires=datetime.utcnow() - timedelta(days=1),  # Expired
    )
    assert verify_capability(capability) is False


def test_revoke_capability(root_capability, test_keys):
    """Test capability revocation."""
    # First invocation should succeed
    first_invocation = invoke_capability(
        capability=root_capability, action="read", invoker_key=test_keys["bob"]
    )
    assert first_invocation is not None

    # Revoke the capability
    revoke_capability(root_capability.id)

    # Second invocation should fail
    second_invocation = invoke_capability(
        capability=root_capability, action="read", invoker_key=test_keys["bob"]
    )
    assert second_invocation is None


def test_delegation_chain_revocation(root_capability, test_keys):
    """Test that revoking a parent capability affects delegated capabilities."""
    # Create a delegation chain
    delegated = delegate_capability(
        parent_capability=root_capability,
        delegator_key=test_keys["bob"],
        new_invoker="did:example:charlie",
        actions=[{"name": "read"}],
    )

    # Revoke the root capability
    revoke_capability(root_capability.id)

    # Attempt to create further delegation should fail
    with pytest.raises(ValueError):
        delegate_capability(
            parent_capability=delegated,
            delegator_key=test_keys["charlie"],
            new_invoker="did:example:dave",
            actions=[{"name": "read"}],
        )


def test_capability_json_ld(root_capability):
    """Test JSON-LD serialization of capabilities."""
    json_ld = root_capability.to_json_ld()

    assert "@context" in json_ld
    assert isinstance(json_ld["@context"], list)
    assert json_ld["type"] == "zcap"
    assert "controller" in json_ld
    assert "invoker" in json_ld
    assert "action" in json_ld
    assert "target" in json_ld
    assert "proof" in json_ld


def test_verify_invocation(root_capability, test_keys):
    """Test verification of invocation objects."""
    # Create an invocation
    invocation = invoke_capability(
        capability=root_capability, action="read", invoker_key=test_keys["bob"]
    )

    # Verify the invocation
    assert invocation is not None
    assert verify_invocation(invocation, root_capability) is True

    # Test with invalid invocation (tampered action)
    tampered_invocation = invocation.copy()
    tampered_invocation["action"] = "write"  # Changed from "read"
    assert verify_invocation(tampered_invocation, root_capability) is False

    # Test with invalid invocation (missing proof)
    no_proof_invocation = invocation.copy()
    del no_proof_invocation["proof"]
    assert verify_invocation(no_proof_invocation, root_capability) is False

    # Test with capability lookup by ID
    assert verify_invocation(invocation) is True
