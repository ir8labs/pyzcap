"""
Test cases for ZCAP-LD caveat enforcement.
"""

import unittest
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from zcap.capability import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    register_public_key,
    revoke_capability,
)


class CaveatEnforcementTests(unittest.TestCase):
    """Test cases for ZCAP-LD caveat enforcement."""

    def setUp(self):
        """Set up test keys and identities."""
        # Generate test keys
        self.controller_private = ed25519.Ed25519PrivateKey.generate()
        self.controller_public = self.controller_private.public_key()
        self.controller_did = "did:key:controller"

        self.invoker_private = ed25519.Ed25519PrivateKey.generate()
        self.invoker_public = self.invoker_private.public_key()
        self.invoker_did = "did:key:invoker"

        self.delegate_private = ed25519.Ed25519PrivateKey.generate()
        self.delegate_public = self.delegate_private.public_key()
        self.delegate_did = "did:key:delegate"

        # Register keys
        register_public_key(self.controller_did, self.controller_public)
        register_public_key(self.invoker_did, self.invoker_public)
        register_public_key(self.delegate_did, self.delegate_public)

        # Basic target and actions
        self.target = {
            "id": "https://example.com/resource/1",
            "type": "ExampleResource",
        }
        self.actions = [
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {}},
        ]

    def test_time_based_caveats(self):
        """Test time-based caveats (ValidUntil, ValidAfter)."""
        # Capability that is valid for 1 hour
        future = datetime.utcnow() + timedelta(hours=1)
        caveats = [{"type": "ValidUntil", "date": future.isoformat()}]

        cap = create_capability(
            controller=self.controller_did,
            invoker=self.invoker_did,
            target=self.target,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats,
        )

        # Should verify and invoke successfully
        self.assertTrue(verify_capability(cap))
        invocation = invoke_capability(cap, "read", self.invoker_private)
        self.assertIsNotNone(invocation)

        # Capability that is valid starting tomorrow
        tomorrow = datetime.utcnow() + timedelta(days=1)
        caveats = [{"type": "ValidAfter", "date": tomorrow.isoformat()}]

        cap = create_capability(
            controller=self.controller_did,
            invoker=self.invoker_did,
            target=self.target,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats,
        )

        # Should fail verification and invocation
        self.assertFalse(verify_capability(cap))
        invocation = invoke_capability(cap, "read", self.invoker_private)
        self.assertIsNone(invocation)

    def test_action_specific_caveats(self):
        """Test action-specific caveats."""
        # Capability with allowed actions caveat
        caveats = [{"type": "AllowedAction", "actions": ["read"]}]

        cap = create_capability(
            controller=self.controller_did,
            invoker=self.invoker_did,
            target=self.target,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats,
        )

        # Should verify successfully
        self.assertTrue(verify_capability(cap))

        # Should invoke successfully for "read" action
        read_invocation = invoke_capability(cap, "read", self.invoker_private)
        self.assertIsNotNone(read_invocation)
        self.assertEqual(read_invocation["action"], "read")

        # Should fail invocation for "write" action
        write_invocation = invoke_capability(cap, "write", self.invoker_private)
        self.assertIsNone(write_invocation)

        # Capability with required parameter caveat
        caveats = [{"type": "RequireParameter", "parameter": "mode", "value": "secure"}]

        cap = create_capability(
            controller=self.controller_did,
            invoker=self.invoker_did,
            target=self.target,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats,
        )

        # Should fail invocation with missing parameter
        missing_param_invocation = invoke_capability(cap, "read", self.invoker_private)
        self.assertIsNone(missing_param_invocation)

        # Should fail invocation with wrong parameter value
        wrong_param_invocation = invoke_capability(
            cap, "read", self.invoker_private, {"mode": "insecure"}
        )
        self.assertIsNone(wrong_param_invocation)

        # Should succeed with correct parameter value
        correct_param_invocation = invoke_capability(
            cap, "read", self.invoker_private, {"mode": "secure"}
        )
        self.assertIsNotNone(correct_param_invocation)
        self.assertEqual(correct_param_invocation["action"], "read")
        self.assertEqual(correct_param_invocation["parameters"]["mode"], "secure")

    def test_valid_while_true_caveat(self):
        """Test ValidWhileTrue caveat type."""
        # Capability with ValidWhileTrue caveat
        condition_id = "condition:example:12345"
        caveats = [{"type": "ValidWhileTrue", "conditionId": condition_id}]

        cap = create_capability(
            controller=self.controller_did,
            invoker=self.invoker_did,
            target=self.target,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats,
        )

        # Should verify and invoke successfully initially
        self.assertTrue(verify_capability(cap))
        invocation = invoke_capability(cap, "read", self.invoker_private)
        self.assertIsNotNone(invocation)

        # Revoke the condition
        revoke_capability(condition_id)

        # Should now fail verification and invocation
        self.assertFalse(verify_capability(cap))
        invocation = invoke_capability(cap, "read", self.invoker_private)
        self.assertIsNone(invocation)

    def test_delegation_with_caveats(self):
        """Test that caveats are enforced throughout delegation chain."""
        # Create root capability with no caveats
        root_cap = create_capability(
            controller=self.controller_did,
            invoker=self.invoker_did,
            target=self.target,
            actions=self.actions,
            controller_key=self.controller_private,
        )

        # Delegate with a time constraint caveat
        future = datetime.utcnow() + timedelta(hours=1)
        delegation_caveats = [{"type": "ValidUntil", "date": future.isoformat()}]

        delegated_cap = delegate_capability(
            parent_capability=root_cap,
            delegator_key=self.invoker_private,
            new_invoker=self.delegate_did,
            caveats=delegation_caveats,
        )

        # Should verify and invoke successfully
        self.assertTrue(verify_capability(delegated_cap))
        invocation = invoke_capability(delegated_cap, "read", self.delegate_private)
        self.assertIsNotNone(invocation)

        # Add additional caveats in another delegation
        action_caveat = [{"type": "AllowedAction", "actions": ["read"]}]

        sub_delegated_cap = delegate_capability(
            parent_capability=delegated_cap,
            delegator_key=self.delegate_private,
            new_invoker=self.controller_did,  # Delegate back to controller for simplicity
            caveats=action_caveat,
        )

        # Should verify and invoke successfully for read
        self.assertTrue(verify_capability(sub_delegated_cap))
        read_invocation = invoke_capability(
            sub_delegated_cap, "read", self.controller_private
        )
        self.assertIsNotNone(read_invocation)

        # Should fail for write due to caveat in the chain
        write_invocation = invoke_capability(
            sub_delegated_cap, "write", self.controller_private
        )
        self.assertIsNone(write_invocation)


if __name__ == "__main__":
    unittest.main()
