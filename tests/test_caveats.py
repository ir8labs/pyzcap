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
    CapabilityVerificationError,
    InvocationError,
)
from zcap.models import Capability


class CaveatEnforcementTests(unittest.TestCase):
    """Test cases for ZCAP-LD caveat enforcement."""

    def setUp(self):
        """Set up test keys and identities and client-managed stores."""
        self.controller_private = ed25519.Ed25519PrivateKey.generate()
        self.controller_public = self.controller_private.public_key()
        self.controller_did = "did:key:controller"

        self.invoker_private = ed25519.Ed25519PrivateKey.generate()
        self.invoker_public = self.invoker_private.public_key()
        self.invoker_did = "did:key:invoker"

        self.delegate_private = ed25519.Ed25519PrivateKey.generate()
        self.delegate_public = self.delegate_private.public_key()
        self.delegate_did = "did:key:delegate"

        # Client-managed stores
        self.did_key_store = {
            self.controller_did: self.controller_public,
            self.invoker_did: self.invoker_public,
            self.delegate_did: self.delegate_public,
        }
        self.capability_store = {}
        self.revoked_capabilities = set()
        self.used_invocation_nonces = set()
        self.nonce_timestamps = {}
        # For ValidWhileTrue, we might need a separate set if conditionId isn't a capability ID
        # For this test, we'll assume condition_id can be added to revoked_capabilities.

        self.target_info = {
            "id": "https://example.com/resource/1",
            "type": "ExampleResource",
        }
        self.actions = [
            {"name": "read", "parameters": {}},
            {"name": "write", "parameters": {}},
        ]

    def _add_cap_to_store(self, cap: Capability):
        self.capability_store[cap.id] = cap

    def test_time_based_caveats(self):
        """Test time-based caveats (ValidUntil, ValidAfter)."""
        # Capability that is valid for 1 hour
        future = datetime.utcnow() + timedelta(hours=1)
        caveats1 = [{"type": "ValidUntil", "date": future.isoformat()}]

        cap1 = create_capability(
            controller_did=self.controller_did,
            invoker_did=self.invoker_did,
            target_info=self.target_info,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats1,
        )
        self._add_cap_to_store(cap1)

        # Should verify and invoke successfully
        try:
            verify_capability(cap1, self.did_key_store, self.revoked_capabilities, self.capability_store)
        except CapabilityVerificationError as e:
            self.fail(f"Valid capability verification failed: {e}")
        
        invocation1 = invoke_capability(
            capability=cap1, action_name="read", invoker_key=self.invoker_private,
            did_key_store=self.did_key_store, capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities,
            used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
        )
        self.assertIsNotNone(invocation1)

        # Capability that is valid starting tomorrow
        tomorrow = datetime.utcnow() + timedelta(days=1)
        caveats2 = [{"type": "ValidAfter", "date": tomorrow.isoformat()}]

        cap2 = create_capability(
            controller_did=self.controller_did,
            invoker_did=self.invoker_did,
            target_info=self.target_info,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats2,
        )
        self._add_cap_to_store(cap2)

        # Should fail verification and invocation
        with self.assertRaises(CapabilityVerificationError):
            verify_capability(cap2, self.did_key_store, self.revoked_capabilities, self.capability_store)
        
        with self.assertRaises(CapabilityVerificationError):
            invoke_capability(
                capability=cap2, action_name="read", invoker_key=self.invoker_private,
                did_key_store=self.did_key_store, capability_store=self.capability_store,
                revoked_capabilities=self.revoked_capabilities,
                used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
            )

    def test_action_specific_caveats(self):
        """Test action-specific caveats."""
        caveats_allowed_action = [{"type": "AllowedAction", "actions": ["read"]}]

        cap_allowed = create_capability(
            controller_did=self.controller_did,
            invoker_did=self.invoker_did,
            target_info=self.target_info,
            actions=self.actions, # Main capability allows read and write
            controller_key=self.controller_private,
            caveats=caveats_allowed_action,
        )
        self._add_cap_to_store(cap_allowed)

        try:
            verify_capability(cap_allowed, self.did_key_store, self.revoked_capabilities, self.capability_store)
        except CapabilityVerificationError as e:
            self.fail(f"AllowedAction cap verification failed: {e}")

        read_invocation = invoke_capability(
            capability=cap_allowed, action_name="read", invoker_key=self.invoker_private,
            did_key_store=self.did_key_store, capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities,
            used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
        )
        self.assertIsNotNone(read_invocation)
        self.assertEqual(read_invocation["action"], "read")

        with self.assertRaises(InvocationError): # Caveat restricts to 'read'
            invoke_capability(
                capability=cap_allowed, action_name="write", invoker_key=self.invoker_private,
                did_key_store=self.did_key_store, capability_store=self.capability_store,
                revoked_capabilities=self.revoked_capabilities,
                used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
            )

        caveats_req_param = [{"type": "RequireParameter", "parameter": "mode", "value": "secure"}]
        cap_req_param = create_capability(
            controller_did=self.controller_did,
            invoker_did=self.invoker_did,
            target_info=self.target_info,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats_req_param,
        )
        self._add_cap_to_store(cap_req_param)

        with self.assertRaises(InvocationError): # Missing parameter
            invoke_capability(
                capability=cap_req_param, action_name="read", invoker_key=self.invoker_private,
                did_key_store=self.did_key_store, capability_store=self.capability_store,
                revoked_capabilities=self.revoked_capabilities,
                used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
            )
        
        with self.assertRaises(InvocationError): # Wrong parameter value
            invoke_capability(
                capability=cap_req_param, action_name="read", invoker_key=self.invoker_private, 
                parameters={"mode": "insecure"},
                did_key_store=self.did_key_store, capability_store=self.capability_store,
                revoked_capabilities=self.revoked_capabilities,
                used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
            )

        correct_param_invocation = invoke_capability(
            capability=cap_req_param, action_name="read", invoker_key=self.invoker_private, 
            parameters={"mode": "secure"},
            did_key_store=self.did_key_store, capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities,
            used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
        )
        self.assertIsNotNone(correct_param_invocation)
        self.assertEqual(correct_param_invocation["action"], "read")
        self.assertEqual(correct_param_invocation["parameters"]["mode"], "secure")

    def test_valid_while_true_caveat(self):
        """Test ValidWhileTrue caveat type."""
        condition_id = "urn:uuid:some-revocable-condition-id" # Treat as a capability ID for this test
        caveats = [{"type": "ValidWhileTrue", "conditionId": condition_id}]

        cap_vwt = create_capability(
            controller_did=self.controller_did,
            invoker_did=self.invoker_did,
            target_info=self.target_info,
            actions=self.actions,
            controller_key=self.controller_private,
            caveats=caveats,
        )
        self._add_cap_to_store(cap_vwt)

        try: # Initially not revoked
            verify_capability(cap_vwt, self.did_key_store, self.revoked_capabilities, self.capability_store)
        except CapabilityVerificationError as e:
            self.fail(f"VWT cap initial verification failed: {e}")
        
        invocation_before_revoke = invoke_capability(
            capability=cap_vwt, action_name="read", invoker_key=self.invoker_private,
            did_key_store=self.did_key_store, capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities, # initially empty or condition_id not in it
            used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
        )
        self.assertIsNotNone(invocation_before_revoke)

        # "Revoke" the condition by adding its ID to the set of revoked IDs
        self.revoked_capabilities.add(condition_id)

        with self.assertRaises(CapabilityVerificationError): # Should fail verification because condition_id is revoked
            verify_capability(cap_vwt, self.did_key_store, self.revoked_capabilities, self.capability_store)
        
        with self.assertRaises(CapabilityVerificationError): # Changed from InvocationError
            invoke_capability(
                capability=cap_vwt, action_name="read", invoker_key=self.invoker_private,
                did_key_store=self.did_key_store, capability_store=self.capability_store,
                revoked_capabilities=self.revoked_capabilities, # now contains condition_id
                used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
            )

    def test_delegation_with_caveats(self):
        """Test that caveats are enforced throughout delegation chain."""
        root_cap = create_capability(
            controller_did=self.controller_did,
            invoker_did=self.invoker_did,
            target_info=self.target_info,
            actions=self.actions,
            controller_key=self.controller_private,
        )
        self._add_cap_to_store(root_cap)

        future = datetime.utcnow() + timedelta(hours=1)
        delegation_caveats = [{"type": "ValidUntil", "date": future.isoformat()}]

        delegated_cap = delegate_capability(
            parent_capability=root_cap,
            delegator_key=self.invoker_private,
            new_invoker_did=self.delegate_did,
            caveats=delegation_caveats,
            did_key_store=self.did_key_store,
            capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities
        )
        self._add_cap_to_store(delegated_cap)

        try:
            verify_capability(delegated_cap, self.did_key_store, self.revoked_capabilities, self.capability_store)
        except CapabilityVerificationError as e:
            self.fail(f"Delegated cap verification failed: {e}")

        invocation_delegated = invoke_capability(
            capability=delegated_cap, action_name="read", invoker_key=self.delegate_private,
            did_key_store=self.did_key_store, capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities,
            used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
        )
        self.assertIsNotNone(invocation_delegated)

        action_caveat = [{"type": "AllowedAction", "actions": ["read"]}]
        sub_delegated_cap = delegate_capability(
            parent_capability=delegated_cap,
            delegator_key=self.delegate_private,
            new_invoker_did=self.controller_did,  # Delegate back to controller
            caveats=action_caveat,
            did_key_store=self.did_key_store,
            capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities
        )
        self._add_cap_to_store(sub_delegated_cap)

        try:
            verify_capability(sub_delegated_cap, self.did_key_store, self.revoked_capabilities, self.capability_store)
        except CapabilityVerificationError as e:
            self.fail(f"Sub-delegated cap verification failed: {e}")

        read_invocation_sub = invoke_capability(
            capability=sub_delegated_cap, action_name="read", invoker_key=self.controller_private,
            did_key_store=self.did_key_store, capability_store=self.capability_store,
            revoked_capabilities=self.revoked_capabilities,
            used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
        )
        self.assertIsNotNone(read_invocation_sub)

        with self.assertRaises(InvocationError): # write should fail due to AllowedAction caveat in chain
            invoke_capability(
                capability=sub_delegated_cap, action_name="write", invoker_key=self.controller_private,
                did_key_store=self.did_key_store, capability_store=self.capability_store,
                revoked_capabilities=self.revoked_capabilities,
                used_invocation_nonces=self.used_invocation_nonces, nonce_timestamps=self.nonce_timestamps
            )


if __name__ == "__main__":
    unittest.main()
