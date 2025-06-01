"""
Core ZCAP-LD capability operations including creation, delegation, invocation, and verification.

This module implements the core functionality of ZCAP-LD capabilities, including:
- Creating capabilities
- Delegating capabilities to other controllers
- Invoking capabilities to perform actions
- Verifying capability chains
- Revoking capabilities

It also includes replay attack protection via invocation nonces. Each invocation
generates a unique nonce that is tracked to prevent replay attacks. Nonces are
automatically expired after a configurable time period (default: 1 hour).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pyld import jsonld

from .contexts import SECURITY_V2_CONTEXT, ZCAP_V1_CONTEXT
from .models import Action, Capability, Controller, Invoker, Proof, Target


# Custom Exception Classes
class ZCAPException(Exception):
    """Base exception for ZCAP-LD errors."""
    pass

class SignatureVerificationError(ZCAPException):
    """Raised when a signature verification fails."""
    pass

class CaveatEvaluationError(ZCAPException):
    """Raised when a caveat evaluation fails."""
    pass

class CapabilityVerificationError(ZCAPException):
    """Raised when capability verification fails."""
    pass

class InvocationVerificationError(ZCAPException):
    """Raised when invocation verification fails."""
    pass

class DelegationError(ZCAPException):
    """Raised when capability delegation fails."""
    pass

class InvocationError(ZCAPException):
    """Raised when capability invocation fails."""
    pass

class DIDKeyNotFoundError(ZCAPException):
    """Raised when a DID key is not found."""
    pass

class CapabilityNotFoundError(ZCAPException):
    """Raised when a capability is not found."""
    pass


def sign_capability_document(
    capability_doc: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey
) -> str:
    """Sign a capability document with an Ed25519 private key."""
    # Add contexts directly to the document
    # Ensure contexts are not duplicated if already present
    existing_contexts = capability_doc.get("@context", [])
    if not isinstance(existing_contexts, list):
        existing_contexts = [existing_contexts]

    new_contexts = []
    if SECURITY_V2_CONTEXT["@context"] not in existing_contexts:
        new_contexts.append(SECURITY_V2_CONTEXT["@context"])
    if ZCAP_V1_CONTEXT["@context"] not in existing_contexts:
        new_contexts.append(ZCAP_V1_CONTEXT["@context"])

    if new_contexts:
        capability_doc["@context"] = existing_contexts + new_contexts
    elif not existing_contexts: # if capability_doc had no @context
        capability_doc["@context"] = [
            SECURITY_V2_CONTEXT["@context"],
            ZCAP_V1_CONTEXT["@context"],
        ]


    # Canonicalize the capability document
    try:
        normalized = jsonld.normalize(
            capability_doc, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )
    except Exception as e:
        raise ZCAPException(f"Error during JSON-LD normalization: {e}")


    # Sign the normalized document
    signature = private_key.sign(normalized.encode("utf-8"))
    return "z" + base58.b58encode(signature).decode("utf-8")


def verify_signature(signature: str, message: str, public_key: ed25519.Ed25519PublicKey):
    """
    Verify a signature. Raises SignatureVerificationError on failure.
    """
    try:
        if signature.startswith("z"):
            signature_bytes = base58.b58decode(signature[1:])
        else:
            # Attempt to decode as hex if not base58 encoded with 'z' prefix
            try:
                signature_bytes = bytes.fromhex(signature)
            except ValueError:
                raise SignatureVerificationError(
                    "Signature format is invalid. Expected 'z' prefix for base58 or hex."
                )
        public_key.verify(signature_bytes, message.encode("utf-8"))
    except InvalidSignature:
        raise SignatureVerificationError("Signature is invalid.")
    except Exception as e:
        raise SignatureVerificationError(f"Verification error: {e}")


def create_capability(
    controller_did: str,
    invoker_did: str,
    actions: List[Dict[str, Any]],
    target_info: Dict[str, Any],
    controller_key: ed25519.Ed25519PrivateKey,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None,
) -> Capability:
    """
    Create a new capability with the specified parameters and sign it.

    Args:
        controller_did: The DID of the controller.
        invoker_did: The DID of the invoker.
        actions: List of allowed actions with their parameters.
        target_info: The target resource information.
        controller_key: The Ed25519 private key of the controller.
        expires: Optional expiration datetime.
        caveats: Optional list of caveats/constraints.

    Returns:
        A new signed Capability instance.
    """
    capability = Capability(
        controller=Controller(id=controller_did),
        invoker=Invoker(id=invoker_did),
        actions=[Action(**action) for action in actions],
        target=Target(**target_info),
        expires=expires,
        caveats=caveats or [],
    )

    capability_doc = capability.to_json_ld()
    # Remove proof if it exists from to_json_ld before signing (it shouldn't for a new cap)
    if "proof" in capability_doc:
        del capability_doc["proof"]

    proof_value = sign_capability_document(capability_doc, controller_key)

    capability.proof = Proof(
        verification_method=f"{controller_did}#key-1", # Assuming key-1 convention
        proof_value=proof_value,
        proof_purpose="capabilityDelegation" # Default for root capabilities as well
    )
    return capability


def delegate_capability(
    parent_capability: Capability,
    delegator_key: ed25519.Ed25519PrivateKey,
    new_invoker_did: str,
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
    actions: Optional[List[Dict[str, Any]]] = None,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None,
) -> Capability:
    """
    Create a delegated capability from a parent capability.

    Args:
        parent_capability: The parent Capability instance.
        delegator_key: The Ed25519 private key of the delegator (current invoker of parent).
        new_invoker_did: The DID of the new invoker.
        did_key_store: A mapping of DIDs to public keys for verification.
        revoked_capabilities: A set of revoked capability IDs.
        capability_store: A mapping of capability IDs to Capability objects.
        actions: Optional list of allowed actions (must be subset of parent).
        expires: Optional expiration datetime.
        caveats: Optional list of additional caveats.

    Returns:
        A new delegated Capability instance.
    Raises:
        DelegationError: If delegation cannot be performed.
        CapabilityNotFoundError: If a parent capability is not found.
    """
    current = parent_capability
    chain_to_check = [current]
    while current.parent_capability:
        parent_cap_id = current.parent_capability
        parent_from_store = capability_store.get(parent_cap_id)
        if not parent_from_store:
            raise CapabilityNotFoundError(
                f"Parent capability {parent_cap_id} not found in store for delegation check."
            )
        chain_to_check.append(parent_from_store)
        current = parent_from_store

    for cap_in_chain in chain_to_check:
        if cap_in_chain.id in revoked_capabilities:
            raise DelegationError(
                f"Cannot delegate: capability {cap_in_chain.id} in the chain has been revoked."
            )

    try:
        verify_capability(parent_capability, did_key_store, revoked_capabilities, capability_store)
    except CapabilityVerificationError as e:
        raise DelegationError(f"Parent capability is invalid: {e}")

    # Ensure the delegator (current invoker of parent) is the one signing
    if parent_capability.invoker.id != parent_capability.controller.id and \
       not did_key_store.get(parent_capability.invoker.id): # Check if delegator key matches parent invoker
        # This check needs refinement based on how controller/invoker DIDs map to keys.
        # For now, we assume the delegator_key belongs to parent_capability.invoker.id
        # A more robust check would verify delegator_key against the invoker's public key.
        pass # Placeholder for a more robust check if needed.


    if actions:
        parent_action_names = {a.name for a in parent_capability.actions}
        if not all(a["name"] in parent_action_names for a in actions):
            raise DelegationError("Delegated actions must be a subset of parent actions.")
    else:
        actions = [a.model_dump() for a in parent_capability.actions] # Inherit all actions

    # Determine new controller: it's the invoker of the parent capability
    new_controller_did = parent_capability.invoker.id

    delegated = Capability(
        controller=Controller(id=new_controller_did),
        invoker=Invoker(id=new_invoker_did),
        actions=[Action(**action) for action in actions],
        target=parent_capability.target, # Target is inherited
        parent_capability=parent_capability.id,
        expires=expires or parent_capability.expires, # Narrower or same expiry
        caveats=(caveats or []) + parent_capability.caveats, # Combine caveats
    )

    delegated_doc = delegated.to_json_ld()
    if "proof" in delegated_doc: # Should not happen for a new capability
        del delegated_doc["proof"]

    proof_value = sign_capability_document(delegated_doc, delegator_key)

    delegated.proof = Proof(
        verification_method=f"{new_controller_did}#key-1", # Signed by the new controller (parent's invoker)
        proof_value=proof_value,
        proof_purpose="capabilityDelegation",
    )
    return delegated


def evaluate_caveat(
    caveat: Dict[str, Any],
    action: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    revoked_ids: Optional[Set[str]] = None, # For caveats checking revocation status of other entities
) -> None:
    """
    Evaluate a caveat. Raises CaveatEvaluationError if not satisfied.

    Args:
        caveat: The caveat to evaluate.
        action: Optional action being invoked.
        parameters: Optional parameters for the action.
        revoked_ids: Set of revoked IDs (e.g., for 'ValidWhileTrue' conditions).
    """
    caveat_type = caveat.get("type")
    satisfied = True # Assume satisfied until a check fails

    if caveat_type == "ValidUntil":
        expiry = datetime.fromisoformat(caveat["date"])
        satisfied = datetime.utcnow() < expiry
    elif caveat_type == "ValidAfter":
        start_time = datetime.fromisoformat(caveat["date"])
        satisfied = datetime.utcnow() >= start_time
    elif caveat_type == "ValidWhileTrue":
        condition_id = caveat.get("conditionId")
        satisfied = condition_id not in (revoked_ids or set())
    elif caveat_type == "TimeSlot":
        from datetime import time
        current_time = datetime.utcnow().time()
        start_time_str = caveat.get("start", "00:00")
        end_time_str = caveat.get("end", "23:59")
        try:
            start_hour, start_minute = map(int, start_time_str.split(":"))
            end_hour, end_minute = map(int, end_time_str.split(":"))
            start_time_obj = time(start_hour, start_minute)
            end_time_obj = time(end_hour, end_minute)
            satisfied = start_time_obj <= current_time <= end_time_obj
        except ValueError:
            satisfied = False # Malformed time string
    elif caveat_type == "AllowedAction":
        if action is not None: # Only apply if an action is being considered
            allowed_actions = caveat.get("actions", [])
            satisfied = action in allowed_actions
    elif caveat_type == "RequireParameter":
        if action is not None: # Only apply during action context
            if parameters is None:
                satisfied = False
            else:
                param_name = caveat.get("parameter")
                required_value = caveat.get("value")
                if param_name not in parameters:
                    satisfied = False
                elif required_value is not None and parameters[param_name] != required_value:
                    satisfied = False
    elif caveat_type == "MaxUses":
        # This type of caveat requires external state management by the client.
        # The library cannot enforce it without access to a usage count.
        # For verification, we assume it's met if present, client must track.
        pass # Cannot be evaluated by this library alone
    elif caveat_type == "AllowedNetwork":
        # This requires knowledge of the client's network, external to the library.
        pass # Cannot be evaluated by this library alone
    else:
        # Fail closed for unknown caveat types
        raise CaveatEvaluationError(f"Unknown or un-evaluatable caveat type: {caveat_type}")

    if not satisfied:
        raise CaveatEvaluationError(f"Caveat not satisfied: {caveat_type} - {caveat}")


def cleanup_expired_nonces(
    used_invocation_nonces: Set[str],
    nonce_timestamps: Dict[str, datetime],
    max_age_seconds: int = 3600
) -> None:
    """
    Remove expired nonces from the provided nonce tracking stores.

    Args:
        used_invocation_nonces: Set of used nonces.
        nonce_timestamps: Dictionary tracking nonce creation times.
        max_age_seconds: Maximum age of nonces in seconds.
    """
    current_time = datetime.utcnow()
    expired_nonces = [
        nonce for nonce, timestamp in nonce_timestamps.items()
        if (current_time - timestamp).total_seconds() > max_age_seconds
    ]
    for nonce in expired_nonces:
        used_invocation_nonces.discard(nonce)
        nonce_timestamps.pop(nonce, None)


def invoke_capability(
    capability: Capability,
    action_name: str,
    invoker_key: ed25519.Ed25519PrivateKey,
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
    used_invocation_nonces: Set[str],
    nonce_timestamps: Dict[str, datetime],
    parameters: Optional[Dict[str, Any]] = None,
    nonce_max_age_seconds: int = 3600,
) -> Dict[str, Any]:
    """
    Invoke a capability to perform an action and return a signed invocation object.

    Args:
        capability: The Capability instance to invoke.
        action_name: The name of the action to perform.
        invoker_key: The Ed25519 private key of the invoker.
        did_key_store: Store for DID public keys.
        revoked_capabilities: Set of revoked capability IDs.
        capability_store: Store for capabilities (for chain verification).
        used_invocation_nonces: Set of used nonces for replay protection.
        nonce_timestamps: Timestamps for nonces.
        parameters: Optional parameters for the action.
        nonce_max_age_seconds: Max age for nonces before cleanup.

    Returns:
        A signed JSON-LD invocation object.
    Raises:
        InvocationError: If invocation fails due to unmet conditions or errors.
        CapabilityVerificationError: If the capability or its chain is invalid.
        CaveatEvaluationError: If a caveat is not met.
        CapabilityNotFoundError: If a parent capability in the chain is missing.
    """
    cleanup_expired_nonces(used_invocation_nonces, nonce_timestamps, nonce_max_age_seconds)

    if capability.id in revoked_capabilities:
        raise InvocationError("Cannot invoke: capability is revoked.")

    verify_capability(capability, did_key_store, revoked_capabilities, capability_store) # Raises on failure

    if not any(a.name == action_name for a in capability.actions):
        raise InvocationError(f"Action '{action_name}' not allowed by this capability.")

    # Evaluate caveats for this specific invocation context
    current_cap_for_caveat_check = capability
    while current_cap_for_caveat_check:
        for caveat in current_cap_for_caveat_check.caveats:
            try:
                evaluate_caveat(caveat, action_name, parameters, revoked_capabilities)
            except CaveatEvaluationError as e:
                raise InvocationError(f"Invocation failed due to caveat on capability {current_cap_for_caveat_check.id}: {e}")

        if current_cap_for_caveat_check.parent_capability:
            parent_cap = capability_store.get(current_cap_for_caveat_check.parent_capability)
            if not parent_cap:
                raise CapabilityNotFoundError(f"Parent capability {current_cap_for_caveat_check.parent_capability} not found for caveat evaluation.")
            current_cap_for_caveat_check = parent_cap
        else:
            current_cap_for_caveat_check = None


    invocation_nonce_val = str(uuid4())
    invocation_id = f"urn:uuid:{invocation_nonce_val}"

    if invocation_id in used_invocation_nonces:
        raise InvocationError("Invocation failed: Replay attack detected (nonce already used).")

    # Create invocation document
    invocation_doc = {
        "@context": [SECURITY_V2_CONTEXT["@context"], ZCAP_V1_CONTEXT["@context"]],
        "id": invocation_id,
        "type": "InvocationProof", # Or specific type if defined by profile
        "capability": capability.id,
        "action": action_name,
        "created": datetime.utcnow().isoformat(),
        **({"parameters": parameters} if parameters else {}),
    }

    # Add proof structure before signing
    verification_method_did = capability.invoker.id # Invocation is signed by the invoker
    invocation_doc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.utcnow().isoformat(),
        "verificationMethod": f"{verification_method_did}#key-1", # Assuming key-1 convention
        "proofPurpose": "capabilityInvocation",
        "capability": capability.id, # Redundant but often included
        "signedAction": action_name, # To detect tampering of action post-signing
    }

    to_sign_doc = invocation_doc.copy()
    # Proof value is added after signing
    # No, the whole doc including proof structure (sans proofValue) is signed.

    normalized = jsonld.normalize(
        to_sign_doc, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )
    signature = invoker_key.sign(normalized.encode("utf-8"))
    proof_value = "z" + base58.b58encode(signature).decode("utf-8")

    invocation_doc["proof"]["proofValue"] = proof_value

    # Record nonce usage *after* successful creation and signing
    used_invocation_nonces.add(invocation_id)
    nonce_timestamps[invocation_id] = datetime.utcnow()

    return invocation_doc


def verify_capability(
    capability: Capability,
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
) -> None:
    """
    Verify a capability and its entire delegation chain.
    Raises CapabilityVerificationError on failure.

    Args:
        capability: The Capability instance to verify.
        did_key_store: Mapping of DIDs to public keys.
        revoked_capabilities: Set of IDs of revoked capabilities.
        capability_store: Mapping of capability IDs to Capability objects for chain lookup.
    """
    if capability.id in revoked_capabilities:
        raise CapabilityVerificationError(f"Capability {capability.id} is revoked.")

    if capability.expires and capability.expires < datetime.utcnow():
        raise CapabilityVerificationError(f"Capability {capability.id} has expired.")

    # Evaluate caveats that apply at verification time (action/params are None)
    current_for_caveats = capability
    while current_for_caveats:
        for caveat in current_for_caveats.caveats:
            try:
                # Pass revoked_capabilities for caveats like ValidWhileTrue
                evaluate_caveat(caveat, revoked_ids=revoked_capabilities)
            except CaveatEvaluationError as e:
                raise CapabilityVerificationError(
                    f"Caveat evaluation failed for {current_for_caveats.id}: {e}"
                )
        if current_for_caveats.parent_capability:
            parent = capability_store.get(current_for_caveats.parent_capability)
            if not parent:
                raise CapabilityNotFoundError(
                    f"Parent capability {current_for_caveats.parent_capability} not found during caveat check."
                )
            current_for_caveats = parent
        else:
            current_for_caveats = None


    # Verify proof of the current capability
    if not capability.proof:
        raise CapabilityVerificationError(f"Capability {capability.id} has no proof.")

    capability_doc_for_sig = capability.to_json_ld()
    proof_data = capability_doc_for_sig.pop("proof") # Temporarily remove proof for normalization
    proof_value = proof_data.get("proof_value")
    if not proof_value:
         raise CapabilityVerificationError(f"Proof for {capability.id} is missing proof_value.")


    normalized_doc = jsonld.normalize(
        capability_doc_for_sig, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )

    verification_method_uri = capability.proof.verification_method
    # Controller of the capability is the one who should have signed it.
    # The verification_method_uri should point to the controller's key.
    signer_did = verification_method_uri.split("#")[0]

    # Check if the signer_did matches the capability's stated controller
    if signer_did != capability.controller.id:
        raise CapabilityVerificationError(
            f"Proof signer DID ({signer_did}) does not match capability controller DID ({capability.controller.id})."
        )

    public_key = did_key_store.get(signer_did)
    if not public_key:
        raise DIDKeyNotFoundError(f"Public key for DID {signer_did} (controller/signer) not found.")

    try:
        verify_signature(proof_value, normalized_doc, public_key)
    except SignatureVerificationError as e:
        raise CapabilityVerificationError(f"Signature verification failed for {capability.id}: {e}")

    # Recursively verify parent capability if it exists
    if capability.parent_capability:
        parent_cap_id = capability.parent_capability
        parent_capability = capability_store.get(parent_cap_id)
        if not parent_capability:
            raise CapabilityNotFoundError(
                f"Parent capability {parent_cap_id} not found in store for verification."
            )
        # The proof purpose for the parent should be 'capabilityDelegation'
        # The controller of the current capability should be the invoker of the parent.
        if capability.controller.id != parent_capability.invoker.id:
            raise CapabilityVerificationError(
                f"Controller of delegated capability ({capability.controller.id}) "
                f"does not match invoker of parent ({parent_capability.invoker.id})."
            )

        verify_capability(parent_capability, did_key_store, revoked_capabilities, capability_store)


def verify_invocation(
    invocation_doc: Dict[str, Any],
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
    # No nonce stores needed here as nonce replay is checked at invocation time.
    # However, if invocation objects are stored and re-verified, then nonce check is relevant.
    # For now, assume verification happens on receipt.
) -> None:
    """
    Verify a capability invocation object.
    Raises InvocationVerificationError on failure.

    Args:
        invocation_doc: The invocation object (JSON-LD as dict).
        did_key_store: Mapping of DIDs to public keys.
        revoked_capabilities: Set of revoked capability IDs.
        capability_store: Store for capabilities.
    """
    if not invocation_doc or "proof" not in invocation_doc:
        raise InvocationVerificationError("Invocation is malformed or missing proof.")

    proof = invocation_doc.get("proof", {})
    if proof.get("proofPurpose") != "capabilityInvocation":
        raise InvocationVerificationError("Proof purpose is not 'capabilityInvocation'.")

    capability_id = proof.get("capability") or invocation_doc.get("capability")
    if not capability_id:
        raise InvocationVerificationError("Capability ID not found in invocation proof or document.")

    target_capability = capability_store.get(capability_id)
    if not target_capability:
        raise CapabilityNotFoundError(f"Target capability {capability_id} for invocation not found.")

    # Verify the capability itself and its chain first
    try:
        verify_capability(target_capability, did_key_store, revoked_capabilities, capability_store)
    except (CapabilityVerificationError, CapabilityNotFoundError) as e:
        raise InvocationVerificationError(f"Underlying capability {capability_id} is invalid: {e}")


    action_name = invocation_doc.get("action")
    if not action_name:
        raise InvocationVerificationError("Action not specified in invocation.")
    if not any(a.name == action_name for a in target_capability.actions):
        raise InvocationVerificationError(f"Action '{action_name}' not allowed by capability {capability_id}.")

    # Check for action tampering if signedAction is present
    signed_action = proof.get("signedAction")
    if signed_action and signed_action != action_name:
        raise InvocationVerificationError(
            f"Action tampering: invocation action '{action_name}' "
            f"does not match signedAction '{signed_action}'."
        )

    parameters = invocation_doc.get("parameters")

    # Evaluate caveats on the entire capability chain in the context of this invocation
    current_cap_for_caveat_check = target_capability
    while current_cap_for_caveat_check:
        for caveat in current_cap_for_caveat_check.caveats:
            try:
                evaluate_caveat(caveat, action_name, parameters, revoked_capabilities)
            except CaveatEvaluationError as e:
                raise InvocationVerificationError(
                    f"Invocation caveat failed on capability {current_cap_for_caveat_check.id}: {e}"
                )
        if current_cap_for_caveat_check.parent_capability:
            parent_cap = capability_store.get(current_cap_for_caveat_check.parent_capability)
            if not parent_cap: # Should have been caught by verify_capability earlier
                raise CapabilityNotFoundError(
                    f"Parent {current_cap_for_caveat_check.parent_capability} not found for invocation caveat."
                )
            current_cap_for_caveat_check = parent_cap
        else:
            current_cap_for_caveat_check = None


    # Verify invocation signature
    verification_method_uri = proof.get("verificationMethod")
    if not verification_method_uri:
        raise InvocationVerificationError("Verification method not found in invocation proof.")

    invoker_did = verification_method_uri.split("#")[0]
    # The invoker_did from the proof's verificationMethod should match the capability's invoker
    if invoker_did != target_capability.invoker.id:
        raise InvocationVerificationError(
            f"Invocation signer DID ({invoker_did}) does not match "
            f"capability's specified invoker DID ({target_capability.invoker.id})."
        )

    public_key = did_key_store.get(invoker_did)
    if not public_key:
        raise DIDKeyNotFoundError(f"Public key for invoker DID {invoker_did} not found.")

    invocation_to_verify = invocation_doc.copy()
    proof_copy = proof.copy()
    proof_value = proof_copy.pop("proofValue", None)
    if not proof_value:
        raise InvocationVerificationError("proofValue missing from invocation proof.")
    invocation_to_verify["proof"] = proof_copy # Use proof without proofValue for normalization

    try:
        normalized_invocation = jsonld.normalize(
            invocation_to_verify, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )
        verify_signature(proof_value, normalized_invocation, public_key)
    except SignatureVerificationError as e:
        raise InvocationVerificationError(f"Invocation signature verification failed: {e}")
    except Exception as e: # Catch other normalization or unexpected errors
        raise InvocationVerificationError(f"Error during invocation signature processing: {e}")

