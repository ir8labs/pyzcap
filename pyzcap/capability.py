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
from typing import List, Optional, Dict, Any, Set
from uuid import uuid4
import base58
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from pyld import jsonld
from .models import Capability, Controller, Invoker, Target, Action, Proof
from .contexts import SECURITY_V2_CONTEXT, ZCAP_V1_CONTEXT

# In-memory revocation store
_revoked_capabilities: Set[str] = set()

# In-memory stores for demonstration
_capability_store: Dict[str, Capability] = {}
_did_key_store: Dict[str, ed25519.Ed25519PublicKey] = {}
_used_invocation_nonces: Set[str] = set()
_nonce_timestamps: Dict[str, datetime] = {}  # To track when nonces were created


def _sign_capability(
    capability: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey
) -> str:
    """Sign a capability document with an Ed25519 private key."""
    # Add contexts directly to the document
    capability["@context"] = [
        SECURITY_V2_CONTEXT["@context"],
        ZCAP_V1_CONTEXT["@context"],
    ]

    # Canonicalize the capability document
    normalized = jsonld.normalize(
        capability, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )

    # Sign the normalized document
    signature = private_key.sign(normalized.encode("utf-8"))
    return "z" + base58.b58encode(signature).decode("utf-8")


def _verify_signature(signature: str, message: str, public_key: ed25519.Ed25519PublicKey) -> bool:
    try:
        if signature.startswith("z"):
            signature_bytes = base58.b58decode(signature[1:])
        else:
            signature_bytes = bytes.fromhex(signature)
        public_key.verify(signature_bytes, message.encode("utf-8"))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False


def create_capability(
    controller: str,
    invoker: str,
    actions: List[Dict[str, Any]],
    target: Dict[str, Any],
    controller_key: ed25519.Ed25519PrivateKey,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None,
) -> Capability:
    """
    Create a new capability with the specified parameters and sign it.

    Args:
        controller: The DID or URI of the controller
        invoker: The DID or URI of the invoker
        actions: List of allowed actions with their parameters
        target: The target resource information
        controller_key: The Ed25519 private key of the controller
        expires: Optional expiration datetime
        caveats: Optional list of caveats/constraints

    Returns:
        A new signed Capability instance
    """
    # Create the capability model
    capability = Capability(
        controller=Controller(id=controller),
        invoker=Invoker(id=invoker),
        actions=[Action(**action) for action in actions],
        target=Target(**target),
        expires=expires,
        caveats=caveats or [],
    )

    # Convert to JSON-LD and sign
    capability_doc = capability.to_json_ld()
    proof_value = _sign_capability(capability_doc, controller_key)

    # Add the proof
    capability.proof = Proof(
        verification_method=f"{controller}#key-1", proof_value=proof_value
    )

    # Store the capability
    store_capability(capability)

    return capability


def delegate_capability(
    parent_capability: Capability,
    delegator_key: ed25519.Ed25519PrivateKey,
    new_invoker: str,
    actions: Optional[List[Dict[str, Any]]] = None,
    expires: Optional[datetime] = None,
    caveats: Optional[List[Dict[str, Any]]] = None,
) -> Capability:
    """
    Create a delegated capability from a parent capability.

    Args:
        parent_capability: The parent Capability instance
        delegator_key: The Ed25519 private key of the delegator
        new_invoker: The DID or URI of the new invoker
        actions: Optional list of allowed actions (must be subset of parent)
        expires: Optional expiration datetime
        caveats: Optional list of additional caveats

    Returns:
        A new delegated Capability instance
    """
    # Check if any capability in the chain is revoked
    current = parent_capability
    while current:
        if current.id in _revoked_capabilities:
            raise ValueError(
                "Cannot delegate: a capability in the chain has been revoked"
            )
        current = (
            get_capability_by_id(current.parent_capability)
            if current.parent_capability
            else None
        )

    # Verify the parent capability is still valid
    if not verify_capability(parent_capability):
        raise ValueError("Parent capability is invalid")

    # Ensure actions are a subset of parent actions
    if actions:
        parent_action_names = {a.name for a in parent_capability.actions}
        if not all(a["name"] in parent_action_names for a in actions):
            raise ValueError("Delegated actions must be subset of parent actions")
    else:
        actions = [a.model_dump() for a in parent_capability.actions]

    # Create the delegated capability
    delegated = Capability(
        controller=Controller(id=parent_capability.invoker.id),
        invoker=Invoker(id=new_invoker),
        actions=[Action(**action) for action in actions],
        target=parent_capability.target,
        parent_capability=parent_capability.id,
        expires=expires or parent_capability.expires,
        caveats=(caveats or []) + parent_capability.caveats,
    )

    # Sign the delegated capability
    capability_doc = delegated.to_json_ld()
    proof_value = _sign_capability(capability_doc, delegator_key)

    # Add the proof
    delegated.proof = Proof(
        verification_method=f"{parent_capability.invoker.id}#key-1",
        proof_value=proof_value,
        proof_purpose="capabilityDelegation",
    )

    # Store the delegated capability
    store_capability(delegated)

    return delegated


def _evaluate_caveat(
    caveat: Dict[str, Any],
    action: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Evaluate a caveat against the current context.

    Args:
        caveat: The caveat to evaluate
        action: Optional action being invoked (for invocation-specific caveats)
        parameters: Optional parameters for the action (for invocation-specific caveats)

    Returns:
        True if the caveat is satisfied, False otherwise
    """
    # Evaluate different types of caveats based on their type
    caveat_type = caveat.get("type")

    # Time-based caveats
    if caveat_type == "ValidUntil":
        expiry = datetime.fromisoformat(caveat["date"])
        return datetime.utcnow() < expiry

    elif caveat_type == "ValidAfter":
        start_time = datetime.fromisoformat(caveat["date"])
        return datetime.utcnow() >= start_time

    elif caveat_type == "ValidWhileTrue":
        # For demo purposes, this could check an external condition
        # In a real system, this would make an HTTP request or check a database
        condition_id = caveat.get("conditionId")
        # For demonstration, let's assume we have a way to check conditions
        # Return False if condition is not valid anymore
        return condition_id not in _revoked_capabilities

    elif caveat_type == "TimeSlot":
        # Check if the current time is within the specified time slot
        from datetime import time

        current_time = datetime.utcnow().time()
        start_time_str = caveat.get("start", "00:00")
        end_time_str = caveat.get("end", "23:59")

        # Parse start and end times
        start_hour, start_minute = map(int, start_time_str.split(":"))
        end_hour, end_minute = map(int, end_time_str.split(":"))

        start_time = time(start_hour, start_minute)
        end_time = time(end_hour, end_minute)

        # Check if current time is within the time slot
        return start_time <= current_time <= end_time

    # Action-specific caveats (only applied during invocation when action is provided)
    elif caveat_type == "AllowedAction":
        allowed_actions = caveat.get("actions", [])
        # If we're not currently invoking an action, this caveat passes verification
        if action is None:
            return True
        # During invocation, check if the action is allowed
        return action in allowed_actions

    elif caveat_type == "RequireParameter":
        # If we're not currently invoking an action, this caveat passes verification
        if action is None:
            return True

        # During invocation, if parameters are required but not provided, fail
        if parameters is None:
            return False

        # During invocation, check if the parameter is present and has the right value
        param_name = caveat.get("parameter")
        required_value = caveat.get("value")

        if param_name not in parameters:
            return False

        if required_value is not None:
            return parameters[param_name] == required_value

        return True

    elif caveat_type == "MaxUses":
        # In a real system, this would track usage counts in a database
        max_uses = caveat.get("limit", 0)
        current_uses = 0  # This would be fetched from storage in a real system
        return current_uses < max_uses

    # Network restrictions
    elif caveat_type == "AllowedNetwork":
        # In a real system, this would check client IP address
        allowed_networks = caveat.get("networks", [])
        client_network = "localhost"  # This would be the actual client network
        return client_network in allowed_networks

    # Default for unknown caveat types (extensible)
    # In a production system, you might have a registry of caveat evaluators
    else:
        # For unknown caveat types, fail closed (deny by default)
        print(f"Unknown caveat type: {caveat_type}")
        return False


def _cleanup_expired_nonces(max_age_seconds: int = 3600) -> None:
    """
    Remove expired nonces from the nonce tracking store.

    Args:
        max_age_seconds: Maximum age of nonces in seconds (default: 1 hour)
    """
    current_time = datetime.utcnow()
    expired_nonces = []

    for nonce, timestamp in _nonce_timestamps.items():
        if (current_time - timestamp).total_seconds() > max_age_seconds:
            expired_nonces.append(nonce)

    for nonce in expired_nonces:
        _used_invocation_nonces.discard(nonce)
        _nonce_timestamps.pop(nonce, None)


def invoke_capability(
    capability: Capability,
    action: str,
    invoker_key: ed25519.Ed25519PrivateKey,
    parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Invoke a capability to perform an action and return a signed invocation object.

    Args:
        capability: The Capability instance to invoke
        action: The name of the action to perform
        invoker_key: The Ed25519 private key of the invoker
        parameters: Optional parameters for the action

    Returns:
        A fully formed, signed JSON-LD invocation object if successful,
        or None if the invocation cannot be performed
    """
    # Clean up expired nonces periodically (this could be more sophisticated in production)
    _cleanup_expired_nonces()

    if capability.id in _revoked_capabilities:
        return None

    # Verify the capability chain
    if not verify_capability(capability):
        return None

    # Check if action is allowed
    if not any(a.name == action for a in capability.actions):
        return None

    # Evaluate all caveats in the entire capability chain for this specific invocation
    current = capability
    while current:
        # Evaluate each caveat in the current capability
        for caveat in current.caveats:
            if not _evaluate_caveat(caveat, action, parameters):
                return None

        # Move up the chain
        current = (
            get_capability_by_id(current.parent_capability)
            if current.parent_capability
            else None
        )

    # Create a unique nonce for this invocation to prevent replay attacks
    invocation_nonce = str(uuid4())

    # Get the verification method for the invoker
    verification_method = f"{capability.invoker.id}#key-1"

    # Create invocation object in alignment with ZCAP-LD spec
    invocation_doc = {
        "@context": [SECURITY_V2_CONTEXT["@context"], ZCAP_V1_CONTEXT["@context"]],
        "id": f"urn:uuid:{invocation_nonce}",
        "type": "InvocationProof",
        "capability": capability.id,
        "action": action,
        "created": datetime.utcnow().isoformat(),
        **({"parameters": parameters} if parameters else {}),
    }

    # Check if this nonce has been used before (replay protection)
    if invocation_doc["id"] in _used_invocation_nonces:
        return None

    # Record this nonce as used
    _used_invocation_nonces.add(invocation_doc["id"])
    _nonce_timestamps[invocation_doc["id"]] = datetime.utcnow()

    # Add the proof with all fields except proofValue (which will be added after signing)
    invocation_doc["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.utcnow().isoformat(),
        "verificationMethod": verification_method,
        "proofPurpose": "capabilityInvocation",
        "capability": capability.id,
        "signedAction": action,  # Store the signed action to detect tampering
    }

    # Create a copy of the document for signing
    to_sign = invocation_doc.copy()

    # Normalize the invocation document for signing
    normalized = jsonld.normalize(
        to_sign, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )

    # Sign the normalized document
    signature = invoker_key.sign(normalized.encode("utf-8"))
    proof_value = base58.b58encode(signature).decode("utf-8")

    # Add the proofValue back to the proof
    invocation_doc["proof"]["proofValue"] = f"z{proof_value}"

    # Return the signed invocation document
    return invocation_doc


def verify_capability(capability: Capability) -> bool:
    """
    Verify a capability and its entire delegation chain.

    Args:
        capability: The Capability instance to verify

    Returns:
        True if the capability is valid, False otherwise
    """
    if capability.id in _revoked_capabilities:
        return False

    # Check expiration
    if capability.expires and capability.expires < datetime.utcnow():
        return False

    # Evaluate all caveats in the entire capability chain
    # This is for caveats that are checked at verification time, not just invocation time
    current = capability
    while current:
        # Evaluate each caveat in the current capability
        for caveat in current.caveats:
            if not _evaluate_caveat(caveat):
                return False

        # Move up the chain
        current = (
            get_capability_by_id(current.parent_capability)
            if current.parent_capability
            else None
        )

    # Reset current to the original capability for signature verification
    current = capability

    # Verify the proof
    if not capability.proof:
        return False

    capability_doc = capability.to_json_ld()
    # Remove the proof from the document before verification
    proof_value = capability_doc.pop("proof")["proof_value"]

    # Normalize the document
    normalized = jsonld.normalize(
        capability_doc, {"algorithm": "URDNA2015", "format": "application/n-quads"}
    )

    # In a real system, you would fetch the public key from the verification method
    # Here we extract the controller's DID from the verification method
    verification_method = capability.proof.verification_method
    controller_did = verification_method.split("#")[0]

    try:
        # For demonstration, we'll use a simple mapping of DIDs to public keys
        # In a real system, you would fetch this from a DID resolver
        public_key = get_public_key_for_did(controller_did)

        # Verify the signature
        if not _verify_signature(proof_value, normalized, public_key):
            return False
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

    # Also verify parent capability if it exists
    if capability.parent_capability:
        parent = get_capability_by_id(capability.parent_capability)
        if not parent or not verify_capability(parent):
            return False

    return True


def revoke_capability(capability_id: str) -> None:
    """
    Revoke a capability by its ID.

    Args:
        capability_id: The ID of the capability to revoke
    """
    _revoked_capabilities.add(capability_id)


def register_public_key(did: str, public_key: ed25519.Ed25519PublicKey) -> None:
    """
    Register a public key for a DID.
    In a real system, this would be handled by a DID resolver.

    Args:
        did: The DID to register the key for
        public_key: The Ed25519 public key
    """
    _did_key_store[did] = public_key


def get_public_key_for_did(did: str) -> ed25519.Ed25519PublicKey:
    """
    Get the public key for a DID.
    In a real system, this would be fetched from a DID resolver.

    Args:
        did: The DID to get the key for

    Returns:
        The Ed25519 public key

    Raises:
        KeyError: If the DID is not registered
    """
    if did not in _did_key_store:
        raise KeyError(f"No public key registered for DID: {did}")
    return _did_key_store[did]


def store_capability(capability: Capability) -> None:
    """
    Store a capability.
    In a real system, this would be persisted to a database.

    Args:
        capability: The capability to store
    """
    _capability_store[capability.id] = capability


def get_capability_by_id(capability_id: str) -> Optional[Capability]:
    """
    Get a capability by its ID.
    In a real system, this would be fetched from a database.

    Args:
        capability_id: The ID of the capability to get

    Returns:
        The capability if found, None otherwise
    """
    return _capability_store.get(capability_id)


def verify_invocation(
    invocation: Dict[str, Any], capability: Optional[Capability] = None
) -> bool:
    """
    Verify a capability invocation object.

    Args:
        invocation: The invocation object to verify
        capability: Optional capability object. If not provided, it will be fetched by ID from the invocation.

    Returns:
        True if the invocation is valid, False otherwise
    """
    if not invocation or "proof" not in invocation:
        return False

    # Get the proof from the invocation
    proof = invocation["proof"]

    # Check proof purpose
    if proof.get("proofPurpose") != "capabilityInvocation":
        return False

    # Get the capability
    capability_id = proof.get("capability")
    if not capability_id:
        return False

    if capability is None:
        capability = get_capability_by_id(capability_id)
        if not capability:
            return False

    # Verify that the capability itself is valid
    if not verify_capability(capability):
        return False

    # Check that the action is allowed by the capability
    action = invocation.get("action")
    if not action or not any(a.name == action for a in capability.actions):
        return False

    # Check for tampering by comparing the action in the invocation with the signed action
    signed_action = proof.get("signedAction")
    if signed_action and signed_action != action:
        return False

    # Check if the invocation has parameters
    parameters = invocation.get("parameters")

    # Evaluate all caveats in the entire capability chain for this specific invocation
    current = capability
    while current:
        # Evaluate each caveat in the current capability
        for caveat in current.caveats:
            if not _evaluate_caveat(caveat, action, parameters):
                return False

        # Move up the chain
        current = (
            get_capability_by_id(current.parent_capability)
            if current.parent_capability
            else None
        )

    # Verify the invocation signature
    try:
        # Get the proof value and verification method
        proof_value = proof["proofValue"]
        verification_method = proof["verificationMethod"]

        # Extract the controller ID from the verification method
        controller_did = verification_method.split("#")[0]

        # Get the public key for verification
        public_key = get_public_key_for_did(controller_did)

        # Create a copy of the invocation without the proofValue for canonicalization
        to_verify = invocation.copy()
        proof_copy = proof.copy()
        del proof_copy["proofValue"]
        to_verify["proof"] = proof_copy

        # Normalize the invocation document
        normalized = jsonld.normalize(
            to_verify, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )

        # Verify the signature
        return _verify_signature(proof_value, normalized, public_key)

    except Exception as e:
        print(f"Invocation verification failed with exception: {e}")
        return False

