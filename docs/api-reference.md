# API Reference

This API reference details the functions and models provided by the `pyzcap` library, focusing on the `zcap.capability` module. The library has been refactored to give clients more control over state management (e.g., capability stores, DID key stores, revocation lists) and uses exception-based error handling.

## Core Functions

These functions form the primary interface for creating, delegating, invoking, and verifying capabilities.

### `create_capability`

```python
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
    Creates a new ZCAP-LD capability object and signs it.
    The client is responsible for storing the returned Capability object.

    Args:
        controller_did: The DID of the controller (owner/issuer).
        invoker_did: The DID of the entity allowed to invoke the capability.
        actions: List of permitted action dictionaries (e.g., {"name": "read"}).
        target_info: Dictionary describing the resource (e.g., {"id": "urn:foo:bar", "type": "ResourceType"}).
        controller_key: The Ed25519 private key of the controller for signing.
        expires: Optional datetime when the capability expires.
        caveats: Optional list of caveat dictionaries restricting the capability.

    Returns:
        A `zcap.models.Capability` object representing the new signed capability.

    Raises:
        ZCAPException: For errors during creation or signing.
    """
```

### `delegate_capability`

```python
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
    Creates a new delegated capability from a parent capability.
    The client is responsible for storing the returned Capability object.

    Args:
        parent_capability: The parent `Capability` object.
        delegator_key: The Ed25519 private key of the delegator (current invoker of the parent capability).
        new_invoker_did: The DID of the new invoker for the delegated capability.
        did_key_store: A dictionary mapping DIDs to public keys, used for verifying the parent chain.
        revoked_capabilities: A set of revoked capability IDs.
        capability_store: A dictionary mapping capability IDs to `Capability` objects, for chain resolution.
        actions: Optional list of actions for the new capability (must be a subset of parent's actions if specified).
                 If None, actions are inherited from the parent.
        expires: Optional expiration datetime (cannot extend beyond parent's expiry).
        caveats: Optional list of additional caveat dictionaries.

    Returns:
        A new `zcap.models.Capability` object representing the delegated capability.

    Raises:
        DelegationError: If delegation is not possible (e.g., parent invalid, actions not a subset).
        CapabilityVerificationError: If the parent capability or its chain is invalid.
        CapabilityNotFoundError: If a capability in the chain cannot be found in `capability_store`.
        DIDKeyNotFoundError: If a required public key is not in `did_key_store`.
        ZCAPException: For other errors.
    """
```

### `invoke_capability`

```python
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
    Invokes a capability to perform an action and returns a signed invocation object.
    Manages nonces for replay protection; the client must persist `used_invocation_nonces`
    and `nonce_timestamps` between invocations.

    Args:
        capability: The `Capability` object to invoke.
        action_name: The name of the action to perform.
        invoker_key: The Ed25519 private key of the invoker.
        did_key_store: DID-to-public key mapping.
        revoked_capabilities: Set of revoked capability IDs.
        capability_store: Capability ID to `Capability` object mapping.
        used_invocation_nonces: Set of nonces that have already been used.
        nonce_timestamps: Dictionary mapping nonces to their creation timestamps.
        parameters: Optional parameters for the action.
        nonce_max_age_seconds: Maximum age for nonces before being cleaned up.

    Returns:
        A dictionary representing the signed JSON-LD invocation object.

    Raises:
        InvocationError: If invocation fails (e.g., action not allowed, caveat not met, replay attack).
        CapabilityVerificationError: If the capability or its chain is invalid.
        CaveatEvaluationError: If a caveat is not met during invocation.
        CapabilityNotFoundError: If a parent capability in the chain is missing from `capability_store`.
        DIDKeyNotFoundError: If a required public key is not in `did_key_store`.
        ZCAPException: For other errors.
    """
```

### `verify_capability`

```python
def verify_capability(
    capability: Capability,
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
) -> None:
    """
    Verifies a capability and its entire delegation chain, including its proof, expiry, and caveats.

    Args:
        capability: The `Capability` object to verify.
        did_key_store: DID-to-public key mapping.
        revoked_capabilities: Set of revoked capability IDs.
        capability_store: Capability ID to `Capability` object mapping for chain resolution.

    Raises:
        CapabilityVerificationError: If verification fails (e.g., signature invalid, expired, caveat not met, revoked).
        SignatureVerificationError: Specifically if a signature in the chain is invalid.
        CaveatEvaluationError: If a caveat is not met during verification.
        CapabilityNotFoundError: If a parent capability in the chain is missing from `capability_store`.
        DIDKeyNotFoundError: If a required public key is not in `did_key_store`.
        ZCAPException: For other errors.
    """
```

### `verify_invocation`

```python
def verify_invocation(
    invocation_doc: Dict[str, Any],
    did_key_store: Dict[str, ed25519.Ed25519PublicKey],
    revoked_capabilities: Set[str],
    capability_store: Dict[str, Capability],
) -> None:
    """
    Verifies a capability invocation object.
    This includes checking the invocation proof, the validity of the invoked capability and its chain,
    and evaluating caveats in the context of the invocation.

    Args:
        invocation_doc: The JSON-LD invocation object (as a dict).
        did_key_store: DID-to-public key mapping.
        revoked_capabilities: Set of revoked capability IDs.
        capability_store: Capability ID to `Capability` object mapping.

    Raises:
        InvocationVerificationError: If invocation verification fails.
        CapabilityVerificationError: If the underlying capability or its chain is invalid.
        SignatureVerificationError: If the invocation signature is invalid.
        CaveatEvaluationError: If a caveat is not met during invocation context.
        CapabilityNotFoundError: If the target capability or one in its chain is missing from `capability_store`.
        DIDKeyNotFoundError: If a required public key is not in `did_key_store`.
        ZCAPException: For other errors.
    """
```

## Cryptographic & Utility Functions

### `sign_capability_document`

```python
def sign_capability_document(
    capability_doc: Dict[str, Any], 
    private_key: ed25519.Ed25519PrivateKey
) -> str:
    """
    Signs a JSON-LD capability document (dictionary form) and returns the signature value.
    Adds ZCAP-LD contexts if not present and normalizes before signing.

    Args:
        capability_doc: The capability document as a dictionary (proof should NOT be included).
        private_key: The Ed25519 private key for signing.

    Returns:
        The base58 encoded signature string (e.g., "z[signature_value]").
    
    Raises:
        ZCAPException: If normalization or signing fails.
    """
```

### `verify_signature`

```python
def verify_signature(
    signature: str, 
    message: str, 
    public_key: ed25519.Ed25519PublicKey
) -> None:
    """
    Verifies an Ed25519 signature against a message (typically a normalized document string).

    Args:
        signature: The signature string (base58 with 'z' prefix, or hex).
        message: The message string that was signed.
        public_key: The Ed25519 public key for verification.

    Raises:
        SignatureVerificationError: If the signature is invalid or a verification error occurs.
    """
```

### `evaluate_caveat`

```python
def evaluate_caveat(
    caveat: Dict[str, Any],
    action: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    revoked_ids: Optional[Set[str]] = None,
) -> None:
    """
    Evaluates a single caveat dictionary. 
    Some caveats like 'AllowedNetwork' or 'MaxUses' are placeholders and must be evaluated by the client.
    Unknown caveat types will cause an error.

    Args:
        caveat: The caveat dictionary to evaluate.
        action: Optional action name (for action-specific caveats during invocation).
        parameters: Optional parameters for the action (for parameter-specific caveats).
        revoked_ids: Optional set of revoked IDs (for caveats like 'ValidWhileTrue').

    Raises:
        CaveatEvaluationError: If the caveat is not satisfied or is of an unknown type.
    """
```

### `cleanup_expired_nonces`

```python
def cleanup_expired_nonces(
    used_invocation_nonces: Set[str],
    nonce_timestamps: Dict[str, datetime],
    max_age_seconds: int = 3600
) -> None:
    """
    Removes expired nonces from the client-managed nonce tracking stores.

    Args:
        used_invocation_nonces: Set of used nonces (will be modified).
        nonce_timestamps: Dictionary of nonce creation times (will be modified).
        max_age_seconds: Maximum age of nonces in seconds (default: 1 hour).
    """
```

## Data Models (`zcap.models`)

The library uses Pydantic models to represent ZCAP-LD structures. Key models include:

*   **`Capability`**: Represents a full capability, including its controller, invoker, actions, target, proof, caveats, etc.
*   **`Controller`**: Represents the controller (e.g., `id: str`, `type: str`).
*   **`Invoker`**: Represents the invoker (e.g., `id: str`, `type: str`).
*   **`Action`**: Represents an action (e.g., `name: str`, `parameters: Dict`).
*   **`Target`**: Represents the target resource (e.g., `id: str`, `type: str`).
*   **`Proof`**: Represents the cryptographic proof (e.g., `type: str`, `created: datetime`, `verification_method: str`, `proof_purpose: str`, `proof_value: str`).

Caveats within a `Capability` object are represented as `List[Dict[str, Any]]`. Each dictionary in the list is a caveat that must conform to a recognized structure (e.g., `{"type": "ValidUntil", "date": "ISO8601_DATETIME_STRING"}`).

Refer to `zcap/models.py` for detailed field definitions.

## Exception Classes (`zcap.capability`)

The library uses a hierarchy of custom exceptions for error handling:

*   `ZCAPException(Exception)`: Base exception for all library errors.
    *   `SignatureVerificationError(ZCAPException)`
    *   `CaveatEvaluationError(ZCAPException)`
    *   `CapabilityVerificationError(ZCAPException)`
    *   `InvocationVerificationError(ZCAPException)`
    *   `DelegationError(ZCAPException)`
    *   `InvocationError(ZCAPException)`
    *   `DIDKeyNotFoundError(ZCAPException)`
    *   `CapabilityNotFoundError(ZCAPException)`

Clients should be prepared to handle these exceptions.

## Key Management (Client Responsibility)

Generation and management of Ed25519 key pairs are the client's responsibility. Standard cryptographic libraries like `cryptography` can be used.

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# Example: Generate a key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()
```

## State Management (Client Responsibility)

The `pyzcap` library is stateless. The client application is responsible for managing all persistent state, including:

*   **DID Key Store**: A mapping from DIDs to their public keys (e.g., `Dict[str, ed25519.Ed25519PublicKey]`).
*   **Capability Store**: A mapping from capability IDs to `Capability` objects (e.g., `Dict[str, Capability]`).
*   **Revocation List**: A set of IDs of revoked capabilities (e.g., `Set[str]`).
*   **Nonce Store**: For replay protection in invocations:
    *   `used_invocation_nonces: Set[str]`
    *   `nonce_timestamps: Dict[str, datetime]`

These stores must be passed to the relevant library functions as arguments.

For usage examples, see the [Examples](examples.md) section and the updated example scripts in the `/examples` directory of the repository.