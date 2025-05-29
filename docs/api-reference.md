# API Reference

## Core Functions

### Capability Creation

```python
def create_capability(
    controller: str,
    invoker: str,
    actions: List[Dict[str, Any]],
    target: Dict[str, Any],
    controller_key: Ed25519PrivateKey,
    caveats: Optional[List[Dict[str, Any]]] = None,
    parent: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Create a new ZCAP-LD capability.

    Args:
        controller: DID or URI of the capability controller
        invoker: DID or URI of the entity allowed to invoke the capability
        actions: List of permitted actions
        target: Resource the capability grants access to
        controller_key: Ed25519 private key for signing
        caveats: Optional list of restrictions
        parent: Optional parent capability for delegation chains

    Returns:
        Dict containing the capability document
    """
```

### Delegation

```python
def delegate_capability(
    capability: Dict[str, Any],
    new_invoker: str,
    delegator_key: Ed25519PrivateKey,
    restricted_actions: Optional[List[Dict[str, Any]]] = None,
    additional_caveats: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Delegate a capability to a new invoker.

    Args:
        capability: Original capability document
        new_invoker: DID or URI of the new invoker
        delegator_key: Private key of the current invoker
        restricted_actions: Optional subset of original actions
        additional_caveats: Optional additional restrictions

    Returns:
        Dict containing the delegated capability
    """
```

### Invocation

```python
def invoke_capability(
    capability: Dict[str, Any],
    action: str,
    invoker_key: Ed25519PrivateKey,
    parameters: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Invoke a capability to perform an action.

    Args:
        capability: Capability document
        action: Name of the action to perform
        invoker_key: Private key of the invoker
        parameters: Optional action parameters

    Returns:
        bool indicating success
    """
```

### Revocation

```python
def revoke_capability(
    capability: Dict[str, Any],
    controller_key: Ed25519PrivateKey,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Revoke a capability.

    Args:
        capability: Capability to revoke
        controller_key: Private key of the controller
        reason: Optional reason for revocation

    Returns:
        Dict containing the revocation record
    """
```

## Data Models

### Capability Model

```python
class Capability(BaseModel):
    id: str
    controller: str
    invoker: str
    target: Target
    actions: List[Action]
    proof: Optional[Proof] = None
    caveats: Optional[List[Caveat]] = None
    parent_capability: Optional[str] = None
```

### Action Model

```python
class Action(BaseModel):
    name: str
    parameters: Optional[Dict[str, Any]] = None
```

### Target Model

```python
class Target(BaseModel):
    id: str
    type: str
    additional_properties: Optional[Dict[str, Any]] = None
```

### Proof Model

```python
class Proof(BaseModel):
    type: str = "Ed25519Signature2020"
    created: datetime
    verificationMethod: str
    proofPurpose: str
    proofValue: str
```

### Caveat Model

```python
class Caveat(BaseModel):
    type: str
    condition: Dict[str, Any]
```

## Utility Functions

### Key Management

```python
def generate_key_pair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 key pair."""

def key_to_did(public_key: Ed25519PublicKey) -> str:
    """Convert a public key to a DID."""
```

### Verification

```python
def verify_capability_chain(
    capability: Dict[str, Any]
) -> bool:
    """Verify the entire delegation chain of a capability."""

def verify_proof(
    capability: Dict[str, Any],
    public_key: Ed25519PublicKey
) -> bool:
    """Verify the cryptographic proof of a capability."""
```

For usage examples, see the [Examples](examples.md) section.