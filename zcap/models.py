"""
Core data models for ZCAP-LD capabilities and related structures.

This module defines the core data models for ZCAP-LD capabilities and related structures.
It includes models for actions, controllers, invokers, targets, proofs, and capabilities.

The models are designed to be used with the pydantic library for validation and serialization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from .contexts import SECURITY_V2_CONTEXT, ZCAP_V1_CONTEXT


class Action(BaseModel):
    """Represents an action that can be performed with a capability."""

    name: str = Field(..., description="The name of the action")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Optional parameters for the action"
    )


class Controller(BaseModel):
    """Represents a capability controller."""

    id: str = Field(..., description="The DID or URI of the controller")
    type: str = Field(
        default="Ed25519VerificationKey2020", description="The type of verification key"
    )
    public_key: Optional[str] = Field(None, description="The controller's public key")


class Invoker(BaseModel):
    """Represents a capability invoker."""

    id: str = Field(..., description="The DID or URI of the invoker")
    type: str = Field(
        default="Ed25519VerificationKey2020", description="The type of verification key"
    )
    public_key: Optional[str] = Field(None, description="The invoker's public key")


class Target(BaseModel):
    """Represents a capability target."""

    id: str = Field(..., description="The URI of the target resource")
    type: str = Field(..., description="The type of the target resource")


class Proof(BaseModel):
    """Represents a cryptographic proof for a capability."""

    id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for the proof",
    )
    type: str = Field(default="Ed25519Signature2020", description="The type of proof")
    created: datetime = Field(
        default_factory=datetime.utcnow, description="When the proof was created"
    )
    verification_method: str = Field(..., description="The verification method used")
    proof_purpose: str = Field(
        default="capabilityDelegation", description="The purpose of the proof"
    )
    proof_value: str = Field(..., description="The actual proof value (signature)")
    domain: Optional[str] = Field(None, description="The domain the proof is bound to")
    nonce: Optional[str] = Field(None, description="Optional nonce for the proof")


class Capability(BaseModel):
    """Represents a ZCAP-LD capability."""

    id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for the capability",
    )
    type: str = Field(default="zcap", description="The type of the capability")
    controller: Controller = Field(..., description="The controller of the capability")
    invoker: Invoker = Field(..., description="The invoker of the capability")
    actions: List[Action] = Field(..., description="The allowed actions")
    target: Target = Field(..., description="The target of the capability")
    proof: Optional[Proof] = Field(None, description="The cryptographic proof")
    parent_capability: Optional[str] = Field(
        None, description="Reference to parent capability if delegated"
    )
    caveats: List[Dict[str, Any]] = Field(
        default_factory=list, description="Additional constraints on the capability"
    )
    created: datetime = Field(
        default_factory=datetime.utcnow, description="When the capability was created"
    )
    expires: Optional[datetime] = Field(None, description="When the capability expires")

    model_config = ConfigDict()

    @field_serializer("created", "expires")
    def serialize_datetime(self, dt: Optional[datetime]) -> Optional[str]:
        return dt.isoformat() if dt else None

    @field_serializer("id")
    def serialize_uuid(self, uuid_val: UUID) -> str:
        return str(uuid_val)

    def to_json_ld(self) -> Dict[str, Any]:
        """Convert the capability to a JSON-LD document."""
        return {
            "@context": [SECURITY_V2_CONTEXT["@context"], ZCAP_V1_CONTEXT["@context"]],
            "id": self.id,
            "type": self.type,
            "controller": {
                "id": self.controller.id,
                "type": self.controller.type,
                **(
                    {"publicKey": self.controller.public_key}
                    if self.controller.public_key
                    else {}
                ),
            },
            "invoker": {
                "id": self.invoker.id,
                "type": self.invoker.type,
                **(
                    {"publicKey": self.invoker.public_key}
                    if self.invoker.public_key
                    else {}
                ),
            },
            "action": [action.model_dump() for action in self.actions],
            "target": self.target.model_dump(),
            **({"proof": self.proof.model_dump()} if self.proof else {}),
            **(
                {"parentCapability": self.parent_capability}
                if self.parent_capability
                else {}
            ),
            "caveats": self.caveats,
            "created": self.created.isoformat(),
            **({"expires": self.expires.isoformat()} if self.expires else {}),
        }
