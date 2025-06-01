"""
zcap - Python ZCAP-LD Implementation

A pure Python implementation of ZCAP-LD (Authorization Capabilities for Linked Data)
for decentralized applications.
"""

from .capability import (
    create_capability,
    delegate_capability,
    invoke_capability,
    verify_capability,
    verify_invocation,
    cleanup_expired_nonces,
    sign_capability_document,
    verify_signature,
    evaluate_caveat,
    ZCAPException,
    SignatureVerificationError,
    CaveatEvaluationError,
    CapabilityVerificationError,
    InvocationVerificationError,
    DelegationError,
    InvocationError,
    DIDKeyNotFoundError,
    CapabilityNotFoundError,
)

from .models import (
    Capability,
    Proof,
    Action,
    Controller,
    Invoker,
    Target,
)

__version__ = "0.2.0"
__all__ = [
    "create_capability",
    "delegate_capability",
    "invoke_capability",
    "verify_capability",
    "verify_invocation",
    "cleanup_expired_nonces",
    "sign_capability_document",
    "verify_signature",
    "evaluate_caveat",
    "Capability",
    "Proof",
    "Action",
    "Controller",
    "Invoker",
    "Target",
    "ZCAPException",
    "SignatureVerificationError",
    "CaveatEvaluationError",
    "CapabilityVerificationError",
    "InvocationVerificationError",
    "DelegationError",
    "InvocationError",
    "DIDKeyNotFoundError",
    "CapabilityNotFoundError",
]
