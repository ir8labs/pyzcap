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
    revoke_capability,
    register_public_key,
    get_public_key_for_did,
    store_capability,
    get_capability_by_id,
    _cleanup_expired_nonces as cleanup_expired_nonces,
)

from .models import (
    Capability,
    Proof,
    Action,
    Controller,
    Invoker,
    Target,
)

__version__ = "0.1.0"
__all__ = [
    "create_capability",
    "delegate_capability",
    "invoke_capability",
    "verify_capability",
    "verify_invocation",
    "revoke_capability",
    "register_public_key",
    "get_public_key_for_did",
    "store_capability",
    "get_capability_by_id",
    "cleanup_expired_nonces",
    "Capability",
    "Proof",
    "Action",
    "Controller",
    "Invoker",
    "Target",
]
