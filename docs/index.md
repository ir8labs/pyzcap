# zcap API Documentation

zcap is a pure Python implementation of ZCAP-LD (Authorization Capabilities for Linked Data) for decentralized applications.

## Table of Contents

1. [Core Concepts](core-concepts.md)
2. [API Reference](api-reference.md)
3. [Examples](examples.md)
4. [Security Considerations](security.md)

## Quick Links

- [GitHub Repository](https://github.com/yourusername/zcap)
- [PyPI Package](https://pypi.org/project/zcap/)
- [Issue Tracker](https://github.com/yourusername/zcap/issues)

## Installation

```bash
pip install zcap
```

## Basic Usage

```python
import asyncio
from zcap import create_capability, invoke_capability
from cryptography.hazmat.primitives.asymmetric import ed25519

async def main_index_example():
    # Generate keys
    controller_key = ed25519.Ed25519PrivateKey.generate()
    invoker_key = ed25519.Ed25519PrivateKey.generate()

    # Define DIDs and stores (minimal for this snippet to be conceptually runnable)
    controller_did = "did:example:controller"
    invoker_did = "did:example:invoker"
    did_key_store = {
        controller_did: controller_key.public_key(),
        invoker_did: invoker_key.public_key()
    }
    capability_store = {}
    revoked_capabilities = set()
    used_invocation_nonces = set()
    nonce_timestamps = {}

    # Create a capability
    capability = await create_capability(
        controller_did=controller_did,
        invoker_did=invoker_did,
        actions=[{"name": "read"}],
        target_info={
            "id": "https://example.com/resource/123",
            "type": "Document"
        },
        controller_key=controller_key
    )
    if capability:
        capability_store[capability.id] = capability
        print(f"Index example: Capability created: {capability.id}")

        # Use the capability
        try:
            invocation_proof = await invoke_capability(
                capability, "read", invoker_key,
                did_key_store, capability_store, revoked_capabilities,
                used_invocation_nonces, nonce_timestamps
            )
            print(f"Index example: Invocation successful, proof ID: {invocation_proof['id']}")
        except Exception as e:
            print(f"Index example: Invocation failed: {e}")
    else:
        print("Index example: Capability creation failed.")

if __name__ == "__main__":
    asyncio.run(main_index_example())

For detailed documentation on each component, please refer to the sections above. 