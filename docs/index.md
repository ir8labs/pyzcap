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
from zcap import create_capability, delegate_capability, invoke_capability
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate keys
controller_key = ed25519.Ed25519PrivateKey.generate()

# Create a capability
capability = create_capability(
    controller="did:example:controller",
    invoker="did:example:invoker",
    actions=[{"name": "read"}],
    target={
        "id": "https://example.com/resource/123",
        "type": "Document"
    },
    controller_key=controller_key
)

# Use the capability
success = invoke_capability(capability, "read", invoker_key)
```

For detailed documentation on each component, please refer to the sections above. 