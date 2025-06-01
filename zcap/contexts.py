"""
JSON-LD contexts for ZCAP-LD.

These contexts are used to serialize and deserialize ZCAP-LD documents.
TODO: Might need versioning for these contexts.
"""

SECURITY_V2_CONTEXT = {
    "@context": {
        "id": "@id",
        "type": "@type",
        "dc": "http://purl.org/dc/terms/",
        "sec": "https://w3id.org/security#",
        "proof": {"@id": "sec:proof", "@type": "@id"},
        "controller": {"@id": "sec:controller", "@type": "@id"},
        "target": {"@id": "sec:target", "@type": "@id"},
        "action": {"@id": "sec:action", "@type": "@id"},
    }
}

ZCAP_V1_CONTEXT = {
    "@context": {
        "id": "@id",
        "type": "@type",
        "zcap": "https://w3id.org/zcap/v1#",
        "invoker": {"@id": "zcap:invoker", "@type": "@id"},
        "parentCapability": {"@id": "zcap:parentCapability", "@type": "@id"},
        "caveats": {"@id": "zcap:caveats", "@type": "@id"},
    }
}
