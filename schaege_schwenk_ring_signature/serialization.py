"""Versioned JSON envelopes around Charm's uncompressed element encodings."""

import json
from base64 import b64decode, b64encode

from charm.core.math.pairing import (
    G1,
    ZR,
    deserialize,
    init,
    ismember,
    order,
    pc_element,
    serialize,
)

from .utils import create_hash


def validate_element(group, value, element_type, *, allow_identity=True):
    """Check type, pairing compatibility and prime-order subgroup membership."""
    if not isinstance(value, pc_element) or value.type != element_type:
        raise ValueError("Element has the wrong group type")
    identity = init(group, element_type, 0 if element_type == ZR else 1)
    try:
        is_identity = value == identity
    except Exception as error:
        # Charm does not export its native exception for incompatible pairing groups.
        raise ValueError("Element belongs to an incompatible pairing group") from error
    if not ismember(group, value):
        raise ValueError("Element is outside the required subgroup")
    if not allow_identity and is_identity:
        raise ValueError("Identity elements are not permitted here")


def _validate_count(kind, count):
    if kind in ("public-key", "secret-key"):
        if count != 1:
            raise ValueError("Expected exactly one key")
    elif kind == "parameters":
        if count < 4:
            raise ValueError("Parameters must describe a positive message length")
    elif kind == "signature":
        if count < 2:
            raise ValueError("Expected a signature for a nonempty ring")
    else:
        raise ValueError("Unsupported document type")


def encode(group, pairing_parameters, kind, parameter_id, elements, *, hash_name=None) -> bytes:
    _validate_count(kind, len(elements))
    encoded = []
    for element in elements:
        validate_element(
            group, element, ZR if kind == "secret-key" else G1, allow_identity=kind == "signature"
        )
        if element.type == G1 and element == init(group, G1, 1):
            # PBC's coordinate encoding does not preserve the point at infinity.
            encoded.append("identity")
        else:
            encoded.append(serialize(element, False).decode("ascii"))
    document = {
        "version": 2,
        "curve": pairing_parameters,
        "type": kind,
        "parameters": parameter_id,
        "elements": encoded,
    }
    if kind == "parameters":
        document["hash"] = hash_name
    data = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    if len(data) > 1_048_576:
        raise ValueError("Encoded document exceeds the 1 MiB format limit")
    return data


def _unique_fields(pairs):
    document = {}
    for name, value in pairs:
        if name in document:
            raise ValueError("Duplicate JSON field")
        document[name] = value
    return document


def read_document(data, kind, parameter_id):
    if not isinstance(data, bytes) or len(data) > 1_048_576:
        raise ValueError("Expected a byte document of at most 1 MiB")
    try:
        document = json.loads(data, object_pairs_hook=_unique_fields)
    except (ValueError, RecursionError) as error:
        raise ValueError("Invalid JSON document") from error
    fields = {
        "version",
        "curve",
        "type",
        "parameters",
        "elements",
    }
    if kind == "parameters":
        fields.add("hash")
    if not isinstance(document, dict) or set(document) != fields:
        raise ValueError("Invalid document fields")
    if (
        type(document["version"]) is not int
        or document["version"] != 2
        or not isinstance(document["curve"], str)
    ):
        raise ValueError("Unsupported format version or pairing curve")
    if document["type"] != kind or document["parameters"] != parameter_id:
        raise ValueError("Document type or public parameter context does not match")
    if not isinstance(document["elements"], list):
        raise ValueError("Expected an element list")
    _validate_count(kind, len(document["elements"]))
    if kind == "parameters" and document["hash"] is not None:
        if not isinstance(document["hash"], str):
            raise ValueError("Expected a hashlib algorithm name or null")
        digest = create_hash(document["hash"])
        if digest.digest_size * 8 != len(document["elements"]) - 3:
            raise ValueError("Public parameter length does not match the hash output")
    return document


def decode(group, pairing_parameters, document) -> tuple[pc_element, ...]:
    if document["curve"] != pairing_parameters:
        raise ValueError("Pairing context does not match")
    kind = document["type"]

    element_type = ZR if kind == "secret-key" else G1
    identity = init(group, element_type, 0 if element_type == ZR else 1)
    reference = serialize(identity, False)
    expected_length = len(b64decode(reference.split(b":", 1)[1]))
    result = []
    for encoding in document["elements"]:
        if encoding == "identity" and element_type == G1:
            if kind != "signature":
                raise ValueError("Identity elements are not permitted here")
            result.append(init(group, G1, 1))
            continue
        if not isinstance(encoding, str) or not encoding.startswith(f"{element_type}:"):
            raise ValueError("Invalid element encoding or group type")
        try:
            raw = b64decode(encoding[2:], validate=True)
        except ValueError as error:
            raise ValueError("Invalid base64 element encoding") from error
        if len(raw) != expected_length or b64encode(raw).decode("ascii") != encoding[2:]:
            raise ValueError("Invalid element length or noncanonical encoding")
        if element_type == ZR and int.from_bytes(raw, "big") >= order(group):
            raise ValueError("Scalar is outside the field")
        # The native decoder assumes a correctly sized buffer.
        element = deserialize(group, encoding.encode("ascii"), False)
        validate_element(group, element, element_type, allow_identity=False)
        if serialize(element, False).decode("ascii") != encoding:
            raise ValueError("Noncanonical group element")
        result.append(element)
    return tuple(result)
