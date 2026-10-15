import json
import multiprocessing
from base64 import b64encode
from hashlib import sha256

import pytest
from charm.core.math.pairing import G1, ZR, init, order, pair, pairing, random
from charm.toolbox.pairingcurves import params

from schaege_schwenk_ring_signature import (
    PublicParameters,
    RingSignature,
    SSRingSignatureScheme,
)
from schaege_schwenk_ring_signature.serialization import decode, read_document
from schaege_schwenk_ring_signature.utils import create_pairing


@pytest.mark.parametrize("pairing_type,qbits", [("a", 1024), ("e", 1024)])
def test_custom_pairing_and_batch_key_generation(pairing_type, qbits):
    instance = SSRingSignatureScheme.setup(
        pairing_type=pairing_type,
        rbits=224,
        qbits=qbits,
        message_length=13,
        precompute=True,
    )
    assert instance.message_length == 13
    users = instance.keygen(3)
    ring = [key.public_key for key in users]
    message = b"\x01\x10"
    signature = instance.sign(message, ring, users[2].secret_key, 2)
    assert instance.verify(message, ring, signature)
    assert not instance.verify(b"\x00\x10", ring, signature)
    assert not instance.verify(b"\x01\x00", ring, signature)

    verifier = SSRingSignatureScheme.from_parameters(instance.export_parameters())
    received_ring = [
        verifier.import_public_key(instance.export_public_key(key)) for key in ring
    ]
    received_signature = verifier.import_signature(instance.export_signature(signature))
    assert verifier.verify(message, received_ring, received_signature)
    restored_secret = verifier.import_secret_key(
        instance.export_secret_key(users[2].secret_key)
    )
    restored_signature = verifier.sign(message, received_ring, restored_secret, 2)
    assert verifier.verify(message, received_ring, restored_signature)


def test_hash_setup_with_custom_parameters():
    instance = SSRingSignatureScheme.setup(pairing_type="a", rbits=160, qbits=512)
    assert instance.hash_name == "sha256"
    assert instance.message_length == 256
    (key,) = instance.keygen(1)
    signature = instance.sign(
        b"arbitrary length message", [key.public_key], key.secret_key, 0
    )
    assert instance.verify(b"arbitrary length message", [key.public_key], signature)
    assert not instance.verify(b"changed", [key.public_key], signature)


@pytest.mark.parametrize(
    "hash_name,digest",
    [
        ("SHA256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "sha512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "sha3_256",
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        ),
        (
            "blake2b",
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
        ),
        ("blake2s", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
    ],
)
def test_configurable_hash_and_exchange(hash_name, digest):
    instance = SSRingSignatureScheme.setup("a", 160, 512, hash_name=hash_name)
    expected = bytes.fromhex(digest)
    assert instance.message_length == len(expected) * 8
    (key,) = instance.keygen(1)
    ring = [key.public_key]
    signature = instance.sign(b"abc", ring, key.secret_key, 0)
    digest_point = instance.group_hash_function(expected)
    assert pair(signature.components[0], ring[0]) * pair(
        signature.components[1], digest_point
    ) == pair(instance.copy_g(), instance.copy_h())
    assert not instance.verify(b"abd", ring, signature)
    verifier = SSRingSignatureScheme.from_parameters(instance.export_parameters())
    assert verifier.message_length == len(expected) * 8
    assert verifier.hash_name == instance.hash_name
    public_key = verifier.import_public_key(instance.export_public_key(key.public_key))
    restored = verifier.import_signature(instance.export_signature(signature))
    assert verifier.verify(b"abc", [public_key], restored)


@pytest.mark.parametrize("hash_name", ["shake_128", "shake_256"])
def test_variable_output_hash_is_rejected_before_generation(monkeypatch, hash_name):
    monkeypatch.setenv("PATH", "")
    with pytest.raises(ValueError, match="fixed-output"):
        SSRingSignatureScheme.setup("a", 160, 512, hash_name=hash_name)


def test_different_hashes_cannot_share_exported_keys(scheme, keys):
    other = SSRingSignatureScheme(
        scheme.pairing_parameters, scheme.copy_parameters(), hash_name="sha3_256"
    )
    with pytest.raises(ValueError):
        other.import_public_key(scheme.export_public_key(keys[0].public_key))


def test_nonzero_padding_bits_are_rejected():
    instance = SSRingSignatureScheme.setup("a", 160, 512, message_length=13)
    (key,) = instance.keygen(1)
    ring = [key.public_key]
    signature = instance.sign(b"\x00\x00", ring, key.secret_key, 0)
    with pytest.raises(ValueError):
        instance.sign(b"\x00\x20", ring, key.secret_key, 0)
    assert not instance.verify(b"\x00\x20", ring, signature)


def test_message_length_is_independent_of_document_size():
    instance = SSRingSignatureScheme.setup("a", 160, 512, message_length=8192)
    (key,) = instance.keygen(1)
    message = bytes(1024)
    signature = instance.sign(message, [key.public_key], key.secret_key, 0)
    assert instance.verify(message, [key.public_key], signature)
    with pytest.raises(ValueError, match="1 MiB"):
        instance.export_parameters()


@pytest.mark.parametrize("n_users", [0, -1, True, 1.5])
def test_invalid_user_count(scheme, n_users):
    with pytest.raises(ValueError):
        scheme.keygen(n_users)


@pytest.mark.parametrize(
    "pairing_type,rbits,qbits",
    [
        ("f", 160, 512),
        ("a", 2, 512),
        ("a", True, 512),
        ("a", 160, 160),
        ("e", 160, 320),
        ("a", 160, 1 << 31),
    ],
)
def test_invalid_pairing_generation_inputs(pairing_type, rbits, qbits):
    with pytest.raises(ValueError):
        SSRingSignatureScheme.setup(pairing_type, rbits, qbits, message_length=8)


def test_missing_pbc_generator_has_a_clear_error(monkeypatch):
    monkeypatch.setenv("PATH", "")
    with pytest.raises(RuntimeError, match="genaparam"):
        SSRingSignatureScheme.setup("a", 160, 512, message_length=8)


def test_pairing_parameter_whitespace_does_not_change_the_context(scheme, keys):
    reformatted = "  ".join(scheme.pairing_parameters.split())
    verifier = SSRingSignatureScheme(
        reformatted, scheme.copy_parameters(), hash_name=scheme.hash_name
    )
    ring = [verifier.import_public_key(scheme.export_public_key(keys[0].public_key))]
    signature = scheme.sign(b"report", [keys[0].public_key], keys[0].secret_key, 0)
    restored = verifier.import_signature(scheme.export_signature(signature))
    assert verifier.verify(b"report", ring, restored)


@pytest.mark.parametrize(
    "field,value",
    [
        ("q", "15"),
        ("r", "15"),
        ("h", "0"),
        ("h", "1"),
        ("exp1", "0"),
        ("exp2", "1000000"),
        ("sign1", "0"),
        ("sign0", "0"),
        ("r", "invalid"),
    ],
)
def test_inconsistent_pairing_parameters_are_rejected(pairing_parameters, field, value):
    tokens = pairing_parameters.split()
    tokens[tokens.index(field) + 1] = value
    with pytest.raises(ValueError):
        create_pairing(" ".join(tokens))


@pytest.mark.parametrize(
    "data", ["", "type a", "type a q 15", "type a type a", "type a q 1\x00"]
)
def test_malformed_pairing_definitions_are_rejected(data):
    with pytest.raises(ValueError):
        create_pairing(data)


def test_pairing_definitions_cannot_cross_import_contexts(scheme):
    other = SSRingSignatureScheme.setup("a", 224, 1024)
    with pytest.raises(ValueError):
        other.import_public_key(
            scheme.export_public_key(scheme.keygen(1)[0].public_key)
        )


def test_invalid_type_e_curve_is_rejected_before_setup():
    # Use a fixed PBC sample: changing arbitrary b values can yield an isomorphic curve.
    data = """type e
q 7245986106510086080714203333362098431608853335867425877960916928496629182991629664903654100214900946450053872786629995869445693724001299041657434948257845644905153122838458864000479326695430719258600053239930483226650953770354174712511646273516974069245462534034085895319225452125649979474047163305307830001
r 730750862221594424981965739670091261094297337857
h 13569343110918781839835249021482970252603216587988030044836106948825516930173270978617489032334001006615524543925753725725046733884363846960470444404747241287743773746682188521738728797153760275116924829183670000
a 7130970454025799000067946137594446075551569949583815943390108723282396973737794273397246892274981883807989525599540630855644968426794929215599380425269625872763801485968007136000471718335185787206876242871042697778608875139078711621836858237429403052273312335081163896980825048123655535355411494046493419999
b 7169309004853894693616698536183663527570664411678352588247044791687141043489072737232715961588288238022010974661903752526911876859197052490952065266265699130144252031591491045333807587788600764557450846327338626261289568016170532652061787582791926724597362401398804563093625182790987016728290050466098223333
exp2 159
exp1 135
sign1 1
sign0 1"""
    tokens = data.split()
    index = tokens.index("b") + 1
    tokens[index] = str(int(tokens[index]) + 1)
    with pytest.raises(ValueError):
        create_pairing(" ".join(tokens))


@pytest.mark.parametrize(
    "field,value",
    [
        ("type", "public-key"),
        ("parameters", "wrong"),
        ("elements", "wrong"),
        ("elements", []),
        ("hash", 7),
        ("hash", "unknown-hash"),
        ("hash", "sha512"),
        ("hash", "shake_256"),
    ],
)
def test_invalid_parameter_envelope_never_initialises_native_pairing(
    scheme, monkeypatch, field, value
):
    document = json.loads(scheme.export_parameters())
    document[field] = value

    def reject_native_pairing(*args):
        pytest.fail("Invalid envelope reached native pairing initialisation")

    monkeypatch.setattr(
        "schaege_schwenk_ring_signature.scheme.create_pairing",
        reject_native_pairing,
    )
    with pytest.raises(ValueError):
        SSRingSignatureScheme.from_parameters(json.dumps(document).encode())


@pytest.fixture(scope="module")
def pairing_parameters(scheme):
    return scheme.pairing_parameters


@pytest.fixture(scope="module")
def group(scheme):
    return scheme.group


@pytest.fixture(scope="module")
def scheme():
    return SSRingSignatureScheme.setup("a", 160, 512)


@pytest.fixture(scope="module")
def raw_scheme(scheme):
    return SSRingSignatureScheme(scheme.pairing_parameters, scheme.copy_parameters())


@pytest.fixture(scope="module")
def keys(scheme):
    return scheme.keygen(3)


@pytest.mark.parametrize("signer", range(3))
def test_every_ring_member_can_sign(scheme, keys, signer):
    ring = tuple(key.public_key for key in keys)
    signature = scheme.sign(b"a report\x00\xff", ring, keys[signer].secret_key, signer)
    assert len(signature.components) == 4
    assert scheme.verify(b"a report\x00\xff", ring, signature)
    assert not scheme.verify(b"another report", ring, signature)


@pytest.mark.parametrize("members", [(0,), (0, 2)])
def test_single_member_and_subring(scheme, keys, members):
    ring = tuple(keys[i].public_key for i in members)
    signature = scheme.sign(b"", ring, keys[members[0]].secret_key, 0)
    assert scheme.verify(b"", ring, signature)


def test_signature_matches_the_papers_equation(scheme, keys):
    ring = tuple(key.public_key for key in keys)
    message = b"report"
    signature = scheme.sign(message, ring, keys[1].secret_key, 1)
    product = pair(
        signature.components[-1], scheme.group_hash_function(sha256(message).digest())
    )
    for component, public_key in zip(signature.components[:-1], ring):
        product *= pair(component, public_key)
    assert product == pair(scheme.copy_g(), scheme.copy_h())


def test_independently_calculated_signature(group, pairing_parameters):
    g = random(group, G1)
    params = PublicParameters(
        g, g**11, tuple(g**n for n in (2, 3, 5, 7, 11, 13, 17, 19, 23))
    )
    instance = SSRingSignatureScheme(pairing_parameters, params)
    ring = (g**3, g**7)
    # 3*5 + 7*(-2) + (2+3)*2 = 11, the exponent of h.
    signature = RingSignature((g**5, (g**2) ** -1, g**2))
    assert instance.verify(b"\x01", ring, signature)
    assert not instance.verify(b"\x00", ring, signature)


def test_group_hash_uses_each_message_bit(scheme):
    parameters = scheme.copy_parameters()
    for bit in range(parameters.message_length):
        message = bytearray((scheme.message_length + 7) // 8)
        message[bit // 8] = 1 << (bit % 8)
        assert (
            scheme.group_hash_function(bytes(message))
            == parameters.u[0] * parameters.u[bit + 1]
        ), bit


def test_changed_signature_and_ring_are_rejected(scheme, keys):
    ring = tuple(key.public_key for key in keys)
    signature = scheme.sign(b"report", ring, keys[0].secret_key, 0)
    components = list(signature.components)
    components[0] *= scheme.copy_g()
    assert not scheme.verify(b"report", ring, RingSignature(tuple(components)))
    changed_ring = (scheme.keygen(1)[0].public_key, *ring[1:])
    assert not scheme.verify(b"report", changed_ring, signature)


@pytest.mark.parametrize("index", [-1, 3, True, "0"])
def test_invalid_signer_index(scheme, keys, index):
    with pytest.raises((TypeError, ValueError)):
        scheme.sign(
            b"report", [key.public_key for key in keys], keys[0].secret_key, index
        )


def test_wrong_or_zero_signing_key(scheme, keys):
    ring = [key.public_key for key in keys]
    for secret in (keys[1].secret_key, init(scheme.group, ZR, 0)):
        with pytest.raises(ValueError):
            scheme.sign(b"report", ring, secret, 0)


@pytest.mark.parametrize("message", [b"", bytes(31), bytes(33), "message"])
def test_fixed_length_message_validation(raw_scheme, message):
    (key,) = raw_scheme.keygen(1)
    with pytest.raises((TypeError, ValueError)):
        raw_scheme.sign(message, [key.public_key], key.secret_key, 0)


def test_malformed_verification_inputs(scheme, keys):
    ring = [keys[0].public_key]
    signature = scheme.sign(b"report", ring, keys[0].secret_key, 0)
    assert not scheme.verify(b"report", [], RingSignature(()))
    assert not scheme.verify(b"report", ring, RingSignature((keys[0].public_key,)))
    assert not scheme.verify(b"report", ring, RingSignature(("bad", "bad")))
    assert not scheme.verify("not bytes", ring, signature)
    assert not scheme.verify(b"report", [init(scheme.group, G1, 1)], signature)


def test_duplicate_ring_members_are_rejected(scheme, keys):
    with pytest.raises(ValueError):
        scheme.sign(b"report", [keys[0].public_key] * 2, keys[0].secret_key, 0)


def test_precomputation_and_shared_parameters():
    signer = SSRingSignatureScheme.setup("a", 160, 512, precompute=True)
    verifier = SSRingSignatureScheme(
        signer.pairing_parameters, signer.copy_parameters(), hash_name=signer.hash_name
    )
    (key,) = signer.keygen(1)
    signature = signer.sign(b"report", [key.public_key], key.secret_key, 0)
    assert verifier.verify(b"report", [key.public_key], signature)


@pytest.mark.parametrize("field", ["g", "h", "u"])
def test_public_parameter_copies_cannot_change_the_scheme(field):
    instance = SSRingSignatureScheme.setup("a", 160, 512)
    (key,) = instance.keygen(1)
    ring = [key.public_key]
    document = instance.export_parameters()
    parameters = instance.copy_parameters()
    element = parameters.u[1] if field == "u" else getattr(parameters, field)
    element.set(1)
    signature = instance.sign(b"report", ring, key.secret_key, 0)
    assert instance.verify(b"report", ring, signature)
    assert instance.export_parameters() == document


def test_individual_parameter_copies_cannot_change_the_scheme(scheme):
    parameters = scheme.copy_parameters()
    document = scheme.export_parameters()
    elements = (
        scheme.copy_g(),
        scheme.copy_h(),
        scheme.copy_u(0),
        scheme.copy_u(scheme.message_length),
    )
    assert elements == (parameters.g, parameters.h, parameters.u[0], parameters.u[-1])
    for element in elements:
        element.set(1)
    assert scheme.export_parameters() == document


def test_constructor_owns_its_public_parameters():
    source = SSRingSignatureScheme.setup("a", 160, 512)
    parameters = source.copy_parameters()
    instance = SSRingSignatureScheme(
        source.pairing_parameters, parameters, hash_name=source.hash_name
    )
    parameters.h.set(1)
    (key,) = instance.keygen(1)
    signature = instance.sign(b"report", [key.public_key], key.secret_key, 0)
    assert instance.verify(b"report", [key.public_key], signature)


def test_group_hash_result_does_not_expose_a_parameter():
    instance = SSRingSignatureScheme.setup("a", 160, 512)
    document = instance.export_parameters()
    instance.group_hash_function(bytes(32)).set(1)
    assert instance.export_parameters() == document


@pytest.mark.parametrize(
    "kind", ["public-key", "secret-key", "parameters", "signature"]
)
def test_invalid_element_counts_never_reach_native_decoding(
    scheme, keys, monkeypatch, kind
):
    if kind == "public-key":
        document = json.loads(scheme.export_public_key(keys[0].public_key))
        document["elements"] *= 2
    elif kind == "secret-key":
        document = json.loads(scheme.export_secret_key(keys[0].secret_key))
        document["elements"] *= 2
    elif kind == "parameters":
        document = json.loads(scheme.export_parameters())
        document["elements"] = document["elements"][:3]
    else:
        signature = scheme.sign(b"report", [keys[0].public_key], keys[0].secret_key, 0)
        document = json.loads(scheme.export_signature(signature))
        document["elements"] = document["elements"][:1]

    def reject_native_decode(*args, **kwargs):
        pytest.fail("Invalid element count reached native decoding")

    monkeypatch.setattr(
        "schaege_schwenk_ring_signature.serialization.deserialize",
        reject_native_decode,
    )
    with pytest.raises(ValueError):
        decode(
            scheme.group,
            scheme.pairing_parameters,
            read_document(json.dumps(document).encode(), kind, document["parameters"]),
        )


def test_serialisation_allows_an_independent_verifier(scheme, keys):
    ring = [key.public_key for key in keys]
    signature = scheme.sign(b"report", ring, keys[0].secret_key, 0)
    verifier = SSRingSignatureScheme.from_parameters(scheme.export_parameters())
    restored_ring = [
        verifier.import_public_key(scheme.export_public_key(key)) for key in ring
    ]
    restored_signature = verifier.import_signature(scheme.export_signature(signature))
    assert verifier.verify(b"report", restored_ring, restored_signature)
    restored_secret = verifier.import_secret_key(
        scheme.export_secret_key(keys[0].secret_key)
    )
    another = verifier.sign(b"second report", restored_ring, restored_secret, 0)
    assert verifier.verify(b"second report", restored_ring, another)


def test_exports_cannot_cross_parameter_contexts(scheme, keys):
    parameters = scheme.copy_parameters()
    other = SSRingSignatureScheme(
        scheme.pairing_parameters,
        PublicParameters(parameters.g, parameters.h**2, parameters.u),
        hash_name=scheme.hash_name,
    )
    with pytest.raises(ValueError):
        other.import_public_key(scheme.export_public_key(keys[0].public_key))
    with pytest.raises(ValueError):
        scheme.import_public_key(scheme.export_secret_key(keys[0].secret_key))


@pytest.mark.parametrize(
    "data",
    [b"", b"{}", b"[]", b"not json", b'{"version":1,"version":1}', b"{}" * 600_000],
)
def test_malformed_parameter_documents(data):
    with pytest.raises(ValueError):
        SSRingSignatureScheme.from_parameters(data)


def test_truncated_native_encoding_is_rejected(scheme, keys):
    document = json.loads(scheme.export_public_key(keys[0].public_key))
    document["elements"][0] = "1:AA=="
    with pytest.raises(ValueError):
        scheme.import_public_key(json.dumps(document).encode())


def test_secret_key_repr_is_private(keys):
    assert str(keys[0].secret_key) not in repr(keys[0])


@pytest.mark.parametrize("bits", [0, -8, 1.5, True])
def test_invalid_message_bit_length(bits):
    with pytest.raises(ValueError):
        SSRingSignatureScheme.setup("a", 160, 512, message_length=bits)


def test_setup_rejects_a_hash_with_a_raw_message_length(monkeypatch):
    monkeypatch.setenv("PATH", "")
    with pytest.raises(ValueError, match="hash_name or message_length"):
        SSRingSignatureScheme.setup("a", 160, 512, message_length=8, hash_name="sha256")


def test_identity_signature_component_roundtrip(scheme, keys):
    key = keys[0]
    signature = RingSignature(
        (scheme.copy_h() ** (key.secret_key**-1), init(scheme.group, G1, 1))
    )
    restored = scheme.import_signature(scheme.export_signature(signature))
    assert scheme.verify(b"report", [key.public_key], restored)


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", True),
        ("version", 1),
        ("version", 3),
        ("curve", "BN254"),
        ("elements", "bad"),
    ],
)
def test_invalid_document_metadata(scheme, field, value):
    document = json.loads(scheme.export_parameters())
    document[field] = value
    with pytest.raises(ValueError):
        SSRingSignatureScheme.from_parameters(json.dumps(document).encode())


def test_off_curve_public_key_is_rejected(scheme, keys):
    document = json.loads(scheme.export_public_key(keys[0].public_key))
    # x=0, y=1 is not on the Type A curve y^2=x^3+x.
    document["elements"][0] = "1:" + b64encode(bytes(127) + b"\x01").decode()
    with pytest.raises(ValueError):
        scheme.import_public_key(json.dumps(document).encode())


def test_order_two_point_is_rejected(scheme, keys):
    document = json.loads(scheme.export_public_key(keys[0].public_key))
    # (0,0) lies on the curve but is outside its odd prime-order subgroup.
    document["elements"][0] = "1:" + b64encode(bytes(128)).decode()
    with pytest.raises(ValueError):
        scheme.import_public_key(json.dumps(document).encode())


def test_out_of_range_scalar_is_rejected(scheme, keys):
    document = json.loads(scheme.export_secret_key(keys[0].secret_key))
    document["elements"][0] = (
        "0:" + b64encode(order(scheme.group).to_bytes(20, "big")).decode()
    )
    with pytest.raises(ValueError):
        scheme.import_secret_key(json.dumps(document).encode())


def test_wrong_group_type_is_rejected(scheme, keys):
    signature = scheme.sign(b"report", [keys[0].public_key], keys[0].secret_key, 0)
    assert not scheme.verify(b"report", [keys[0].secret_key], signature)
    with pytest.raises(ValueError):
        scheme.export_public_key(keys[0].secret_key)


def test_public_key_from_another_curve_is_rejected(scheme):
    other_group = pairing(string=params["BN254"])
    public_key = random(other_group, G1)
    with pytest.raises(ValueError):
        scheme.export_public_key(public_key)


def test_asymmetric_and_composite_order_presets_are_rejected():
    for profile in ("BN254", "SS1024"):
        with pytest.raises(ValueError):
            create_pairing(params[profile])


def _verify_in_fresh_process(parameters, public_key, signature, result):
    verifier = SSRingSignatureScheme.from_parameters(parameters)
    result.put(
        verifier.verify(
            b"report",
            [verifier.import_public_key(public_key)],
            verifier.import_signature(signature),
        )
    )


def test_verification_in_a_fresh_process(scheme, keys):
    key = keys[0]
    signature = scheme.sign(b"report", [key.public_key], key.secret_key, 0)
    context = multiprocessing.get_context("spawn")
    result = context.Queue()
    process = context.Process(
        target=_verify_in_fresh_process,
        args=(
            scheme.export_parameters(),
            scheme.export_public_key(key.public_key),
            scheme.export_signature(signature),
            result,
        ),
    )
    process.start()
    try:
        process.join(timeout=15)
        assert not process.is_alive()
        assert process.exitcode == 0
        assert result.get(timeout=2) is True
    finally:
        if process.is_alive():
            process.terminate()
            process.join()
        result.close()
