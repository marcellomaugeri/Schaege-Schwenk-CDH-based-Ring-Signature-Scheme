"""Message hashing and validation of public PBC parameter definitions."""

from hashlib import new
from subprocess import CalledProcessError, run

from charm.config import libs, pairing_lib
from charm.core.math.integer import integer, isPrime
from charm.core.math.pairing import G1, GT, init, ismember, pair, pairing, random


def create_hash(hash_name: str):
    """Create a fixed-output hashlib object."""
    digest = new(hash_name)
    if not digest.digest_size:
        raise ValueError(f"{digest.name} has no fixed digest size; choose a fixed-output hash")
    return digest


def hash_message(message: bytes, hash_name: str) -> bytes:
    """Hash a message using the configured algorithm."""
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    digest = create_hash(hash_name)
    digest.update(message)
    return digest.digest()


def generate_pairing_parameters(pairing_type: str, rbits: int, qbits: int) -> str:
    """Generate public parameters with PBC's Type A or Type E generator."""
    if pairing_type not in ("a", "e"):
        raise ValueError("pairing_type must be 'a' or 'e'")
    if type(rbits) is not int or not 3 <= rbits < 2**31:
        raise ValueError("rbits must be at least three and fit a native signed integer")
    if type(qbits) is not int or not 0 < qbits < 2**31:
        raise ValueError("qbits must be positive and fit a native signed integer")
    minimum = rbits if pairing_type == "a" else 2 * rbits
    if qbits <= minimum:
        raise ValueError("qbits must exceed rbits for Type A or twice rbits for Type E")
    generator = f"gen{pairing_type}param"
    try:
        result = run(
            [generator, str(rbits), str(qbits)],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as error:
        raise RuntimeError(f"PBC's {generator} executable must be available on PATH") from error
    except CalledProcessError as error:
        raise RuntimeError(f"PBC parameter generation failed: {error.stderr.strip()}") from error
    return result.stdout


def create_pairing(data: str) -> tuple[str, pairing]:
    """Validate a Type A or Type E definition and create its symmetric pairing."""
    if not isinstance(data, str):
        raise TypeError("pairing_parameters must be PBC parameter text")
    tokens = data.split()
    if not data.isascii() or not tokens or len(tokens) % 2:
        raise ValueError("Invalid PBC parameter definition")
    fields = dict(zip(tokens[::2], tokens[1::2]))
    if len(fields) * 2 != len(tokens):
        raise ValueError("Duplicate PBC parameter field")
    pairing_type = fields.pop("type", None)
    if pairing_type not in ("a", "e"):
        raise ValueError("The scheme requires prime-order symmetric Type A or Type E parameters")
    required = {"q", "r", "h", "exp2", "exp1", "sign1", "sign0"}
    if pairing_type == "e":
        required.update(("a", "b"))
    if set(fields) != required:
        raise ValueError("Missing or unsupported PBC parameter fields")
    try:
        values = {name: int(value) for name, value in fields.items()}
    except ValueError as error:
        raise ValueError("PBC parameter values must be integers") from error
    q, r, h = values["q"], values["r"], values["h"]
    if q <= 3 or r <= 2 or h <= 0 or not isPrime(integer(q)) or not isPrime(integer(r)):
        raise ValueError("The field and subgroup orders must be prime, with a positive cofactor")
    exp1, exp2 = values["exp1"], values["exp2"]
    sign1, sign0 = values["sign1"], values["sign0"]
    if not 0 < exp1 < exp2 <= r.bit_length() or sign1 not in (-1, 1) or sign0 not in (-1, 1):
        raise ValueError("Invalid subgroup exponent parameters")
    if r != (1 << exp2) + sign1 * (1 << exp1) + sign0:
        raise ValueError("Subgroup order does not match its exponent parameters")
    if pairing_type == "a":
        if q % 4 != 3 or q + 1 != h * r:
            raise ValueError("Inconsistent Type A field and subgroup orders")
    else:
        a, b = values["a"], values["b"]
        if q != h * r * r + 1 or not 0 <= a < q or not 0 <= b < q:
            raise ValueError("Inconsistent Type E curve parameters")
        if (4 * pow(a, 3, q) + 27 * pow(b, 2, q)) % q == 0:
            raise ValueError("The elliptic curve is singular")
    if pairing_lib != libs.pbc:
        raise ValueError("PBC-backed Charm is required")
    parameters = f"type {pairing_type}\n" + "\n".join(
        f"{name} {values[name]}" for name in sorted(values)
    )
    group = pairing(string=parameters)
    # Bound retries so an invalid definition cannot keep sampling the identity.
    for _ in range(32):
        point = random(group, G1)
        if point != init(group, G1, 1):
            if not ismember(group, point) or pair(point, point) == init(group, GT, 1):
                raise ValueError("Pairing failed subgroup or nondegeneracy checks")
            return parameters, group
    raise ValueError("Pairing produced no nonidentity source-group element")
