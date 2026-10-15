"""Schäge-Schwenk's symmetric-pairing ring signature construction (2010)."""

from collections.abc import Sequence
from hashlib import sha256

from charm.core.math.pairing import (
    G1,
    GT,
    ZR,
    deserialize,
    init,
    pair,
    pairing,
    pc_element,
    random,
    serialize,
)

from .models import KeyPair, PublicParameters, RingSignature
from .serialization import decode, encode, read_document, validate_element
from .utils import (
    create_hash,
    create_pairing,
    generate_pairing_parameters,
    hash_message,
)


class SSRingSignatureScheme:
    """The original scheme with shared public parameters and caller-owned keys."""

    def __init__(
        self,
        pairing_parameters: str,
        parameters: PublicParameters,
        *,
        hash_name: str | None = None,
        precompute: bool = False,
    ):
        pairing_parameters, group = create_pairing(pairing_parameters)
        self._initialise(
            pairing_parameters,
            group,
            parameters,
            hash_name=hash_name,
            precompute=precompute,
        )

    def _initialise(
        self, pairing_parameters, group, parameters, *, hash_name, precompute
    ):
        self._pairing_parameters = pairing_parameters
        self._group = group
        self._validate_parameters(parameters)
        if hash_name is not None:
            digest = create_hash(hash_name)
            if parameters.message_length != digest.digest_size * 8:
                raise ValueError(
                    "Public parameter length does not match the hash output"
                )
            hash_name = digest.name
        self._hash_name = hash_name
        self._parameters = self._copy_parameters(parameters)
        if precompute and not self._parameters.g.initPP():
            raise ValueError("Charm could not initialise exponentiation precomputation")
        self._pairing_gh = pair(self._parameters.g, self._parameters.h)
        fingerprint = sha256(self._pairing_parameters.encode("ascii"))
        for element in (self._parameters.g, self._parameters.h, *self._parameters.u):
            fingerprint.update(b"\x00")
            fingerprint.update(serialize(element, False))
        if self.hash_name is not None:
            fingerprint.update(b"\x00hash:" + self.hash_name.encode("ascii"))
        self._parameter_id = fingerprint.hexdigest()

    @property
    def group(self) -> pairing:
        return self._group

    @property
    def pairing_parameters(self) -> str:
        return self._pairing_parameters

    @property
    def message_length(self) -> int:
        """Length of the bit string accepted by sign(), in bits."""
        return self._parameters.message_length

    @property
    def hash_name(self) -> str | None:
        return self._hash_name

    def copy_g(self) -> pc_element:
        return self._copy_parameter(self._parameters.g)

    def copy_h(self) -> pc_element:
        return self._copy_parameter(self._parameters.h)

    def copy_u(self, index: int) -> pc_element:
        return self._copy_parameter(self._parameters.u[index])

    def copy_parameters(self) -> PublicParameters:
        """Return an independent copy of all public parameters."""
        return self._copy_parameters(self._parameters)

    def _copy_parameters(self, parameters):
        return PublicParameters(
            self._copy_parameter(parameters.g),
            self._copy_parameter(parameters.h),
            tuple(self._copy_parameter(element) for element in parameters.u),
        )

    def _copy_parameter(self, element):
        return deserialize(self.group, serialize(element, False), False)

    @classmethod
    def setup(
        cls,
        pairing_type: str,
        rbits: int,
        qbits: int,
        message_length: int | None = None,
        *,
        hash_name: str | None = None,
        precompute: bool = False,
    ):
        """Generate public parameters for hashed or raw messages."""
        if message_length is None:
            digest = create_hash(hash_name if hash_name is not None else "sha256")
            message_length = digest.digest_size * 8
            hash_name = digest.name
        elif hash_name is not None:
            raise ValueError("Choose hash_name or message_length, not both")
        return cls._setup(
            pairing_type,
            rbits,
            qbits,
            message_length,
            hash_name=hash_name,
            precompute=precompute,
        )

    @classmethod
    def _setup(
        cls, pairing_type, rbits, qbits, message_length, *, hash_name, precompute
    ):
        if type(message_length) is not int or message_length <= 0:
            raise ValueError("message_length must be a positive integer")
        pairing_parameters = generate_pairing_parameters(pairing_type, rbits, qbits)
        pairing_parameters, group = create_pairing(pairing_parameters)
        elements = []
        identity = init(group, G1, 1)
        while len(elements) < message_length + 3:
            element = random(group, G1)
            if element != identity:
                elements.append(element)
        parameters = PublicParameters(elements[0], elements[1], tuple(elements[2:]))
        instance = cls.__new__(cls)
        instance._initialise(
            pairing_parameters,
            group,
            parameters,
            hash_name=hash_name,
            precompute=precompute,
        )
        return instance

    def _validate_parameters(self, parameters):
        if not isinstance(parameters, PublicParameters):
            raise TypeError("parameters must be PublicParameters")
        if parameters.message_length <= 0:
            raise ValueError(
                "Public parameters must describe a positive message length"
            )
        for element in (parameters.g, parameters.h, *parameters.u):
            validate_element(self.group, element, G1, allow_identity=False)

    def _validate_ring(self, public_keys):
        if (
            not isinstance(public_keys, Sequence)
            or isinstance(public_keys, (str, bytes))
            or not public_keys
        ):
            raise ValueError("The ring must be a nonempty sequence of public keys")
        encodings = set()
        for key in public_keys:
            validate_element(self.group, key, G1, allow_identity=False)
            encoding = serialize(key, False)
            if encoding in encodings:
                raise ValueError("Ring public keys must be distinct")
            encodings.add(encoding)

    def keygen(self, n_users: int) -> tuple[KeyPair, ...]:
        """Generate a key pair for each user, excluding noninvertible zero keys."""
        if type(n_users) is not int or n_users <= 0:
            raise ValueError("n_users must be a positive integer")
        users = []
        for _ in range(n_users):
            secret = random(self.group, ZR)
            while secret == 0:
                secret = random(self.group, ZR)
            users.append(KeyPair(self._parameters.g**secret, secret))
        return tuple(users)

    def group_hash_function(self, message: bytes) -> pc_element:
        """Evaluate U(m), with bit zero of byte zero mapped to u[1]."""
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")
        message_length = self._parameters.message_length
        message_bytes = (message_length + 7) // 8
        if len(message) != message_bytes:
            raise ValueError(f"Expected exactly {message_bytes} message bytes")
        if message_length % 8 and message[-1] >> (message_length % 8):
            raise ValueError("Unused high bits in the final message byte must be zero")
        digest = self._copy_parameter(self._parameters.u[0])
        for bit in range(message_length):
            if message[bit // 8] & (1 << (bit % 8)):
                digest *= self._parameters.u[bit + 1]
        return digest

    def sign(
        self,
        message: bytes,
        public_keys: Sequence[pc_element],
        secret_key: pc_element,
        signer_index: int,
    ) -> RingSignature:
        """Sign message bytes, hashing them when the scheme has a configured hash."""
        if (
            type(signer_index) is not int
            or not isinstance(public_keys, Sequence)
            or not 0 <= signer_index < len(public_keys)
        ):
            raise ValueError("signer_index is outside the ring")
        prepared = (
            hash_message(message, self.hash_name)
            if self.hash_name is not None
            else message
        )
        digest = self.group_hash_function(prepared)
        self._validate_ring(public_keys)
        validate_element(self.group, secret_key, ZR, allow_identity=False)
        if self._parameters.g**secret_key != public_keys[signer_index]:
            raise ValueError(
                "Secret key does not correspond to the selected ring member"
            )
        components = [None] * (len(public_keys) + 1)
        randomness = [None] * len(components)
        # Generate every random signature component except the signer's.
        for index in range(len(components)):
            if index == signer_index:
                continue
            randomness[index] = random(self.group, ZR)
            components[index] = self._parameters.g ** randomness[index]
        # Combine the other members' public-key factors with h.
        signer_component = self._copy_parameter(self._parameters.h)
        for index, public_key in enumerate(public_keys):
            if index != signer_index:
                signer_component *= public_key ** (-randomness[index])
        # Include the message factor and apply the inverse secret key.
        signer_component *= digest ** (-randomness[-1])
        components[signer_index] = signer_component ** (secret_key**-1)
        return RingSignature(tuple(components))

    def verify(
        self,
        message: bytes,
        public_keys: Sequence[pc_element],
        signature: RingSignature,
    ) -> bool:
        """Verify a signature using public information."""
        if (
            not isinstance(public_keys, Sequence)
            or not isinstance(signature, RingSignature)
            or len(signature.components) != len(public_keys) + 1
        ):
            return False
        try:
            prepared = (
                hash_message(message, self.hash_name)
                if self.hash_name is not None
                else message
            )
            digest = self.group_hash_function(prepared)
            self._validate_ring(public_keys)
            for component in signature.components:
                validate_element(self.group, component, G1)
            product = init(self.group, GT, 1)
            for component, public_key in zip(signature.components[:-1], public_keys):
                product *= pair(component, public_key)
            product *= pair(signature.components[-1], digest)
            return product == self._pairing_gh
        except (TypeError, ValueError):
            return False

    def export_parameters(self) -> bytes:
        """Export the public parameter set, including its supported pairing profile."""
        return encode(
            self.group,
            self._pairing_parameters,
            "parameters",
            None,
            (self._parameters.g, self._parameters.h, *self._parameters.u),
            hash_name=self.hash_name,
        )

    @classmethod
    def from_parameters(cls, data: bytes, *, precompute: bool = False):
        """Create an independent scheme instance from a public parameter document."""
        document = read_document(data, "parameters", None)
        pairing_parameters, group = create_pairing(document["curve"])
        elements = decode(group, pairing_parameters, document)
        instance = cls.__new__(cls)
        instance._initialise(
            pairing_parameters,
            group,
            PublicParameters(elements[0], elements[1], elements[2:]),
            hash_name=document["hash"],
            precompute=precompute,
        )
        return instance

    def export_public_key(self, public_key: pc_element) -> bytes:
        return encode(
            self.group,
            self._pairing_parameters,
            "public-key",
            self._parameter_id,
            (public_key,),
        )

    def import_public_key(self, data: bytes) -> pc_element:
        document = read_document(data, "public-key", self._parameter_id)
        elements = decode(self.group, self._pairing_parameters, document)
        return elements[0]

    def export_secret_key(self, secret_key: pc_element) -> bytes:
        """Export plaintext key material; callers must protect its storage."""
        return encode(
            self.group,
            self._pairing_parameters,
            "secret-key",
            self._parameter_id,
            (secret_key,),
        )

    def import_secret_key(self, data: bytes) -> pc_element:
        document = read_document(data, "secret-key", self._parameter_id)
        elements = decode(self.group, self._pairing_parameters, document)
        return elements[0]

    def export_signature(self, signature: RingSignature) -> bytes:
        if not isinstance(signature, RingSignature):
            raise TypeError("signature must be RingSignature")
        return encode(
            self.group,
            self._pairing_parameters,
            "signature",
            self._parameter_id,
            signature.components,
        )

    def import_signature(self, data: bytes) -> RingSignature:
        document = read_document(data, "signature", self._parameter_id)
        elements = decode(self.group, self._pairing_parameters, document)
        return RingSignature(elements)
