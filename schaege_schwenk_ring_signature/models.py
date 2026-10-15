"""Public parameters, keys and signatures for the Schäge-Schwenk scheme."""

from dataclasses import dataclass, field

from charm.core.math.pairing import pc_element


@dataclass(frozen=True)
class PublicParameters:
    g: pc_element
    h: pc_element
    u: tuple[pc_element, ...]

    def __post_init__(self):
        object.__setattr__(self, "u", tuple(self.u))

    @property
    def message_length(self) -> int:
        """Length of the scheme's message bit string."""
        return len(self.u) - 1


@dataclass(frozen=True)
class KeyPair:
    public_key: pc_element
    secret_key: pc_element = field(repr=False)


@dataclass(frozen=True)
class RingSignature:
    components: tuple[pc_element, ...]

    def __post_init__(self):
        object.__setattr__(self, "components", tuple(self.components))
