# Schäge-Schwenk CDH-based ring signatures

Python implementation of the ring-signature scheme proposed by Sven Schäge and Jörg Schwenk in [*A CDH-Based Ring Signature Scheme with Short Signatures and Public Keys*](https://doi.org/10.1007/978-3-642-14577-3_12) (2010).

A ring signature lets one member of a ring sign a message without revealing which member signed it.
The signer uses their own secret key and the ring's public keys; the other members need not participate, and anyone with the message, signature and public keys can verify it.

I originally implemented this scheme in C during my master's studies in Computer Science (LM-18) at the University of Catania, for the [Cryptographic Engineering](https://diraimondo.dmi.unict.it/teaching/crypto/) course taught by Prof. Mario Di Raimondo.
That implementation depended on private course libraries, so I could not publish it.
To make the project open source, I recently asked GPT to reimplement my C code in Python using publicly available libraries.

## Getting started

### Prerequisites

- Python 3.10+
- PBC 1.0.0
- GMP
- OpenSSL 3

### Install dependencies

#### Linux (Ubuntu 22.04+ or Debian 12+)

```bash
sudo apt-get update
sudo apt-get install -y \
    python3 python3-dev python3-venv python3-pip \
    build-essential libgmp-dev libssl-dev libfl-dev \
    flex bison pkg-config curl git
```

#### macOS

Install [Homebrew](https://docs.brew.sh/Installation) if needed.

```bash
brew install python gmp openssl@3 pkgconf git

export CPPFLAGS="-I$(brew --prefix gmp)/include -I$(brew --prefix openssl@3)/include"
export LDFLAGS="-L$(brew --prefix gmp)/lib -L$(brew --prefix openssl@3)/lib"
```

### Build PBC and install the package

```bash
git clone https://github.com/marcellomaugeri/Schaege-Schwenk-CDH-based-Ring-Signature-Scheme.git
cd Schaege-Schwenk-CDH-based-Ring-Signature-Scheme
python3 -m venv .venv
source .venv/bin/activate
```

PBC's `make install` omits `genaparam` and `geneparam`, which this package needs for parameter generation.

```bash
pbc_build_dir="$(mktemp -d)"
curl --fail --location https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz \
    --output "$pbc_build_dir/pbc-1.0.0.tar.gz"
tar -xzf "$pbc_build_dir/pbc-1.0.0.tar.gz" -C "$pbc_build_dir"
(
    cd "$pbc_build_dir/pbc-1.0.0"
    ./configure --prefix="$VIRTUAL_ENV/native"
    make -j2
    make install
    ./libtool --mode=install install gen/genaparam gen/geneparam "$VIRTUAL_ENV/bin"
)

export CPPFLAGS="-I$VIRTUAL_ENV/native/include ${CPPFLAGS:-}"
export LDFLAGS="-L$VIRTUAL_ENV/native/lib -Wl,-rpath,$VIRTUAL_ENV/native/lib ${LDFLAGS:-}"
python -m pip install '.[demo,test]'
```

To install the published library after setting up the native dependencies, run `python -m pip install schaege-schwenk-ring-signature`.
The source checkout above is needed for `demo.py` and the tests.

### Run the demonstration

```bash
python demo.py --type a --rbits 256 --qbits 1536 --hash sha256 \
    --users 5 --signer 2 --message 'Hello'
```

The demonstration verifies the original message and rejects a modified one.
`--type a` selects one of the two PBC pairing families supported by this package; the Python API section explains the choice.
`--hash` defaults to `sha256`; choosing `sha512` also changes the digest length automatically.
Run `python demo.py --help` for the remaining options.

## Python API

Each operation uses the same public parameter set. The signer also needs their secret key; the verifier does not.

| Operation | Input | Result |
| --- | --- | --- |
| `setup()` | Pairing family, size parameters and message mode | Scheme instance with public parameters |
| `keygen()` | Scheme instance and number of users | Key pairs |
| `sign()` | Message, ordered public keys, signer's secret key and position | Ring signature |
| `verify()` | Message, ordered public keys and signature | `True` or `False` |

The examples below use SHA-256 to sign an arbitrary-length byte string.

### Setup

```python
from schaege_schwenk_ring_signature import SSRingSignatureScheme

scheme = SSRingSignatureScheme.setup(
    pairing_type='a',
    rbits=256,
    qbits=1536,
    hash_name='sha256',
)
```

`setup()` returns an `SSRingSignatureScheme` instance containing the pairing and public elements shared by everyone in the ring. `keygen()` creates user keys later, and `sign()` hashes the message when called.

| Parameter | Meaning |
| --- | --- |
| `pairing_type` | `'a'` or `'e'`, the PBC pairing family. |
| `rbits` | Requested bit length of the prime subgroup order `r`. Secret scalars belong to this subgroup. |
| `qbits` | Requested bit length of the base-field prime `q`, used in the curve arithmetic. |
| `hash_name` | Name of a fixed-output `hashlib` algorithm. Omit it for SHA-256. |
| `message_length` | Length in bits for raw signing. Supply this instead of `hash_name` to bypass hashing. |
| `precompute` | Set to `True` to prepare repeated powers of the generator. Defaults to `False`. |

The pairing is the operation `e` in the verification equation below. PBC calls the two supported families Type A and Type E. Both use the same group for the pairing's two inputs, as this scheme requires. The signature algorithm is the same for either choice.

| `pairing_type` | PBC pairing family |
| --- | --- |
| `'a'` | Type A uses a supersingular curve. The pairing's result lies in a quadratic extension of the base field. |
| `'e'` | Type E works without a field extension. PBC describes its pairing as slower and its group elements as large. |

The original C demo offered both families. Type A requires `qbits > rbits`; Type E requires `qbits > 2 * rbits`. These are generation constraints, not security guarantees.

For ordinary messages, `setup()` uses the hash's digest size to determine how many public elements to generate. SHA-256 needs 256 message bits; selecting `'sha512'` needs 512. The input message itself can have any byte length. BLAKE2 uses its default digest size, while SHAKE is rejected because it has no fixed output length. Choose a collision-resistant hash for signatures; being present in `hashlib` does not establish that property.

### Keygen

```python
keys = scheme.keygen(n_users=3)
ring = tuple(key.public_key for key in keys)
```

| Parameter | Meaning |
| --- | --- |
| `n_users` | Positive number of key pairs to generate. |

`keygen()` returns a tuple of `KeyPair` objects. Each has a private `secret_key` and a shareable `public_key`.

The example generates three pairs in one process. In an application, each participant can call `keygen(1)` using the same public parameters. The ring collects their distinct public keys in a fixed order.

### Sign

```python
message = b'A report from an authorised ring member'
signature = scheme.sign(
    message=message,
    public_keys=ring,
    secret_key=keys[1].secret_key,
    signer_index=1,
)
```

| Parameter | Meaning |
| --- | --- |
| `message` | Bytes to sign. In this mode, the scheme hashes them before signing. |
| `public_keys` | Ordered sequence of distinct ring members' public keys. |
| `secret_key` | The signer's private scalar. |
| `signer_index` | Zero-based position of that signer's public key in `public_keys`. |

Here, index `1` selects the second key in `ring`. `sign()` checks that the secret key matches it and returns a `RingSignature` with one component per ring member plus one message component. Invalid signing inputs raise `TypeError` or `ValueError`.

### Verify

```python
assert scheme.verify(message=message, public_keys=ring, signature=signature)
assert not scheme.verify(message=message + b'!', public_keys=ring, signature=signature)
```

| Parameter | Meaning |
| --- | --- |
| `message` | The original message bytes, before hashing. |
| `public_keys` | The same public keys in the same order used for signing. |
| `signature` | The `RingSignature` returned by `sign()`. |

`verify()` returns `True` for a valid signature and `False` for a changed message or malformed cryptographic input. It uses public information only.

### Fixed-length bit strings

To sign a bit string directly, give its length in bits to `setup()` instead of selecting a hash. The same `keygen()`, `sign()` and `verify()` methods then use the bytes you supply without hashing them.

```python
raw_scheme = SSRingSignatureScheme.setup('a', 256, 1536, message_length=13)
raw_keys = raw_scheme.keygen(1)
raw_ring = (raw_keys[0].public_key,)
raw_message = b'\x01\x10'
raw_signature = raw_scheme.sign(raw_message, raw_ring, raw_keys[0].secret_key, 0)
assert raw_scheme.verify(raw_message, raw_ring, raw_signature)
```

The raw message must occupy `ceil(message_length / 8)` bytes. Set unused high bits in the last byte to zero.
The implementation reads each byte from its least significant bit, so the first message bit selects `u[1]` in the group encoding.

## Share parameters and verify independently

The following example continues the SHA-256 flow above. Export the public parameters, ordered ring and signature as JSON bytes for storage or exchange.
`from_parameters()` reconstructs the same pairing and hash configuration in the verifier, which then imports the ring's public keys in their original order.
Each exported document is limited to 1 MiB.

```python
parameter_document = scheme.export_parameters()
public_key_documents = [scheme.export_public_key(key) for key in ring]
signature_document = scheme.export_signature(signature)

verifier = SSRingSignatureScheme.from_parameters(parameter_document)
received_ring = [verifier.import_public_key(data) for data in public_key_documents]
received_signature = verifier.import_signature(signature_document)

assert verifier.verify(message, received_ring, received_signature)
```

Each exported key and signature includes the public parameter set's fingerprint, so imports reject documents from a different parameter set.
The application must still authenticate the source of the parameters and establish which identities own the public keys.
Secret-key exports contain plaintext key material that the application must protect.

To create another instance in the same process, pass `scheme.pairing_parameters`, `scheme.copy_parameters()` and `hash_name=scheme.hash_name` to the constructor.
This reuses the parameter set without exporting JSON.

## How the scheme works

The scheme uses an elliptic-curve subgroup `G` of prime order `r` and a symmetric bilinear pairing `e: G x G -> G_T`.
Bilinearity means that `e(g^a, g^b) = e(g, g)^(a*b)`: the verifier can check relations involving secret exponents using public group elements.
Participants share a generator `g` and public points `h, u_0, ..., u_l`.
Each participant keeps a nonzero scalar `x` modulo `r` as their secret key and publishes `g^x`, a single group element.

The scheme encodes an `l`-bit message as a group element using the shared points:

```text
U(m) = u_0 * u_1^m_1 * ... * u_l^m_l
```

For ordinary messages, `sign()` first hashes the input and gives the digest to `U`. With SHA-256, `U` receives 256 bits regardless of the original message length. With `message_length`, it receives the supplied bit string directly.

Signing creates `n + 1` group elements for a ring of `n` public keys.
The signer chooses the other components randomly, then uses their secret key to compute the component corresponding to their public key so that this equation holds:

```text
e(s_1, pk_1) * ... * e(s_n, pk_n) * e(s_(n+1), U(m)) = e(g, h)
```

The verifier checks the equation using public information.
The public parameters grow with the message bit length, while the signature grows with the number of ring members.

## Security scope

The paper's unforgeability proof relies on the Computational Diffie-Hellman assumption: given `g`, `g^a` and `g^b`, computing `g^(ab)` in the source group is assumed to be infeasible.
The proof covers chosen-subring attacks, in which an attacker can request signatures on subrings but cannot obtain honest users' secret keys.
The paper also proves perfect anonymity for the mathematical construction; its security analysis does not cover information revealed by an application's logs, transport or handling of private keys.
This Python implementation has not been independently audited.

## Tests

```bash
python -m pytest
```
