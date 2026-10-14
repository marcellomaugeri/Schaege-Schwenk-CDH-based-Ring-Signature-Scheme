# Charm reimplementation design

## Purpose and agreed scope

Provide a Python implementation of the Schäge–Schwenk ring signature scheme that can be packaged for PyPI.
Use Charm-Crypto and its public mathematical dependencies.
Implement from the published paper without copying, importing, compiling or distributing files from `var`.
Preserve the package name `ssringsignaturescheme` and the existing class name `SSRingSignatureScheme`.
Keep the demonstration outside the library and validate the cryptographic behaviour with tests.
Publishing to PyPI is a later action; preparing and testing a distribution is within this implementation's scope.

## Mathematical construction

Follow sections 2.5, 2.6 and 3 of [the original paper](https://ifca.ai/pub/fc10/26_74.pdf).
Use a symmetric bilinear pairing over a prime-order group, not an asymmetric adaptation.
Choose public parameters `g`, `h`, `u[0]`, ..., `u[l]` independently through Charm's random group-element API, rejecting the identity.
Do not publish scalar representations of these parameters relative to `g`.

The programmable group hash is `U(m) = u[0] * product(u[j] ** m[j], j=1..l)`.
Encode fixed-length messages as bytes with the least significant bit of the first byte representing `m[1]`.
Include all `l` bits exactly once, and require a positive message length divisible by eight.
The initial message length is 256 bits.

Generate a nonzero scalar secret key `x` and public key `PK = g ** x`.
For an ordered ring of `n` public keys and signer position `t`, sample `r[i]` for each component except `t`, including the final message component.
Set each corresponding `s[i] = g ** r[i]`.
Compute the signer component as `(h * product(PK[i] ** (-r[i]), i != t) * U(m) ** (-r[n])) ** (1/x)`, using zero-based Python indexing.
The signature contains exactly `n + 1` elements of the source group.
Verification evaluates `product(pair(s[i], PK[i]), i=0..n-1) * pair(s[n], U(m)) == pair(g, h)`.

Retain a separate SHA-256 hash-and-sign convenience layer for arbitrary byte messages.
This layer feeds the digest to the programmable group hash; it does not replace that hash with Charm's generic hash-to-group API.
Document the additional preprocessing assumption separately from the paper's fixed-length construction.

## Library interface

Use the existing `ssringsignaturescheme/ssringsignaturescheme.py` for the implementation and add a package `__init__.py` exporting the class.
Keep the implementation small and avoid a backend abstraction or private support libraries.

- Construction selects the pairing preset, message length and optional public Charm exponentiation precomputation.
- `setup()` creates and returns fresh public parameters; calling it again replaces the previous parameter context.
- A second scheme instance can be constructed from those public parameters and their shared Charm group context for independent verification without access to private keys.
- `keygen()` generates one `(public_key, secret_key)` pair using that context.
- `sign(message, public_keys, secret_key, signer_index)` signs a fixed-length byte message.
- `verify(message, public_keys, signature)` verifies using public information only and returns a Boolean.
- `sign_hash(message, public_keys, secret_key, signer_index)` and `verify_hash(message, public_keys, signature)` provide SHA-256 preprocessing when the configured fixed message length is 256 bits.

Represent the ordered ring and signature as sequences of Charm elements.
Expose public parameters through an explicit read-only property and a constructor argument for sharing them within a Python process.
The scheme instance retains public parameters, not a collection of users' private keys.
Check that the signing key corresponds to the public key at the requested signer index.
Reject empty rings, invalid signer indices, zero secret keys and malformed or incompatible group elements.
Verification returns `False` for malformed cryptographic input; configuration and signing misuse raise descriptive exceptions.
Keep parameters shared between participating users and verifiers, and explain this in the example.

## Pairing parameters and dependency boundary

The initial supported preset is Charm's PBC-backed `SS512`, which provides a prime-order symmetric Type A pairing.
Explicitly identify it as a legacy research preset, not a modern 128-bit security claim.
Reject asymmetric presets and composite-order presets rather than treating them as interchangeable implementations of the paper.
Do not interpret a curve name, group order or message length as a security-level guarantee.
Arbitrary security-level parameter generation and additional curve presets are outside this initial implementation.
This initial scope reproduces the paper's algorithm and the demonstration workflow, not every historical parameter-generation option or binary format.

Declare `charm-crypto-framework==0.62` as the initial dependency and document its native PBC, GMP and OpenSSL requirements.
Validate with the actual Charm/PBC backend, not a simulated pairing.
Use an isolated environment and avoid changing the user's global Python installation.
Any native libraries built specifically for validation should use a local or temporary prefix.
If the native backend cannot be made available, report that limitation and do not represent the cryptographic tests as passed.

## Demonstration and tests

Add one standalone example that creates public parameters, generates several users' keys, signs a byte message, verifies with public keys and shows rejection of a modified message.
Optional timing belongs in this example; do not port the old benchmarking infrastructure.

Test the paper's verification equation, every possible signer in a small ring, a single-member ring and a proper subring.
Test first and last message bits and each programmable-hash parameter mapping.
Test modified messages, modified signature components, incorrect public keys and mismatched parameter contexts.
Test malformed signatures, invalid indices and signing-key mismatches.
Cover both fixed-length messages and SHA-256 preprocessing, including empty and non-text byte messages in the latter mode.
Exercise the public Charm precomputation option if supported by the selected backend.
Tests establish functional correctness and input handling, not a proof of security or anonymity.

## Packaging and documentation

Replace the placeholder packaging metadata with a setuptools-based `pyproject.toml` and a real initial version.
Retain author information and the existing GPLv3 project licence.
Include the paper citation, native installation requirements, shared-parameter usage and parameter limitations in the README.
Build wheel and source distributions, install the wheel into a clean test environment and run the example from outside the checkout.
Update the existing release workflow to build and test the package before publication, without uploading a release during this work.
Ensure package discovery and distributions exclude `var`, tests, the standalone example and unrelated local files.
Persistent key/parameter serialisation and interoperability with a compiled C executable are deferred; Charm elements can be shared by the public in-process API in this initial release.

## Existing checkout and acceptance

The README has pre-existing changes and the Python skeleton and release workflow are untracked.
Preserve unrelated work and make targeted edits to the requested package files.
No C implementation has been run in this session, so numerical equivalence with a compiled legacy executable is not an acceptance claim.
Acceptance means the public Python operations implement the paper's construction, the real-backend tests pass, the demonstration runs and the built package installs with its documented public dependencies.
