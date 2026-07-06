# Changelog

## v0.2.1 (2026-07-05)

### Features
- **SageLang 4.0.2 Support**: Updated SageLink to require SageLang v4.0.2+, which includes critical fixes to the AOT backend.
- **Benchmarking**: Added `sagemake benchmark` command to compare performance between Native ELF (AOT) and SageVM compilation targets.

## v0.2.0 (2026-07-05)

### Features
- **Cross-Compilation**: Added `compile` command to `sagemake` to compile SageLink natively for `x86_64`, `aarch64`, and `rv64` architectures.
- Fixed infinite hang in `Integration (CMD/FILE/SHELL)` test caused by incorrect `q_len` calculation in `stream_read_msg` loop.

## v0.1.0 (2026-06-21)

Initial release of SageLink — an E2E encrypted protocol suite built on
**Noise_IK_25519_ChaChaPoly_BLAKE2s**.

### Features

- **Noise_IK handshake** — full initiator/responder state machine with
  ephemeral-ephemeral and static-ephemeral DH, AEAD encryption, and
  PSK-style static key authentication.
- **X25519 key exchange** — RFC 7748 compliant Montgomery ladder with
  byte-level field arithmetic (`mul_mod`, `add_mod`, `sub_mod`,
  `inv_mod`).
- **ChaCha20 stream cipher** — RFC 8439 vector-verified block function
  and encryption.
- **Poly1305 MAC** — RFC 8439 vector-verified schoolbook multiplication
  and field reduction.
- **ChaCha20-Poly1305 AEAD** — RFC 8439 encrypt/decrypt with AAD.
- **BLAKE2s hash** — RFC 7693 vector-verified, 32-byte output, no key.
- **HKDF (extract-and-expand)** — RFC 5869 using BLAKE2s as the
  underlying hash.
- **Multiplexed streams** — post-handshake transport framing with per-packet
  encryption, replay protection, and sliding window.
- **Application services** — CMD (remote command execution), FILE
  (remote file transfer), SHELL (remote shell).
- **Build system** — `sagemake` meta-build script with `info`, `check`,
  `test`, `build`, `clean`, `run`, `all` commands.

### Crypto Implementation Details

- All primitives use **byte-level multi-precision arithmetic** to avoid
  SageLang's float conversion of values ≥ 2⁵³.
- `rotr32` / `rotl32` work around SageLang's arithmetic right-shift
  (sign-extending for values ≥ 2³¹) by masking high bits.
- ChaCha20 quarter-round and block functions use explicit `u32()` masking.
- Poly1305 reduction splits at bit 130; `high × 5` is computed as
  byte-level multiplication and added back.
- X25519 field reduction uses `38` as the multiplier for 2²⁵⁶.
- HKDF avoids the `+` operator on lists (SageLang returns `nil` for
  list concatenation) and uses explicit push loops instead.

### Fixed Issues

- **X25519 `mul_mod`**: Rewrote carry-propagation logic to accumulate
  `high × 38` inline before a single carry-sweep pass, fixing wrong
  intermediate results.
- **X25519 `add_mod`**: Fixed dropped carry after `r[0] + 38`.
- **X25519 ladder reference bug**: `x3 = u` copied a reference instead
  of the list contents, causing the base point `u` to be silently
  overwritten during the conditional-swap step.
- **SAGE_PATH / module resolution**: Created `sagelink → src` symlink
  and patched `sagemake` to set `SAGE_PATH` automatically.
- **HKDF list concatenation**: Replaced `salt + ikm` with a manual loop
  because SageLang's `+` operator does not concatenate lists.

### Known Limitations

- RSA/DSA key types are not supported; only X25519.
- The `crypto/rand` module uses a PRNG seeded from `getpid()` rather
  than true random — adequate for the initial release but not
  cryptographically secure.
- Integration tests require a TCP loopback connection and may hang if
  networking is unavailable.
- SageLang v3.8.3-specific workarounds are documented in `AGENTS.md`.
