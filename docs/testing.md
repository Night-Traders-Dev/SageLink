# Testing

All tests are written in SageLang and live in the `Testing/` directory. The project follows a strict **RFC test-vector gated** development philosophy: no cryptographic primitive is used until it passes published test vectors byte-for-byte.

## Test Files

| File | Lines | Purpose |
|---|---|---|
| `Testing/test_crypto.sage` | 183 | Unit tests for all crypto primitives against RFC vectors |
| `Testing/test_handshake.sage` | 147 | Handshake state machine integration test |
| `Testing/test_integration.sage` | 274 | Full system integration test over localhost TCP |

## Running Tests

```bash
# Crypto primitives
sage Testing/test_crypto.sage

# Handshake state machine
sage Testing/test_handshake.sage

# Full integration (CMD, FILE, SHELL)
sage Testing/test_integration.sage
```

### Integration Test Modes

The integration test supports two modes via the `ROLE` environment variable:

```bash
# Run as separate processes (two terminals)
ROLE=server sage Testing/test_integration.sage
ROLE=client sage Testing/test_integration.sage

# Run in single process (threads)
sage Testing/test_integration.sage
```

## Test Coverage

### Crypto Primitives (`test_crypto.sage`)

Each primitive is tested against its RFC reference:

| Primitive | RFC | Test Vector |
|---|---|---|
| ChaCha20 | RFC 8439 §2.4 | Section 2.4 encryption test |
| Poly1305 | RFC 8439 §2.5 | Section 2.5 MAC test |
| ChaCha20-Poly1305 AEAD | RFC 8439 §2.8 | Encrypt + decrypt with tag verification |
| BLAKE2s | RFC 7693 | "abc" input hash vector |
| HKDF-BLAKE2s | RFC 5869 (adapted) | Basic extract-then-expand |
| X25519 | RFC 7748 §5 | Alice-Bob DH exchange |

### Handshake (`test_handshake.sage`)

Tests the full Noise_IK state machine without networking:

1. Keypair generation
2. Full handshake message exchange (msg1 → msg2)
3. Payload encryption/decryption verification
4. Static public key extraction and matching
5. Split key matching (Alice send == Bob recv, Alice recv == Bob send)
6. Post-handshake transport encrypt/decrypt

### Integration (`test_integration.sage`)

End-to-end test over actual localhost TCP sockets:

1. Full Noise_IK handshake
2. Remote command execution (CMD service)
3. File transfer with SHA-256 verification (FILE service)
4. Interactive shell session with echo (SHELL service)

## Negative Testing

The threat model mandates these negative tests:

| Test | Expected Result |
|---|---|
| Wrong pinned pubkey | Handshake fails closed, connection dropped |
| Replayed captured frame | AEAD decryption fails or replay window rejects |
| Tampered ciphertext (single bit flip) | AEAD authentication tag mismatch, frame rejected |
| Malformed/truncated frames | Connection cleanly dropped, no panic |
