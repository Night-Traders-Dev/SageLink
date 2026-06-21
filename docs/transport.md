# Transport Layer

The transport layer handles wire framing, AEAD encryption/decryption, and replay protection for all post-handshake traffic.

## Framing (`transport/framing.sage`)

Every encrypted frame sent over TCP uses this structure:

```
+----------+----------+----------------------------+
| length   | counter  | ciphertext || Poly1305 tag  |
| 4 bytes  | 8 bytes  | variable + 16 bytes         |
+----------+----------+----------------------------+
```

- **length** — uint32 big-endian, total bytes of the payload (counter + ciphertext + tag)
- **counter** — uint64 big-endian, per-direction monotonic counter
- **ciphertext** — ChaCha20-Poly1305 output
- **tag** — 16-byte Poly1305 authentication tag

### Functions

| Function | Purpose |
|---|---|
| `encrypt_frame(key, counter, plaintext)` | Build complete encrypted frame (byte string) |
| `decrypt_frame(key, window, frame_payload)` | Decrypt and verify a frame (without length prefix) |
| `read_frame(sock, key, window)` | Read 4-byte length, then payload bytes from TCP socket |
| `write_frame(sock, key, counter, plaintext)` | Encrypt and write frame to TCP socket |

### Nonce Format

```
0x00000000 || counter (8 bytes big-endian)
```

The 4-byte zero prefix ensures ChaCha20's 12-byte nonce is always properly formed. Counter starts at 0 for each direction and increments by 1 per frame.

## Replay Protection (`transport/replay_window.sage`)

A sliding bitmap replay window prevents an attacker from capturing and replaying valid encrypted frames.

### Structure

- **max_seen** — highest counter value received
- **bitmap** — 64-entry boolean array

### Behavior

| Condition | Action |
|---|---|
| counter > max_seen | Slide window forward, accept |
| counter within bitmap range, not seen | Mark as seen, accept |
| counter within bitmap range, already seen | **Reject** (duplicate) |
| counter < max_seen - 64 | **Reject** (too old) |
| counter < 0 | **Reject** (invalid) |

While TCP guarantees in-order delivery, the replay window protects against:
- Captured frames replayed on a different connection
- Duplicate frames from a network-level replay attack
- Accidental double-delivery
