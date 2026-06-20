# SageLink — Design Plan
**E2E Encrypted Command / File / Shell Protocol — Pure SageLang**
Target: OrangePi RV2 ↔ Raspberry Pi 4, Linux userspace, TCP/IP

---

## 1. Goals & Scope

- Two known devices, mutually authenticated, no CA/PKI.
- Single encrypted TCP tunnel multiplexing three logical services:
  - **CMD** — fire-and-collect remote command execution
  - **FILE** — chunked file transfer, either direction
  - **SHELL** — interactive PTY session
- Zero FFI. Every crypto primitive implemented in SageLang, verified against RFC test vectors before it ever touches a socket.
- Forward secrecy and periodic rekeying — a compromised long-term key shouldn't unlock past or future traffic indefinitely.

**Non-goals (v1):** NAT traversal, >2 peers, post-quantum KEX, mobile/roaming endpoints. Keep the threat model to "two boards on the same LAN/WiFi, possibly hostile network in between."

---

## 2. Threat Model

| Threat | Mitigated by |
|---|---|
| Passive network eavesdropper | ChaCha20-Poly1305 AEAD on all post-handshake traffic |
| Active MITM at handshake | Noise_IK mutual static-key authentication (pinned keys, no TOFU) |
| Replay of captured frames | Per-direction monotonic counter + sliding replay window |
| Key compromise exposing past sessions | Ephemeral DH per handshake → forward secrecy; periodic rekey |
| Nonce reuse | Independent key + counter per direction, derived via HKDF from a single handshake |
| Weak randomness | Ephemeral keys sourced from `/dev/urandom` (the one allowed syscall in an otherwise FFI-free build) |

Out of scope: endpoint compromise (keylogged board, rooted device), traffic analysis (packet timing/size), DoS resistance.

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────┐
│  Application Layer                       │  CMD / FILE / SHELL message types
├─────────────────────────────────────────┤
│  Multiplexing Layer                      │  stream_id framing, flow control
├─────────────────────────────────────────┤
│  Transport Encryption                    │  ChaCha20-Poly1305, per-direction keys
├─────────────────────────────────────────┤
│  Handshake (Noise_IK)                    │  X25519, BLAKE2s, HKDF
├─────────────────────────────────────────┤
│  TCP                                     │  raw socket, length-prefixed frames
└─────────────────────────────────────────┘
```

Each layer is a separate SagePkg module so the crypto primitives can be unit-tested in total isolation from sockets/IO.

---

## 4. Identity & Key Management

- Each board generates one **static X25519 keypair** at install time (`sagelink keygen` → writes `identity.key` mode 0600).
- Public keys are exchanged out-of-band once (literally `cat identity.pub`, copy over, paste into `peers.toml` on the other box). No discovery, no trust-on-first-use — if the pinned key doesn't match at handshake, the connection is dropped before any data layer exists.
- `peers.toml` format:
  ```toml
  [orangepi]
  pubkey = "base64..."
  addr = "192.168.1.50:7420"

  [pi4]
  pubkey = "base64..."
  addr = "192.168.1.51:7420"
  ```

---

## 5. Handshake — Noise_IK, 1-RTT

Chosen because both parties already know each other's static public key — this gets you mutual authentication *and* a confirmed shared secret in a single round trip, with the initiator's identity hidden from passive observers (encrypted, not plaintext, in msg1).

```
Initiator (A)                          Responder (B)
   e = ephemeral keypair
   msg1 = e.pub
        || AEAD_encrypt(k1, A.static.pub)
        || AEAD_encrypt(k2, timestamp)
   --------------------------------->
                                       verify A.static.pub against peers.toml
                                       e' = ephemeral keypair
   <---------------------------------
   msg2 = e'.pub || AEAD_encrypt(k3, empty)

   both sides now derive:
     send_key_A, recv_key_A  (= send_key_B, recv_key_B swapped)
```

Chaining key mixes, in order: `DH(e, B_static)`, `DH(A_static, B_static)`, `DH(e, e')`, `DH(B_static, A_static_via_e')` — standard Noise_IK token sequence. Final `ck` → HKDF-BLAKE2s → two 32-byte keys, one per direction, each with its own zeroed-then-incremented 64-bit counter.

**Why not Noise_XX:** XX is for parties who don't know each other's static key yet (3 messages). You already have pinned keys, so IK's 1-RTT is strictly better here — fewer round trips, same security properties.

---

## 6. Transport Encryption

Post-handshake, every frame is independently encrypted:

```
nonce = 0x00000000 || counter (8 bytes, big-endian, per-direction)
ciphertext, tag = ChaCha20Poly1305_encrypt(key, nonce, plaintext, aad="")
```

- Counter increments per frame, never reused, connection is torn down (not wrapped) on overflow risk — practically unreachable given the rekey interval below.
- Receiver maintains a 64-entry replay bitmap; out-of-order frames within the window are accepted (TCP itself is ordered, so this mainly guards against replayed/duplicated old frames, not reordering).

---

## 7. Wire Framing

**Outer (encrypted) frame, on the wire:**
```
+----------+----------+----------------------------+
| length   | counter  | ciphertext || Poly1305 tag  |
| 4 bytes  | 8 bytes  | variable + 16 bytes         |
+----------+----------+----------------------------+
```

**Inner (decrypted) application frame:**
```
+----------+-----------+-----------------+
| msg_type | stream_id | payload         |
| 1 byte   | 2 bytes   | variable        |
+----------+-----------+-----------------+
```

`msg_type` enum:
```
CHAN_OPEN   = 0x01   stream_id assigned, payload = service type (CMD/FILE/SHELL)
CHAN_DATA   = 0x02   payload = service-specific bytes
CHAN_CLOSE  = 0x03   tear down stream_id
CMD_EXEC    = 0x10   payload = command string
CMD_RESULT  = 0x11   payload = exit_code(1B) + stdout/stderr blob
FILE_META   = 0x20   payload = filename, size, sha256
FILE_CHUNK  = 0x21   payload = offset(8B) + chunk bytes
FILE_ACK    = 0x22   payload = offset(8B) cumulative
SHELL_DATA  = 0x30   payload = raw PTY bytes (either direction)
SHELL_RESIZE= 0x31   payload = rows(2B) + cols(2B)
PING/PONG   = 0xF0/F1
```

One TCP connection, many `stream_id`s — a SHELL and a FILE transfer run concurrently without head-of-line blocking each other at the application layer (TCP itself still serializes bytes on the wire, but each direction's frames are small enough this is a non-issue at LAN speeds).

---

## 8. Application Layer Detail

- **CMD**: open stream → `CMD_EXEC` → remote runs via subprocess, streams `CMD_RESULT` (or chunked `CHAN_DATA` if output is large) → `CHAN_CLOSE`. Stateless, one-shot.
- **FILE**: open stream → `FILE_META` → sender streams `FILE_CHUNK`s (suggest 16KB each) → receiver periodically sends `FILE_ACK` for flow control (simple stop-and-wait or small sliding window — sliding window recommended given WiFi RTT) → integrity verified against the sha256 in `FILE_META` → `CHAN_CLOSE`.
- **SHELL**: open stream → spawn PTY (`forkpty`-equivalent) → bidirectional `SHELL_DATA` until either side sends `CHAN_CLOSE` or the shell exits. `SHELL_RESIZE` mirrors terminal size changes from the controlling client.

---

## 9. Crypto Primitives — Build Order

Each one gets its own SagePkg module + a test file that runs **only** against published RFC test vectors before it's allowed to touch real key material. No primitive moves to the next stage until its test vectors pass byte-for-byte.

| # | Primitive | RFC / Spec | Risk | Notes |
|---|---|---|---|---|
| 1 | ChaCha20 | RFC 8439 §2.4 | Low | Pure bit ops, good warm-up |
| 2 | Poly1305 | RFC 8439 §2.5 | Low-Med | 130-bit modular arithmetic — watch for overflow bugs |
| 3 | ChaCha20-Poly1305 AEAD | RFC 8439 §2.8 | Low | Glue code over 1+2 |
| 4 | X25519 | RFC 7748 §5 | **High** | Field arithmetic mod 2²⁵⁵−19, Montgomery ladder, constant-time conditional swap — this is where subtle bugs become real vulnerabilities |
| 5 | BLAKE2s | RFC 7693 | Med | Needed for HKDF and Noise's hash/mix functions |
| 6 | HKDF-BLAKE2s | RFC 5869 (adapted) | Low | Extract-and-expand over BLAKE2s |

**X25519 specifically:** budget the most review time here. Use the RFC 7748 test vectors *and* the Wycheproof test vectors if you can pull them in statically (no network dependency at runtime — just as a one-time test fixture). Implement the ladder with constant-time swap (no data-dependent branching) even though you're not yet defending against timing attacks from a co-located attacker — it's the difference between "correct" and "correct and not a footgun later."

**Randomness:** `/dev/urandom` via a plain file read for ephemeral key generation. This is the one filesystem syscall exception in an otherwise hand-rolled-crypto, FFI-free build — generating your own CSPRNG is a much worse idea than reading the kernel's.

---

## 10. Rekeying

- Trigger on whichever comes first: **N messages sent** (suggest 2^20, generously below the point where counter-exhaustion or volume-based key wear become a concern) or **T minutes elapsed** (suggest 10–15 min for an interactive/long-running link).
- Rekey = fresh Noise_IK handshake over the *same* TCP connection, multiplexed as a reserved `stream_id = 0x0000` control channel, transparent to CMD/FILE/SHELL streams in flight.
- Old keys are zeroed from memory immediately after the new ones are confirmed (both sides have sent/received at least one frame under the new key).

---

## 11. Implementation Roadmap

**Phase 1 — Crypto core (no networking at all)**
ChaCha20 → Poly1305 → AEAD → BLAKE2s → HKDF → X25519, each gated on RFC test vectors. Deliverable: a `sagelink-crypto` package importable and unit-testable standalone.

**Phase 2 — Handshake state machine**
Noise_IK implemented against an in-memory pipe (two SageLang processes or even two coroutines passing byte buffers) before any real socket is involved. Deliverable: two local instances complete a handshake and derive matching keys.

**Phase 3 — Transport + framing**
Real TCP socket, length-prefixed encrypted frames, replay window. Deliverable: encrypted ping/pong between OrangePi and Pi4 over actual WiFi.

**Phase 4 — Multiplexing + CMD**
stream_id routing, CMD_EXEC/CMD_RESULT. Simplest application protocol first — proves the multiplexing layer before FILE/SHELL add complexity.

**Phase 5 — FILE**
Chunking, flow control, integrity check.

**Phase 6 — SHELL**
PTY spawn/attach, raw mode handling, resize events. Most fiddly due to terminal semantics — saved for last.

**Phase 7 — Rekeying + hardening**
Wire in the rekey trigger, fuzz the frame parser, stress-test replay window edge cases.

---

## 12. Proposed Module Layout (SagePkg)

```
sagelink/
├── sagelink.pkg
├── crypto/
│   ├── chacha20.sg
│   ├── poly1305.sg
│   ├── aead.sg
│   ├── x25519.sg
│   ├── blake2s.sg
│   └── hkdf.sg
├── handshake/
│   └── noise_ik.sg
├── transport/
│   ├── framing.sg
│   └── replay_window.sg
├── mux/
│   └── stream.sg
├── app/
│   ├── cmd.sg
│   ├── file.sg
│   └── shell.sg
├── cli/
│   └── sagelink.sg        # keygen, connect, listen subcommands
└── tests/
    ├── vectors/            # RFC 8439, 7748, 7693 test vectors as static data
    └── *.test.sg
```

---

## 13. Testing & Validation

- **Unit**: every crypto primitive against its RFC vectors — non-negotiable gate before Phase 2.
- **Interop sanity**: handshake + one full CMD/FILE/SHELL cycle run in a loop overnight on the actual LAN link between the two boards, watching for replay-window false rejects or counter drift.
- **Fuzzing**: malformed/truncated/oversized frames fed to the parser — should drop the connection cleanly, never panic or read out of bounds.
- **Negative tests**: wrong pinned pubkey → handshake must fail closed; replayed captured frame → must be rejected; tampered ciphertext (single bit flip) → AEAD must reject.

---

## 14. Open Questions

- Sliding window size for FILE flow control — tune once you have real WiFi RTT numbers between the two boards.
- Whether CMD output should ever exceed a single frame's worth (chunking via CHAN_DATA) — depends on what commands you expect to run.
- Naming: working name is "SageLink" — open to whatever fits your existing Night-Traders-Dev naming convention better.
