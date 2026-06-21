# Architecture

SageLink is organized as a strict layering of independent modules, each responsible for one concern. No module below the multiplexing layer knows about CMD, FILE, or SHELL; no module above the transport layer touches raw sockets or encryption keys.

## Layer Stack

```
┌─────────────────────────────────────────┐
│  Application Layer         (app/)       │  CMD / FILE / SHELL
├─────────────────────────────────────────┤
│  Multiplexing Layer        (mux/)       │  stream_id routing, flow control
├─────────────────────────────────────────┤
│  Transport Encryption      (transport/) │  ChaCha20-Poly1305, replay window
├─────────────────────────────────────────┤
│  Handshake                 (handshake/) │  Noise_IK (X25519, BLAKE2s, HKDF)
├─────────────────────────────────────────┤
│  TCP Socket                             │  length-prefixed binary frames
└─────────────────────────────────────────┘
```

## Module Dependencies

```
sagelink/
├── utils                      (shared byte/list conversion helpers)
├── handshake/noise_ik         (depends on crypto.* modules via builtins)
├── transport/replay_window    (standalone)
├── transport/framing          (depends on replay_window, utils, crypto.aead)
├── mux/stream                 (depends on framing, noise_ik, utils)
├── app/cmd                    (depends on mux/stream, utils)
├── app/file                   (depends on mux/stream, framing, utils)
├── app/shell                  (depends on mux/stream, utils)
└── cli/sagelink               (depends on all of the above)
```

## Wire Format

**Outer encrypted frame (on TCP):**

```
+----------+----------+----------------------------+
| length   | counter  | ciphertext || Poly1305 tag  |
| 4 bytes  | 8 bytes  | variable + 16 bytes         |
+----------+----------+----------------------------+
```

**Inner decrypted application frame:**

```
+----------+-----------+-----------------+
| msg_type | stream_id | payload         |
| 1 byte   | 2 bytes   | variable        |
+----------+-----------+-----------------+
```

## Source Files

| File | Lines | Purpose |
|---|---|---|
| `src/handshake/noise_ik.sage` | 223 | Noise_IK handshake state machine |
| `src/transport/framing.sage` | 147 | Encrypt/decrypt wire frames |
| `src/transport/replay_window.sage` | 56 | Sliding bitmap replay protection |
| `src/mux/stream.sage` | 373 | Stream multiplexing, rekeying |
| `src/app/cmd.sage` | 70 | Remote command execution |
| `src/app/file.sage` | 222 | Chunked file transfer |
| `src/app/shell.sage` | 253 | Interactive PTY shell |
| `src/cli/sagelink.sage` | 548 | CLI entry point |
| `src/utils.sage` | 28 | Byte/list conversion utilities |
