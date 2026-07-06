# SageLink

**E2E Encrypted Command / File / Shell Protocol — Pure SageLang**

SageLink is a secure communication protocol for running remote commands, transferring files, and spawning interactive shells between two known Linux devices over TCP/IP. It is implemented entirely in [SageLang](https://github.com/Night-Traders-Dev/SageLang) — every cryptographic primitive is hand-rolled from the RFC specification and verified against published test vectors before it ever touches a network socket.

```
Target Hardware: OrangePi RV2 <-> Raspberry Pi 4
Threat Model:    Hostile LAN/WiFi, active MITM, passive eavesdropping
```

## Features

- **Mutual Authentication** — pinned X25519 static keypairs via Noise_IK handshake (1 round trip)
- **Encrypted Transport** — ChaCha20-Poly1305 AEAD with per-direction keys and monotonic counters
- **Replay Protection** — sliding 64-entry bitmap replay window
- **Forward Secrecy** — ephemeral Diffie-Hellman per handshake + periodic rekeying
- **Three Multiplexed Services:**
  - **CMD** — fire-and-forget remote command execution with exit code + output
  - **FILE** — chunked file transfer with SHA-256 integrity and sliding-window flow control
  - **SHELL** — interactive PTY-based shell session with terminal resize support
- **Zero FFI** in the crypto layer (only `/dev/urandom` via syscall for ephemeral key generation)
- **RFC Test-Vector Gated** — no primitive is trusted until it passes published test vectors byte-for-byte
- **Cross-Compilation** — natively compile binaries for `x86_64`, `aarch64`, and `rv64` architectures

## Requirements

- **SageLang**: `v4.0.2` or higher (Includes unified CLI & AOT backend fixes)
- **SageVM**: `v0.9.8` or higher (For VM-based execution)
- **OS**: Linux / macOS / SageOS
- **Memory**: Minimal footprint (ideal for embedded and routers)

## Build System

SageLink uses a unified build orchestrator (`sagemake`).

```bash
# Check environment and setup
./sagemake check

# Build for VM
./sagemake cross-build

# Run the test suite
./sagemake test

# Run the benchmark suite (Native AOT vs SageVM)
./sagemake benchmark
```

## Architecture

```
┌─────────────────────────────────────────┐
│  Application Layer                       │  CMD / FILE / SHELL
├─────────────────────────────────────────┤
│  Multiplexing Layer                      │  stream_id, flow control
├─────────────────────────────────────────┤
│  Transport Encryption                    │  ChaCha20-Poly1305
├─────────────────────────────────────────┤
│  Handshake (Noise_IK)                    │  X25519, BLAKE2s, HKDF
├─────────────────────────────────────────┤
│  TCP                                     │  length-prefixed frames
└─────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Generate an identity keypair
sage sagelink/cli/sagelink.sage keygen

# 2. Configure peers in peers.toml
cat > peers.toml <<EOF
[pi4]
pubkey = "<base64 public key of the remote device>"
addr = "192.168.1.51:7420"
EOF

# 3. Listen for incoming connections
sage sagelink/cli/sagelink.sage listen

# 4. Connect and run commands
sage sagelink/cli/sagelink.sage connect pi4 cmd "uname -a"
sage sagelink/cli/sagelink.sage connect pi4 file_send ./local.txt /remote/path.txt
sage sagelink/cli/sagelink.sage connect pi4 shell
```

## Repository Structure

```
├── src/
│   ├── handshake/          Noise_IK handshake state machine
│   ├── transport/          Wire framing & replay protection
│   ├── mux/                Stream multiplexing
│   ├── app/                Application services (CMD, FILE, SHELL)
│   ├── cli/                CLI entry point
│   └── utils.sage          Compatibility utilities
├── Testing/                Crypto, handshake, and integration tests
├── docs/                   Documentation
├── sagemake                Build script
├── plan.md                 Original design plan
└── README.md
```

## Documentation

- [Architecture](docs/architecture.md)
- [Handshake Protocol](docs/handshake.md)
- [Transport Layer](docs/transport.md)
- [Stream Multiplexing](docs/multiplexing.md)
- [Application Services](docs/services.md)
- [CLI Reference](docs/cli.md)
- [Testing](docs/testing.md)

## Security

| Threat | Mitigation |
|---|---|
| Passive eavesdropper | ChaCha20-Poly1305 AEAD on all post-handshake traffic |
| Active MITM | Noise_IK mutual static-key authentication (pinned keys) |
| Replay attacks | Monotonic counter + 64-entry sliding bitmap |
| Key compromise → past sessions | Ephemeral DH per handshake + periodic rekeying |
| Nonce reuse | Independent key+counter per direction via HKDF |

## License

MIT
