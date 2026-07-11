# SageLink Audit Report

## Architecture Map

```text
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
- **Major Subsystems**:
  - `src/handshake/` (Noise_IK handshake state machine)
  - `src/transport/` (Wire framing & replay protection)
  - `src/mux/` (Stream multiplexing)
  - `src/app/` (Application services: CMD, FILE, SHELL)
  - `src/cli/` (CLI entry point)
- **External Dependencies**:
  - Requires `SageLang >= 4.0.2`
  - Zero FFI for cryptography; uses FFI in app/shell.sage (`libc`) and app/file.sage.
- **Build System**:
  - `sagemake` Python script wrapping SageLang compiler/interpreter.
- **Testing Infrastructure**:
  - Shell-based `sagemake test` integrating `.sage` test files (unit/integration tests) inside `Testing/`.

## Executive Summary

This comprehensive audit of SageLink identified several critical and high-priority vulnerabilities primarily impacting the integrity and security of file transfers, identity key management, and resource allocation. While the cryptographic layer successfully implements Noise_IK and ChaCha20-Poly1305 with zero FFI, the application layer exhibits multiple flaws.

The most severe issue is an Integrity Check Bypass in the file transfer service, allowing a malicious actor to silently replace files without triggering SHA-256 validation. Additionally, there are race conditions in key generation leading to insecure file permissions, Out-Of-Memory (OOM) risks on constrained devices due to whole-file buffering, and functionality gaps preventing operation on non-Linux platforms like macOS (due to hardcoded `libc.so` assumptions).

Previous audits contained hallucinated vulnerabilities (e.g. unbounded frame length allocation, replay window unauthenticated state mutation, rekey deadlocks) which have been verified as incorrect via tracing and removed from this report. This report provides detailed findings and actionable recommendations to harden SageLink prior to production deployment.

### Top 10 Issues Ranked by Impact

1. **[Critical]** Integrity Check Bypass in FILE receive logic.
2. **[High]** Insecure Default Permissions (TOCTOU) for identity keys.
3. **[High]** Out-of-Memory (OOM) via whole-file buffering in FILE service.
4. **[High]** Excessive I/O Overhead in FILE Receiver via repeated `io.appendbytes`.
5. **[Medium]** Cross-Platform Functionality Gap in SHELL service (macOS failure).
6. **[Medium]** CPU Overhead (O(N) latency) via element-by-element list copying in transport layer.
7. **[Low]** Potential Stream ID Exhaustion via O(N) linear probe.
8. **[Informational]** Incomplete malicious file cleanup (leaves 0-byte file instead of unlinking).
9. **[Informational]** Missing input validation on chunk sizes during file streaming.
10. **[Informational]** Polling CPU overhead in stream read loops (`thread.sleep`).

---

## Repository Health Score

- Security: 4/10
- Performance: 5/10
- Reliability: 6/10
- Maintainability: 7/10
- Documentation: 9/10

---

## Security Report

### 1. Integrity Check Bypass in FILE Service
- **Severity:** Critical
- **Evidence:** In `src/app/file.sage`, the receive loop `while bytes_written < file_size:` allows an attacker to send a chunk that pushes `bytes_written` to be strictly greater than `file_size`. This causes the loop to terminate, entirely skipping the subsequent `if bytes_written == file_size:` block that performs the SHA-256 hash validation and malicious file deletion.
- **Fix Recommendation:** Modify the loop condition to account for potential overflow, check `bytes_written >= file_size`, and enforce a strict boundary check inside the loop. Ensure that any file failing the check or ending with `bytes_written > file_size` is immediately zeroed and deleted.

### 2. Insecure Default Permissions (TOCTOU) for Identity Keys
- **Severity:** High
- **Evidence:** In `src/cli/sagelink.sage:211-213` (or similar line for keygen), `io.writefile("identity.key", priv_b64 + "\n")` writes the private key with default system permissions (often 0644), followed by a `sys.shell_exec("chmod 600 identity.key")`. This creates a Time-of-Check to Time-of-Use (TOCTOU) race condition where a local attacker can read the private key before the chmod command executes.
- **Fix Recommendation:** Ensure the file is created with 0600 permissions atomically using standard system calls (`umask` or `open` with explicit mode flags) before any sensitive data is written.

---

## Performance Report

### 1. Out-of-Memory (OOM) via Whole-File Buffering
- **Bottleneck:** `io.readbytes` is used to load entire files into memory in `src/app/file.sage` (`let file_bytes = io.readbytes(local_path)`).
- **Estimated Impact:** Critical application crashes (OOM kills) on constrained embedded devices (like the targeted OrangePi RV2 or Raspberry Pi 4) when transferring large files (e.g., > 500MB).
- **Recommended Fixes:** Transition to a streaming read approach, hashing and transferring the file in smaller chunks sequentially without loading the full file into a single list.

### 2. Excessive I/O Overhead in FILE Receiver
- **Bottleneck:** In `src/app/file.sage`, `io.appendbytes(filename, chunk_data)` opens, appends, and closes the file descriptor for every 16KB chunk received.
- **Estimated Impact:** Severe throughput degradation due to thousands of repeated syscall overheads and filesystem metadata updates on large file transfers.
- **Recommended Fixes:** Keep an open file handle and use `io.write` to stream chunks to disk directly, closing the handle only upon completion.

### 3. CPU Overhead via Element-by-Element List Copying
- **Bottleneck:** Extensive use of `push()` in loops in `src/transport/framing.sage` and `src/mux/stream.sage` instead of native slice or memory block operations.
- **Estimated Impact:** O(N) CPU overhead during encryption, decryption, and message framing, severely reducing network throughput.
- **Recommended Fixes:** Leverage native memory buffer operations or bulk slice copies if supported by SageLang.

---

## Functionality Report

### Working Features
- Mutual Authentication via Noise_IK with X25519 and ChaCha20-Poly1305.
- CMD execution with accurate remote shell spawning and output capture.
- Replay Protection via a 64-entry sliding bitmap in the transport layer.
- Multiplexed Streams supporting overlapping operations on a single TCP socket.

### Broken Features
- **Cross-Platform Shell Service (macOS):** The SHELL service in `src/app/shell.sage` assumes the presence of `libc.so.6` or `libc.so`, completely breaking functionality on macOS which uses `libc.dylib` or `libSystem.dylib`.

### Missing Coverage
- Missing tests validating that maliciously oversized file chunks correctly trigger validation failures.
- Missing integration tests for the fallback of the `rekeying` logic under high load.
- No unit tests validating the failure paths of FFI system calls (e.g., `posix_openpt` returning < 0).
