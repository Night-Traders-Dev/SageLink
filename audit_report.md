# SageLink Audit Report

## Architecture Map

SageLink is organized as a strict layering of independent modules, each responsible for one concern. No module below the multiplexing layer knows about CMD, FILE, or SHELL; no module above the transport layer touches raw sockets or encryption keys.

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

**Major Subsystems & Dependencies:**
- **`utils`**: Shared byte/list conversion helpers.
- **`handshake/noise_ik`**: Implements Noise_IK handshake state machine; depends on `crypto.*` modules.
- **`transport/replay_window`**: Sliding bitmap replay protection.
- **`transport/framing`**: Wire framing and encryption/decryption; depends on `replay_window`, `utils`, `crypto.aead`.
- **`mux/stream`**: Stream multiplexing and rekeying; depends on `framing`, `noise_ik`, `utils`.
- **`app/cmd`, `app/file`, `app/shell`**: Application services.
- **`cli/sagelink`**: CLI entry point orchestrating all layers.

## Executive Summary

This comprehensive audit of SageLink identified several critical and high-priority vulnerabilities primarily impacting the integrity and security of file transfers, identity key management, and resource allocation. While the cryptographic layer successfully implements Noise_IK and ChaCha20-Poly1305 with zero FFI, the application layer exhibits multiple flaws.

The most severe issue is an Integrity Check Bypass in the file transfer service, allowing a malicious actor to silently replace files without triggering SHA-256 validation. Additionally, there are race conditions in key generation leading to insecure file permissions, Out-Of-Memory (OOM) risks on constrained devices due to whole-file buffering, and functionality gaps preventing operation on non-Linux platforms like macOS (due to hardcoded `libc.so` assumptions).

Previous audits contained hallucinated vulnerabilities (e.g., unbounded frame length allocation, replay window unauthenticated state mutation, rekey deadlocks) which have been verified as incorrect via tracing and removed from this report. This report provides detailed findings and actionable recommendations to harden SageLink prior to production deployment.

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
- **Evidence:** In `src/cli/sagelink.sage:211-213`, `io.writefile("identity.key", priv_b64 + "\n")` writes the private key with default system permissions (often 0644), followed by a `sys.shell_exec("chmod 600 identity.key")`. This creates a Time-of-Check to Time-of-Use (TOCTOU) race condition where a local attacker can read the private key before the chmod command executes.
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

### 4. Polling Loop CPU Overhead
- **Bottleneck:** Code using `thread.sleep(0.005)` in tight while loops (like waiting for stream messages in `src/mux/stream.sage` and `src/app/file.sage`).
- **Estimated Impact:** Wastes CPU cycles on embedded devices, reducing battery life and taking CPU time from other tasks.
- **Recommended Fixes:** A proper blocking condition variable or channel mechanism should be utilized instead of busy-wait polling.

---

## Functionality Report

### Working Features
- **Mutual Authentication:** Authenticates properly via Noise_IK with X25519 and ChaCha20-Poly1305.
- **CMD Execution:** Accurate remote shell spawning and output capture.
- **Replay Protection:** Replay window logic (64-entry sliding bitmap) functions correctly.
- **Multiplexed Streams:** Supports overlapping operations on a single TCP socket securely.
- **File Transfer Flow Control:** Basic sliding-window flow control ensures reliable transfer within bounded concurrency.

### Broken Features
- **Cross-Platform Shell Service (macOS):** The SHELL service in `src/app/shell.sage` assumes the presence of `libc.so.6` or `libc.so`, failing entirely on non-Linux platforms (e.g., macOS which uses `.dylib` extensions).

### Missing Coverage
- Missing tests validating that maliciously oversized file chunks correctly trigger validation failures.
- Missing integration tests for the fallback of the `rekeying` logic under high load.
- No unit tests validating the failure paths of FFI system calls (e.g., `posix_openpt` returning < 0).
