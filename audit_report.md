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

This comprehensive audit of SageLink identified several critical and high-priority vulnerabilities primarily impacting the integrity and security of file transfers, identity key management, resource allocation, and shell execution. While the cryptographic layer successfully implements Noise_IK and ChaCha20-Poly1305 with zero FFI, the application and connection handling layers exhibit multiple flaws.

The most severe issues include an Integrity Check Bypass in the file transfer service allowing malicious replacement of files, an Unbounded Thread Spawn vulnerability leading to unauthenticated thread exhaustion, and an Unbounded Stream Queue that could cause out-of-memory (OOM) via memory exhaustion on authenticated streams. Additionally, insecure default permissions on generated key files leave them vulnerable to local attackers via a TOCTOU race condition.

Functionality and performance issues were also discovered, including hardcoded OS-specific values that break cross-platform support (such as IPv6 parsing and macOS compatibility), and excessive I/O and memory usage when handling large files.

This report provides detailed findings and actionable recommendations to harden SageLink prior to production deployment.

### Top 10 Issues Ranked by Impact

1. **[Critical]** Integrity Check Bypass in FILE receive logic.
2. **[Critical]** Unbounded Thread Spawn (Unauthenticated Thread Exhaustion) in CLI listener.
3. **[Critical]** Unbounded Stream Queue (Memory Exhaustion) in stream multiplexer.
4. **[High]** Insecure Default Permissions (TOCTOU) for identity keys.
5. **[High]** Out-of-Memory (OOM) via whole-file buffering in FILE service.
6. **[High]** Excessive I/O Overhead in FILE Receiver via repeated `io.appendbytes`.
7. **[Medium]** IPv6 Address Parsing Failure in CLI connection logic.
8. **[Medium]** Hardcoded Exit Code masks actual failures in CMD service.
9. **[Medium]** Cross-Platform Functionality Gap in SHELL service (macOS failure) and Hardcoded IOCTL values.
10. **[Medium]** CPU Overhead (O(N) latency) via element-by-element list copying in transport layer.

---

## Repository Health Score

- Security: 3/10
- Performance: 4/10
- Reliability: 4/10
- Maintainability: 7/10
- Documentation: 9/10

---

## Security Report

### 1. Integrity Check Bypass in FILE Service
- **Severity:** Critical
- **Evidence:** In `src/app/file.sage`, the receive loop `while bytes_written < file_size:` allows an attacker to send a chunk that pushes `bytes_written` to be strictly greater than `file_size`. This causes the loop to terminate, entirely skipping the subsequent `if bytes_written == file_size:` block that performs the SHA-256 hash validation and malicious file deletion.
- **Fix Recommendation:** Modify the loop condition to account for potential overflow, check `bytes_written >= file_size`, and enforce a strict boundary check inside the loop. Ensure that any file failing the check or ending with `bytes_written > file_size` is immediately zeroed and deleted.

### 2. Unbounded Thread Spawn (Unauthenticated Thread Exhaustion) in CLI Listener
- **Severity:** Critical
- **Evidence:** In `src/cli/sagelink.sage:369`, `tcp.accept()` triggers `thread.spawn(handle_client)` without any rate limiting, queueing, or maximum connection limit. An unauthenticated attacker can rapidly open TCP connections, causing the SageLang runtime to exhaust system threads or memory (Slowloris/DoS), even before the Noise_IK handshake begins.
- **Fix Recommendation:** Implement a bounded thread pool or strict connection limits (e.g., maximum 10 concurrent unauthenticated handshake attempts) before spawning handler threads.

### 3. Unbounded Stream Queue (Memory Exhaustion)
- **Severity:** Critical
- **Evidence:** In `src/mux/stream.sage`, inside `mux_reader_loop`, incoming messages are added to a stream's queue (`push(stream["queue"], ...)`) with no maximum bounds checking. A malicious or misconfigured peer can flood the receiver with messages, exhausting the process memory if the receiving thread is slower to consume them.
- **Fix Recommendation:** Implement backpressure or a strict capacity limit on stream queues. If the queue hits the limit, either drop messages or halt reading from the transport socket until the queue is drained.

### 4. Insecure Default Permissions (TOCTOU) for Identity Keys
- **Severity:** High
- **Evidence:** In `src/cli/sagelink.sage`, `io.writefile("identity.key", priv_b64 + "\n")` writes the private key with default system permissions (often 0644), followed by a `sys.shell_exec("chmod 600 identity.key")`. This creates a Time-of-Check to Time-of-Use (TOCTOU) race condition where a local attacker can read the private key before the chmod command executes.
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
- **Cross-Platform Shell Service (macOS):** The SHELL service in `src/app/shell.sage` assumes the presence of `libc.so.6` or `libc.so`, breaking functionality on macOS which uses `libc.dylib` or `libSystem.dylib`.
- **Hardcoded IOCTL Values:** The SHELL service uses hardcoded integer values for platform-specific IOCTLs (e.g. `TIOCSCTTY = 21518`, `TIOCSWINSZ = 21524` in `src/app/shell.sage`), preventing correct terminal handling across different operating systems or architectures.
- **IPv6 Address Parsing Failure:** In `src/cli/sagelink.sage`, `parse_addr` unconditionally searches for the first colon `:` to separate host and port, breaking support for IPv6 addresses.
- **Hardcoded CMD Exit Code:** In `src/app/cmd.sage`, the command handler always returns a hardcoded exit code of `0` (`let resp = [0]`) regardless of the actual command's execution success, masking remote errors from the client.

### Missing Coverage
- Missing tests validating that maliciously oversized file chunks correctly trigger validation failures.
- Missing integration tests for the fallback of the `rekeying` logic under high load.
- No unit tests validating the failure paths of FFI system calls (e.g., `posix_openpt` returning < 0).
