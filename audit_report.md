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
  - Zero FFI for cryptography; uses FFI in `app/shell.sage` (`libc`), `app/file.sage`, and `app/cmd.sage`.
- **Build System**:
  - `sagemake` Python script wrapping SageLang compiler/interpreter.
- **Testing Infrastructure**:
  - Shell-based `sagemake test` integrating `.sage` test files inside `Testing/`.

## Executive Summary

This comprehensive audit of SageLink identified several vulnerabilities primarily impacting identity key management, command execution, and CPU performance. The core cryptography layer implements Noise_IK and ChaCha20-Poly1305 correctly. The development team has successfully mitigated many critical issues previously identified (e.g., Unbounded Unauthenticated Thread Spawn, IPv6 parsing failures, Integrity Check Bypass in file transfers, and Out-of-Memory risks from whole-file buffering).

The most critical remaining findings include an insecure default permission generation process for identity keys via a TOCTOU race condition, and a double-execution bug in the CMD service that could lead to unintended remote side-effects.

This report provides detailed findings and actionable recommendations to harden SageLink prior to production deployment.

## Top 10 issues ranked by impact

1. **[High]** Insecure Default Permissions (TOCTOU) for identity keys.
2. **[High]** Double Execution of Commands in CMD service.
3. **[Medium]** Unbounded Thread Spawn for Authenticated Clients.
4. **[Medium]** Polling Loop CPU Overhead in stream reading.
5. **[Medium]** O(N) Array Operations (List Copying) Overhead.
6. **[Low]** Linear Probe for Stream IDs allocation.

## Repository Health Score

- Security: 7/10
- Performance: 7/10
- Reliability: 8/10
- Maintainability: 8/10
- Documentation: 9/10

---

## Security Report

### 1. Insecure Default Permissions (TOCTOU) for Identity Keys
- **Severity:** High
- **Findings / Evidence:** In `src/cli/sagelink.sage`, `io.writefile(tmp_key, priv_b64 + "\n")` writes the private key with default system permissions, followed by a `sys.shell_exec("chmod 600 " + tmp_key + " && mv ...")`. This creates a Time-of-Check to Time-of-Use (TOCTOU) race condition where a local attacker can read the private key before the `chmod` command executes.
- **Fix Recommendation:** Ensure the file is created with 0600 permissions atomically using standard system calls (`umask` or `open` with explicit mode flags) before any sensitive data is written.

### 2. Double Execution of Commands
- **Severity:** High
- **Findings / Evidence:** In `src/app/cmd.sage`, `handle_cmd_stream` executes the command string twice. First, it runs `ffi_run_command(cmd)` to capture the exit code via `system()`. Then, it runs `sys.shell_exec(cmd)` to capture the standard output. This can lead to unintended side-effects on the host system (e.g., if a command modifies state or deletes files, it will run twice).
- **Fix Recommendation:** Use `popen` or a similar construct via FFI to execute the command exactly once, capturing both the standard output and the exit code simultaneously.

### 3. Unbounded Thread Spawn for Authenticated Clients
- **Severity:** Medium
- **Findings / Evidence:** In `src/cli/sagelink.sage`, the `server_stream_dispatcher` spawns threads without limits for authenticated peers (`thread.spawn(run_cmd)`, `thread.spawn(run_file)`, `thread.spawn(run_shell)`). While unauthenticated connections are now bounded, an authenticated peer could still cause resource exhaustion by opening thousands of concurrent streams.
- **Fix Recommendation:** Implement a maximum limit on concurrent open streams per connection.

---

## Performance Report

### 1. Polling Loop CPU Overhead
- **Bottlenecks:** `stream_read_msg` relies on a tight polling loop `while true: ... thread.sleep(0.005)` in `src/mux/stream.sage`. Similar loops exist for rekeying state checks.
- **Estimated Impact:** Constant CPU utilization on embedded devices even when idle, leading to increased power consumption and thermal load.
- **Recommended Fixes:** Implement a blocking channel or condition variable mechanism for stream message reading to yield the CPU entirely when no messages are pending.

### 2. O(N) Array Operations (List Copying) Overhead
- **Bottlenecks:** Extensive use of element-by-element list copying (e.g. `push()` in loops) instead of native memory operations is prevalent in `src/transport/framing.sage` and payload serialization.
- **Estimated Impact:** High CPU usage and decreased throughput for large messages due to O(N) element-wise operations.
- **Recommended Fixes:** Use native slice operations or memory copy utilities where possible to manipulate byte buffers.

### 3. Linear Probe for Stream IDs
- **Bottlenecks:** `mux_open_stream` in `src/mux/stream.sage` checks up to 65536 stream IDs sequentially in a while loop.
- **Estimated Impact:** O(N) degraded stream opening times when many streams are concurrently opened.
- **Recommended Fixes:** Implement an efficient ID allocator such as a free-list or a bitmap to quickly find unused stream IDs.

---

## Functionality Report

### Working Features
- Mutual Authentication via Noise_IK with X25519 and ChaCha20-Poly1305.
- CMD execution with remote shell spawning and output capture.
- Replay Protection via a 64-entry sliding bitmap in the transport layer.
- Multiplexed Streams supporting overlapping operations on a single TCP socket.
- Cross-platform SHELL compatibility logic (macOS and Linux).
- FILE transfers with streaming memory buffers to prevent OOM.

### Broken Features
- None identified in this review cycle.

### Missing Coverage
- Missing tests validating that maliciously oversized file chunks correctly trigger validation failures.
- Missing integration tests for the fallback of the `rekeying` logic under high load.
- No unit tests validating the failure paths of FFI system calls (e.g., `posix_openpt` returning < 0).