# SageLink Comprehensive Audit Report

## Architecture Map

**Major Subsystems:**
- CMD Service (`src/app/cmd.sage`)
- FILE Service (`src/app/file.sage`)
- SHELL Service (`src/app/shell.sage`)
- Stream Multiplexing (`src/mux/stream.sage`)
- Transport Encryption (`src/transport/framing.sage`, `src/transport/replay_window.sage`)
- Handshake (`src/handshake/noise_ik.sage`)
- Command Line Interface (`src/cli/sagelink.sage`)

**Runtime Architecture:**
```text
┌─────────────────────────────────────────┐
│  Application Layer (CMD / FILE / SHELL) │
├─────────────────────────────────────────┤
│  Multiplexing Layer                     │
├─────────────────────────────────────────┤
│  Transport Encryption Layer             │
├─────────────────────────────────────────┤
│  Handshake Layer (Noise_IK)             │
├─────────────────────────────────────────┤
│  TCP Socket Layer                       │
└─────────────────────────────────────────┘
```

**External Dependencies:**
- `sagelang-lib-crypto` (loaded as `crypto` submodule)
- `libc` (loaded via FFI for PTY and process operations)
- No external FFI dependency for cryptographic operations (hand-rolled)

**Build Systems:**
- Custom unified orchestrator `sagemake` (`python3 sagemake check|test|cross-build`)

**Testing Infrastructure:**
- Custom SageLang test scripts in `Testing/` (e.g., `test_crypto.sage`, `test_handshake.sage`, `test_integration.sage`)

## Executive Summary

SageLink has been comprehensively audited for security, performance, reliability, maintainability, and functionality. The implementation adheres nicely to a clean modular architecture and successfully builds custom cryptographic primitives without external FFI dependencies. However, the audit revealed critical functionality flaws and significant security risks. Most notably, the CMD service executes side-effects twice, and hardcoded C struct offsets in the SHELL service break cross-platform compatibility. Unhandled FFI returns, process tracking leaks, unbounded thread spawning, and lacking DoS protections require immediate remediation before production deployment.

## Top 10 Issues Ranked By Impact

1. **Unintended Double-Execution of Commands**: `app/cmd.sage` executes remote commands twice—once via `ffi_run_command()` and once via `sys.shell_exec()`—leading to duplicated side-effects.
2. **Unhandled FFI Return Values in PTY Setup**: Failing to check `ptsname_r` return values in `app/shell.sage` risks out-of-bounds memory reads on uninitialized buffers.
3. **Process / Resource Leaks**: Using `system("/bin/sh")` instead of `execve` to spawn long-running shells causes the parent to lose tracking, leading to orphaned processes because the parent cannot reliably kill the shell.
4. **Hardcoded C Struct Offsets**: `app/shell.sage` hardcodes the `winsize` offset (8 bytes), breaking cross-platform execution on systems with different layout architectures.
5. **Memory Allocation DoS Risks**: Lack of validation on payload sizes (up to 1MB allowed in `transport/framing.sage`) and unbounded queue byte sizes expose the daemon to memory exhaustion attacks.
6. **Slowloris DoS Susceptibility**: Blocking `tcp.recvall()` socket reads in the handshake and stream readers lack timeouts, making the service vulnerable to connection stagnation.
7. **Unbounded Authenticated Thread Spawning**: `mux_reader_loop` spawns a new thread for every `CHAN_OPEN` request without a global connection limit, leading to resource exhaustion.
8. **File Permission TOCTOU Weaknesses**: Sensitive file creations (e.g., identity keys in CLI) lack secure atomic permission management.
9. **Synchronous DH Computation Blocking**: Heavy Diffie-Hellman calculations block the multiplexer's main reader loop, reducing overall stream concurrency.
10. **O(N^2) Array Operations**: Frequent list copying and string concatenations in byte manipulations (e.g., `transport/framing.sage` and `utils.sage`) incur heavy algorithmic overhead and CPU exhaustion DoS.

## Repository Health Score

- Security: 6/10
- Performance: 5/10
- Reliability: 5/10
- Maintainability: 7/10
- Documentation: 8/10

## Security Report

**Finding 1: Unhandled FFI return values**
- **Severity**: High
- **Evidence**: `app/shell.sage` calls `ffi_call(libc, "ptsname_r", "int", [master_fd, name_buf, 256])` but does not check the return value. It then immediately loops `while true` reading `name_buf` until a null byte is found. This can lead to out-of-bounds reads if `ptsname_r` fails.
- **Fix Recommendation**: Always check the return values of FFI calls, specifically `ptsname_r` and `posix_openpt`.

**Finding 2: DoS vulnerabilities (Memory/Network)**
- **Severity**: High
- **Evidence**: `transport/framing.sage` sets a maximum frame size of 1MB. Before authentication is completed, an attacker can spam large payloads. Additionally, `tcp.recvall()` in `noise_ik` and `framing` blocks indefinitely without a timeout.
- **Fix Recommendation**: Implement global read timeouts for `tcp.recvall` during the handshake and limit pre-authentication payload sizes.

**Finding 3: Process and resource leaks**
- **Severity**: High
- **Evidence**: `app/shell.sage` spawns the interactive shell via: `ffi_call(libc, "system", "int", ["/bin/sh"])`. The parent's `kill(pid, 9)` only kills the intermediate shell, leaving the actual `/bin/sh` orphaned.
- **Fix Recommendation**: Replace the `system()` call in the SHELL service with `execve` (or equivalent) so that the child process image is replaced and the PID exactly matches the interactive shell.

**Finding 4: Unbounded Authenticated Thread Spawning**
- **Severity**: High
- **Evidence**: `mux_reader_loop` in `src/mux/stream.sage` spawns a thread unconditionally for every `CHAN_OPEN` request received from an authenticated peer, without bounding the number of concurrent active streams or threads.
- **Fix Recommendation**: Introduce a thread pool or global stream/connection limit for authenticated stream dispatches.

**Finding 5: Authenticated O(N^2) String Concatenation DoS**
- **Severity**: Medium
- **Evidence**: `mux_reader_loop` in `src/mux/stream.sage` processes `CHAN_OPEN` frames by looping over `payload_bytes` and concatenating characters. An excessively large `CHAN_OPEN` payload (up to 1MB allowed by framing) causes extreme O(N^2) string concatenation overhead, leading to CPU exhaustion.
- **Fix Recommendation**: Apply strict bounds checking on `len(payload_bytes)` before reading service strings and avoid O(N^2) string building.

**Finding 6: TOCTOU Weaknesses**
- **Severity**: Medium
- **Evidence**: The CLI tool (`cli/sagelink.sage`) creates sensitive files without atomically setting restrictive file permissions (e.g., `0600`) at the moment of creation.
- **Fix Recommendation**: Utilize secure file permission flags during `open` (e.g., `O_CREAT | O_EXCL` with mode `0600`).

**Finding 7: Hardcoded IOCTLs Crossing OS Boundaries**
- **Severity**: Low
- **Evidence**: `get_ioctl_ctty` and `get_ioctl_winsz` in `app/shell.sage` rely on OS uname but are brittle to kernel version changes or differing architectures.
- **Fix Recommendation**: Expose IOCTLs properly through a platform-specific C binding or FFI header extraction script.

**Finding 8: File Clean-Up Failures**
- **Severity**: Low
- **Evidence**: In `app/file.sage`, on stream close during partial transfer, the target file is not always deleted if `bytes_written < file_size` and the connection drops.
- **Fix Recommendation**: Implement an `on_close` hook or structured error handling to delete partial downloads.

## Performance Report

**Bottlenecks:**
1. **O(N^2) Array Operations:** Iteratively pushing to arrays or concatenating strings in `utils.bytes`, `utils.to_list`, and `framing.sage`.
2. **Synchronous DH Computations:** `x25519` key exchanges run synchronously within the `mux_reader_loop`, blocking all other stream processing.
3. **Busy Polling:** `stream_read_msg` uses `while true` loops with `thread.sleep(0.005)` to wait for queue messages.
4. **Delayed Garbage Collection/Compaction:** Stream queues only compact when `queue_head >= 1024`, holding onto memory longer than necessary.

**Estimated Impact:**
- Excessive memory copying and garbage collection pauses during large file transfers.
- Severe concurrency drops when rekeying or authenticating multiple peers simultaneously.
- High idle CPU utilization (especially critical on embedded target hardware).

**Recommended Fixes:**
- Preallocate arrays based on known sizes and use memory slicing/views instead of iterative pushing.
- Offload Diffie-Hellman handshake logic to asynchronous worker threads.
- Implement condition variables or blocking I/O signaling instead of sleep-based polling.
- Implement circular buffers for stream queues to avoid manual array compaction.

## Functionality Report

**Working Features:**
- Hand-rolled ChaCha20-Poly1305, BLAKE2s, X25519 primitives correctly adhere to RFC tests (verified via `Testing/test_crypto.sage`).
- Single-round trip Noise_IK mutual authentication.
- Sliding 64-entry bitmap replay protection works accurately.

**Broken Features:**
- **CMD Service**: Remote commands execute twice. In `app/cmd.sage`, `ffi_run_command(cmd)` executes the command to capture the exit code via `system()`, and immediately after, `sys.shell_exec(cmd)` executes the same command again to capture standard output. This causes side-effects (e.g., `mkdir`, `rm`) to run twice.
- **SHELL Service**: Resizing logic in `app/shell.sage` manually populates a `winsize` struct by hardcoding 8 bytes. This breaks cross-platform compatibility because struct layouts and padding vary between architectures.

**Missing Coverage:**
- PTY file descriptor leaks: Error handling on mid-setup PTY operations in `handle_shell_stream` is incomplete; if an intermediate step fails, file descriptors might leak before cleanup occurs.
- Network timeouts are entirely missing from integration tests.
