# SageLink Comprehensive Audit Report

## Architecture Map

**Major Subsystems:**
- CMD Service (`src/app/cmd.sage`): Handles remote command execution and exit code retrieval.
- FILE Service (`src/app/file.sage`): Handles chunked file transfers and SHA-256 integrity checks.
- SHELL Service (`src/app/shell.sage`): Manages interactive PTY sessions and terminal resizing.
- Stream Multiplexing (`src/mux/stream.sage`): Provides stream isolation and flow control.
- Transport Encryption (`src/transport/framing.sage`, `replay_window.sage`): ChaCha20-Poly1305 AEAD framing.
- Handshake (`src/handshake/noise_ik.sage`): Noise_IK protocol for mutual authentication.
- Command Line Interface (`src/cli/sagelink.sage`): Entry point for daemon and client connections.
- Utilities & Helpers (`src/utils.sage`): Common data transformation functions.

**Runtime Architecture:**
```text
┌─────────────────────────────────────────┐
│  Application Layer (CMD / FILE / SHELL) │  <-- Services
├─────────────────────────────────────────┤
│  Multiplexing Layer (Stream IDs)        │  <-- Flow Control
├─────────────────────────────────────────┤
│  Transport Encryption (ChaCha20 AEAD)   │  <-- Wire Framing & Replay Window
├─────────────────────────────────────────┤
│  Handshake Layer (Noise_IK X25519)      │  <-- BLAKE2s, HKDF, Static/Ephemeral Keys
├─────────────────────────────────────────┤
│  TCP Socket Layer (IPv4 / IPv6)         │  <-- Network I/O
└─────────────────────────────────────────┘
```

**External Dependencies:**
- `sagelang-lib-crypto` (loaded as `crypto` submodule for AES/ChaCha/Hash ops)
- `sagelang-lib-gc` (loaded as `sagelang-lib-gc` submodule for memory management)
- `libc` (loaded via FFI for PTY, process operations, and file I/O)
- No external FFI dependency for cryptographic operations (hand-rolled)

**Build Systems:**
- Custom unified orchestrator `sagemake` (`python3 sagemake check|test|cross-build`)

**Testing Infrastructure:**
- Custom SageLang test scripts in `Testing/` (e.g., `test_crypto.sage`, `test_handshake.sage`, `test_integration.sage`)
- CI/CD workflow testing for AOT and SageVM environments.

## Executive Summary

SageLink has been comprehensively audited for security, performance, reliability, maintainability, and functionality. The implementation adheres nicely to a clean modular architecture and successfully builds custom cryptographic primitives without external FFI dependencies. However, the audit revealed critical functionality flaws and significant security risks. Most notably, the CMD service executes side-effects twice, and hardcoded C struct offsets in the SHELL service break cross-platform compatibility. Unhandled FFI returns, process tracking leaks, and lacking DoS protections require immediate remediation before production deployment. In addition, incomplete write handling in the PTY layer poses reliability risks. Continuous monitoring of cross-platform dependencies and FFI boundaries is strongly advised. This report highlights key vulnerabilities and proposes actionable remediations.

## Top 10 Issues Ranked By Impact

1. **Unintended Double-Execution of Commands**: `app/cmd.sage` executes remote commands twice—once via `ffi_run_command()` and once via `sys.shell_exec()`—leading to duplicated side-effects.
2. **Unhandled FFI Return Values in PTY Setup**: Failing to check `ptsname_r` return values in `app/shell.sage` risks out-of-bounds memory reads on uninitialized buffers.
3. **Process / Resource Leaks**: Using `system("/bin/sh")` instead of `execve` to spawn long-running shells causes the parent to lose tracking, leading to orphaned processes because the parent cannot reliably kill the shell.
4. **Hardcoded C Struct Offsets**: `app/shell.sage` hardcodes the `winsize` offset (8 bytes), breaking cross-platform execution on systems with different layout architectures.
5. **Memory Allocation DoS Risks**: Lack of validation on payload sizes (up to 1MB allowed in `transport/framing.sage`) and unbounded queue byte sizes expose the daemon to memory exhaustion attacks.
6. **Slowloris DoS Susceptibility**: Blocking `tcp.recvall()` socket reads in the handshake and stream readers lack timeouts, making the service vulnerable to connection stagnation.
7. **File Permission TOCTOU Weaknesses**: Sensitive file creations (e.g., identity keys in CLI) lack secure atomic permission management.
8. **Synchronous DH Computation Blocking**: Heavy Diffie-Hellman calculations (`x25519` inside `read_message_1`/`write_message_2`) block the multiplexer's main reader loop, reducing overall stream concurrency.
9. **Idle CPU Waste via Polling**: Tight polling loops relying on `thread.sleep(0.005)` are used for stream reads and synchronization (e.g., awaiting rekeying), causing unnecessary CPU load.
10. **Partial Write Reliability Risk in SHELL**: `app/shell.sage` does not handle short writes when calling `ffi_call(libc, "write", ...)`, which can result in truncated terminal output under heavy load.

## Repository Health Score

- Security: 6.5/10
- Performance: 6.0/10
- Reliability: 5.5/10
- Maintainability: 7.0/10
- Documentation: 8.5/10

## Security Report

**Finding 1: Unhandled FFI return values**
- **Severity**: High
- **Evidence**: `app/shell.sage` calls `ffi_call(libc, "ptsname_r", "int", [master_fd, name_buf, 256])` without validating the integer return code before looping over `name_buf`.
- **Fix Recommendation**: Always verify the return values of FFI calls, specifically `ptsname_r`, `posix_openpt`, and check for negative error codes before buffer reads.

**Finding 2: DoS vulnerabilities (Memory/Network)**
- **Severity**: High
- **Evidence**: `transport/framing.sage` sets a maximum frame size of 1MB (`if len_val > 1048576`). Pre-authentication, attackers can exhaust memory by spamming large payloads. Furthermore, `tcp.recvall()` lacks read timeouts.
- **Fix Recommendation**: Implement read timeouts for all socket operations during the Noise_IK handshake and strictly limit pre-authentication payload sizes to a few kilobytes.

**Finding 3: Process and resource leaks**
- **Severity**: High
- **Evidence**: `app/shell.sage` spawns the interactive shell using `ffi_call(libc, "system", "int", ["/bin/sh"])`. The `kill(pid, 9)` only terminates the shell spawned by `system`, not the interactive session.
- **Fix Recommendation**: Replace the `system()` call in the SHELL service with `execve` or `execvp` so that the child process image is fully replaced, ensuring accurate PID tracking and cleanup.

**Finding 4: TOCTOU Weaknesses**
- **Severity**: Medium
- **Evidence**: The CLI tool (`cli/sagelink.sage`) creates identity keys without atomically setting restrictive file permissions (e.g., `0600`) at the exact moment of file creation.
- **Fix Recommendation**: Use secure file permission flags during the initial `open` call (e.g., `O_CREAT | O_EXCL` with mode `0600`).

**Finding 5: Authenticated O(N^2) String Concatenation DoS**
- **Severity**: Medium
- **Evidence**: `mux_reader_loop` in `src/mux/stream.sage` parses `CHAN_OPEN` frames by looping over `payload_bytes` and concatenating characters. A malicious authenticated peer can send up to a 1MB payload, resulting in extreme CPU overhead.
- **Fix Recommendation**: Enforce strict length limits on `payload_bytes` prior to reading service strings and employ efficient memory slicing instead of iterative concatenation.

**Finding 6: Unbounded Authenticated Thread Spawning**
- **Severity**: Medium
- **Evidence**: `mux_reader_loop` unconditionally executes `thread.spawn(run_cb)` for every incoming `CHAN_OPEN` request without checking active stream counts.
- **Fix Recommendation**: Introduce a thread pool, or enforce a global concurrent stream limit for authenticated peers.

## Performance Report

**Bottlenecks:**
1. **O(N^2) Array Operations:** Iteratively pushing to arrays or concatenating strings in `utils.bytes`, `utils.to_list`, and payload parsers causes high memory churn.
2. **Synchronous DH Computations:** `x25519` key exchanges block the main `mux_reader_loop` synchronously, halting all other stream processing.
3. **Busy Polling Mechanisms:** Functions like `stream_read_msg` rely on `while true` loops with `thread.sleep(0.005)` to await queue messages.
4. **Delayed Queue Compaction:** Stream queues only compact when `queue_head >= 1024`, causing memory retention spikes during heavy traffic.
5. **Inefficient Path Resolution:** Missing explicit SAGE_PATH propagation causes redundant directory traversals when resolving submodules.

**Estimated Impact:**
- Noticeable memory copying overhead and frequent garbage collection pauses during large FILE transfers.
- Severe concurrency bottlenecks when multiple peers rekey simultaneously.
- Consistently high idle CPU utilization, severely impacting battery life on embedded devices.

**Recommended Fixes:**
- Preallocate byte arrays and utilize memory slices/views rather than iterative pushing and string concatenation.
- Dispatch Diffie-Hellman handshake processing to asynchronous worker threads.
- Replace sleep-based polling with blocking condition variables or I/O signaling constructs.
- Utilize circular buffers (ring buffers) for stream queues to completely eliminate manual array compaction.

## Functionality Report

**Working Features:**
- Custom ChaCha20-Poly1305, BLAKE2s, and X25519 primitives pass RFC test vectors byte-for-byte.
- Noise_IK mutual authentication completes successfully in one round trip.
- 64-entry sliding bitmap effectively mitigates packet replay attacks.

**Broken Features:**
- **CMD Service Side-Effects**: Remote commands execute twice. `ffi_run_command(cmd)` executes the command via `system()` to capture the exit code, and then `sys.shell_exec(cmd)` executes it again to capture stdout.
- **SHELL Service Struct Layouts**: Terminal resizing logic manually builds a `winsize` struct by hardcoding 8 bytes. Padding and sizing differ heavily across architectures (e.g., Linux vs macOS).
- **CLI Keygen Execution**: Key generation fails because `sys.shell_exec` actively blocks unsafe characters like `&&`, breaking the CLI's atomic key rename (`chmod 600 ... && mv ...`).

**Missing Coverage:**
- **Partial Write Handling**: `app/shell.sage` doesn't handle short writes when writing to the PTY master, risking truncated data.
- **FD Leaks on Errors**: Mid-setup failures during PTY initialization lack proper file descriptor cleanup before returning.
- **Network Timeout Tests**: Integration tests do not validate the system's behavior against stalled or slow network connections.
- **Cross-Compilation Verification**: Dedicated integration test runners for `aarch64` and `rv64` architectures are not enforced in the standard CI pipeline.
