# SageLink Comprehensive Audit Report

## Architecture Map

**Major Subsystems:**
- CMD Service (`src/app/cmd.sage`)
- FILE Service (`src/app/file.sage`)
- SHELL Service (`src/app/shell.sage`)
- Stream Multiplexing (`src/mux/stream.sage`)
- Transport Encryption (`src/transport/framing.sage`, `replay_window.sage`)
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

SageLink has been comprehensively audited for security, performance, reliability, maintainability, and functionality. The implementation adheres nicely to a clean modular architecture and successfully builds custom cryptographic primitives without external FFI dependencies. However, the audit revealed critical functionality flaws and significant security risks. Most notably, the CMD service executes side-effects twice, and hardcoded C struct offsets in the SHELL service break cross-platform compatibility. Unhandled FFI returns, process tracking leaks, and lacking DoS protections require immediate remediation before production deployment.

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
10. **O(N^2) Array Operations**: Frequent list copying and string concatenations in byte manipulations (e.g., `transport/framing.sage` and `utils.sage`) incur heavy algorithmic overhead.

## Repository Health Score

- Security: 6/10
- Performance: 5/10
- Reliability: 5/10
- Maintainability: 7/10
- Documentation: 8/10

## Security Report

**Finding 1: Unhandled FFI return values**
- **Severity**: High
- **Evidence**: `app/shell.sage` (line ~104) calls `ffi_call(libc, "ptsname_r", "int", [master_fd, name_buf, 256])` but does not check the return value. It then immediately loops `while true` reading `name_buf` until a null byte is found:
  ```
  ffi_call(libc, "ptsname_r", "int", [master_fd, name_buf, 256])
  let slave_name = ""
  let idx = 0
  while true:
      let char_val = mem_read(name_buf, idx, "byte")
      ...
  ```
  This can lead to out-of-bounds reads if `ptsname_r` fails.
- **Fix Recommendation**: Always check the return values of FFI calls, specifically `ptsname_r` and `posix_openpt`.

**Finding 2: DoS vulnerabilities (Memory/Network)**
- **Severity**: High
- **Evidence**: `transport/framing.sage` (line ~81) sets a maximum frame size of 1MB: `if len_val > 1048576: # 1MB limit`. Before authentication is completed, an attacker can spam large payloads. Additionally, `tcp.recvall()` in `noise_ik` and `framing` blocks indefinitely without a timeout.
- **Fix Recommendation**: Implement global read timeouts for `tcp.recvall` during the handshake and limit pre-authentication payload sizes.

**Finding 3: Process and resource leaks**
- **Severity**: High
- **Evidence**: `app/shell.sage` (line ~146) spawns the interactive shell via: `ffi_call(libc, "system", "int", ["/bin/sh"])`. The `system()` call spawns a sub-shell which then executes `/bin/sh`. The parent's `kill(pid, 9)` only kills the intermediate shell, leaving the actual `/bin/sh` orphaned.
- **Fix Recommendation**: Replace the `system()` call in the SHELL service with `execve` (or equivalent) so that the child process image is replaced and the PID exactly matches the interactive shell.

**Finding 4: TOCTOU Weaknesses**
- **Severity**: Medium
- **Evidence**: The CLI tool (`cli/sagelink.sage`) creates sensitive files without atomically setting restrictive file permissions (e.g., `0600`) at the moment of creation.
- **Fix Recommendation**: Utilize secure file permission flags during `open` (e.g., `O_CREAT | O_EXCL` with mode `0600`).

**Finding 5: Unauthenticated Network Data Processing**
- **Severity**: Medium
- **Evidence**: `mux_reader_loop` in `src/mux/stream.sage` processes unauthenticated frames (e.g. `CHAN_OPEN` length reading logic) without bounded restrictions on the service string loop length.
- **Fix Recommendation**: Apply strict bounds checking on `len(payload_bytes)` before reading service strings.

**Finding 6: Hardcoded IOCTLs Crossing OS Boundaries**
- **Severity**: Low
- **Evidence**: `get_ioctl_ctty` and `get_ioctl_winsz` in `app/shell.sage` rely on OS uname but are brittle to kernel version changes or differing architectures.
- **Fix Recommendation**: Expose IOCTLs properly through a platform-specific C binding or FFI header extraction script.

**Finding 7: File Clean-Up Failures**
- **Severity**: Low
- **Evidence**: In `app/file.sage`, on stream close during partial transfer, the target file is not always deleted if `bytes_written < file_size` and the connection drops.
- **Fix Recommendation**: Implement an `on_close` hook or structured error handling to delete partial downloads.

**Finding 8: Unbounded Thread Spawning**
- **Severity**: High
- **Evidence**: `sagelink/cli/sagelink.sage` spawns a thread (`thread.spawn(handle_client)`) unconditionally for every accepted socket before handshake.
- **Fix Recommendation**: Introduce a thread pool or global connection limit.

**Finding 9: Predictable Randomness Check**
- **Severity**: Low
- **Evidence**: No verification that `/dev/urandom` successfully returns high-entropy data inside `rand.sage` (relies completely on underlying OS without fallback).
- **Fix Recommendation**: Check `/dev/urandom` return codes thoroughly.

**Finding 10: Incomplete Submodule Init Security**
- **Severity**: Informational
- **Evidence**: Relying on external cloned submodules introduces a supply chain surface area if not pinned to specific hashes.
- **Fix Recommendation**: Document submodule hashes in build steps.

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
- **CMD Service**: Remote commands execute twice. In `app/cmd.sage` (lines 53-56):
  ```
  let result = ffi_run_command(cmd)
  let output = sys.shell_exec(cmd)
  ```
  `ffi_run_command(cmd)` executes the command to capture the exit code via `system()`, and immediately after, `sys.shell_exec(cmd)` executes the same command again to capture standard output. This causes side-effects (e.g., `mkdir`, `rm`) to run twice.
- **SHELL Service**: Resizing logic in `app/shell.sage` manually populates a `winsize` struct by hardcoding 8 bytes:
  ```
  let ws = mem_alloc(8)
  mem_write(ws, 0, "byte", rows & 255)
  ...
  ```
  This breaks cross-platform compatibility because struct layouts and padding vary between architectures.

**Missing Coverage:**
- PTY file descriptor leaks: Error handling on mid-setup PTY operations in `handle_shell_stream` is incomplete; if an intermediate step fails, file descriptors might leak before cleanup occurs.
- Network timeouts are entirely missing from integration tests.
