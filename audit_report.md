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
  - Zero FFI for cryptography; uses FFI in `app/shell.sage` (`libc`), `app/file.sage` and `app/cmd.sage`.
- **Build System**:
  - `sagemake` Python script wrapping SageLang compiler/interpreter.
- **Testing Infrastructure**:
  - Shell-based `sagemake test` integrating `.sage` test files inside `Testing/`.

## Executive Summary

This comprehensive LinkGuard audit of SageLink identified several vulnerabilities primarily impacting memory management, file permissions, cross-platform compatibility, and CPU performance. The core cryptography layer implements Noise_IK and ChaCha20-Poly1305 correctly, and many critical issues from previous iterations have been resolved.

However, the current implementation suffers from significant resource exhaustion vectors. Specifically, unbounded string concatenation of unvalidated payloads and uncontrolled thread spawning for authenticated streams expose the system to severe Denial of Service (DoS) risks. Furthermore, process leaks in the shell service and double execution in the CMD service lead to resource exhaustion and unintended side-effects on the host system. The hardcoding of C struct offsets introduces severe cross-platform compatibility issues, notably during `fstat` and `winsize` calculations. Lack of timeouts in the handshake and stream reading also exposes the service to Slowloris-style denial-of-service attacks.

This report provides detailed findings and actionable recommendations to harden SageLink prior to production deployment. All reported issues are firmly grounded in tracing the actual code implementation.

## Top 10 issues ranked by impact

1. **[Critical] OOM / DoS via Unvalidated Service Type String Concatenation**: In `src/mux/stream.sage`, an incoming `CHAN_OPEN` request processes up to 1MB payloads by concatenating characters in a loop, leading to O(N^2) allocations.
2. **[Critical] OOM / DoS via Unbounded Memory Allocation in File/Shell Transfers**: In `src/app/file.sage` and `src/app/shell.sage`, memory is blindly allocated up to 1MB based on chunk sizes.
3. **[High] Shell Process Leak (Orphan/Zombie) due to `system('/bin/sh')`**: The `system()` call spawns an intermediate shell, causing process/resource leaks on the host when killed.
4. **[High] OOB Memory Read in PTY Name Resolution**: Ignoring `ptsname_r` return code leads to a crash when iterating over uninitialized `name_buf`.
5. **[High] Double Execution of Commands**: In CMD service, `handle_cmd_stream` executes commands twice via `system()` and `sys.shell_exec`.
6. **[High] Insecure Default Permissions (TOCTOU) for Identity Keys**: The private key is temporarily written with default permissions before changing it to `0600`.
7. **[High] Cross-Platform Breakage via Hardcoded Struct Offsets**: `mem_read(stat_buf, 48, "u64")` assumes `st_size` offset is 48, breaking compatibility.
8. **[Medium] Unbounded Thread Spawn for Authenticated Clients**: Streams spawn unbounded threads (e.g. `thread.spawn(run_cmd)`).
9. **[Medium] DoS via Lack of Network Timeouts**: Using indefinite network wait (`tcp.recvall` indefinitely) allows for Slowloris-style attacks.
10. **[Medium] OOM / DoS via Stream Queue Message Accumulation**: Stream messages are unbounded in byte size, storing up to 1GB per stream in memory.

## Repository Health Score

- Security: 5/10
- Performance: 4/10
- Reliability: 4/10
- Maintainability: 7/10
- Documentation: 9/10

---

## Security Report

### 1. OOM / DoS via Unvalidated Service Type String Concatenation
- **Findings**: In `src/mux/stream.sage` within `mux_reader_loop`, an incoming `CHAN_OPEN` request reads `payload_bytes` up to the transport frame size (1MB). It then iteratively builds a string via `service_type = service_type + chr(payload_bytes[i])`. Concatenating a 1MB string character-by-character can cause O(N^2) allocations, leading to extreme memory and CPU exhaustion.
- **Severity**: Critical
- **Evidence**: `src/mux/stream.sage` line ~260 - `for i in range(len(payload_bytes)): service_type = service_type + chr(payload_bytes[i])`
- **Fix recommendation**: Validate that the `len(payload_bytes)` is within expected bounds (e.g., less than 32 bytes) before iterating.

### 2. OOM / DoS via Unbounded Memory Allocation in File/Shell Transfers
- **Findings**: In `src/app/file.sage` (`handle_file_stream`) and `src/app/shell.sage` (`handle_shell_stream`), `mem_alloc(len(chunk_data))` and `mem_alloc(count)` are called based on the size of the incoming payload, up to 1MB. This can exhaust heap memory rapidly if multiple streams receive large frames simultaneously.
- **Severity**: Critical
- **Evidence**: `src/app/file.sage` line ~292 (`let write_buf = mem_alloc(len(chunk_data))`) and `src/app/shell.sage` line ~156 (`let write_buf = mem_alloc(count)`).
- **Fix recommendation**: Limit chunk size bounds strictly or process writes in fixed-size internal buffers rather than allocating memory matching the incoming network frame.

### 3. Shell Process Leak (Orphan/Zombie) due to `system('/bin/sh')`
- **Findings**: In `src/app/shell.sage`, the child process executing the shell uses `ffi_call(libc, "system", "int", ["/bin/sh"])` instead of `exec`. Because `system()` forks a new process to run the shell, when the parent later cleans up the session using `ffi_call(libc, "kill", "int", [pid, 9])`, it only kills the intermediate child process. The actual `/bin/sh` process is orphaned and left running, causing a severe process/resource leak on the host system.
- **Severity**: High
- **Evidence**: `src/app/shell.sage` line ~128 - `ffi_call(libc, "system", "int", ["/bin/sh"])`
- **Fix recommendation**: Replace the `system()` call with an `exec` family function (e.g., `execl("/bin/sh", "sh", NULL)`) so the shell replaces the child process, allowing the parent's `kill` signal to correctly terminate the shell.

### 4. OOB Memory Read in PTY Name Resolution
- **Findings**: In `src/app/shell.sage`, the return value of `ffi_call(libc, "ptsname_r", "int", [master_fd, name_buf, 256])` is ignored. If `ptsname_r` fails, the `name_buf` is uninitialized, but the subsequent `while true` loop unconditionally iterates using `mem_read` until it finds a null byte. This can lead to an out-of-bounds (OOB) memory read and a crash.
- **Severity**: High
- **Evidence**: `src/app/shell.sage` line ~94 - return value of `ptsname_r` is not checked before iterating over `name_buf`.
- **Fix recommendation**: Check the return value of `ptsname_r` before iterating over `name_buf`. If it returns a non-zero error code, handle the failure appropriately and close the stream.

### 5. Double Execution of Commands
- **Findings**: In `src/app/cmd.sage`, `handle_cmd_stream` executes the command string twice. First, it runs `ffi_run_command(cmd)` to capture the exit code via `system()`. Then, it runs `sys.shell_exec(cmd)` to capture the standard output. This leads to unintended side-effects on the host system, executing mutating commands twice.
- **Severity**: High
- **Evidence**: `src/app/cmd.sage` lines ~82-85 - calls both `ffi_run_command(cmd)` and `sys.shell_exec(cmd)`.
- **Fix recommendation**: Use a unified approach (e.g., pipe/popen) to capture both the output and the exit code from a single execution instance.

### 6. Insecure Default Permissions (TOCTOU) for Identity Keys
- **Findings**: In `src/cli/sagelink.sage`, `io.writefile(tmp_key, priv_b64 + "\n")` writes the private key with default system permissions, followed by a `sys.shell_exec("chmod 600 " + tmp_key + " && mv ...")`. This creates a Time-of-Check to Time-of-Use (TOCTOU) race condition where a local attacker can read the private key.
- **Severity**: High
- **Evidence**: `src/cli/sagelink.sage` - `io.writefile(tmp_key, priv_b64 + "\n")` followed by `sys.shell_exec("chmod 600 ...")`.
- **Fix recommendation**: Ensure the file is created with 0600 permissions atomically using standard system calls (`umask` or `open` with explicit mode flags) before any sensitive data is written.

### 7. Cross-Platform Breakage via Hardcoded Struct Offsets
- **Findings**: In `src/app/file.sage`, `mem_read(stat_buf, 48, "u64")` assumes `st_size` is at offset 48, which is only valid on Linux x86_64, causing incorrect file size readings on other platforms (e.g., macOS or ARM64). Similarly, in `src/app/shell.sage`, the `winsize` struct manipulation relies on a hardcoded 8-byte format.
- **Severity**: High
- **Evidence**: `src/app/file.sage` line ~62 - `mem_read(stat_buf, 48, "u64")`. `src/app/shell.sage` line ~169 - hardcoded 8-byte format.
- **Fix recommendation**: Use cross-platform libraries or calculate offsets dynamically using C headers.

### 8. Unbounded Thread Spawn for Authenticated Clients
- **Findings**: In `src/cli/sagelink.sage`, the `server_stream_dispatcher` spawns threads without limits for authenticated peers (`thread.spawn(run_cmd)`, `thread.spawn(run_file)`, `thread.spawn(run_shell)`). An authenticated peer could maliciously open thousands of concurrent streams, causing resource exhaustion.
- **Severity**: Medium
- **Evidence**: `src/cli/sagelink.sage` - unconditional `thread.spawn` for each incoming connection type.
- **Fix recommendation**: Implement a maximum limit on concurrent open streams per authenticated connection.

### 9. DoS via Lack of Network Timeouts
- **Findings**: In `src/cli/sagelink.sage` and `src/mux/stream.sage`, network operations such as `tcp.recvall` wait indefinitely. This allows an attacker to open connections and hold them open without sending data, exhausting the connection pool and worker threads (Slowloris attack).
- **Severity**: Medium
- **Evidence**: Use of `tcp.recvall(..., true)` without timeouts in multiple places.
- **Fix recommendation**: Implement read and write timeouts on the TCP sockets to disconnect idle or slow peers.

### 10. OOM / DoS via Stream Queue Message Accumulation
- **Findings**: In `src/mux/stream.sage`, each stream restricts queue depth via `max_queue_size = 1000`. However, the messages are completely unbounded in byte size (up to 1MB each). An attacker can easily store 1GB (1000 * 1MB) of data in memory per stream, leading to OOM.
- **Severity**: Medium
- **Evidence**: `src/mux/stream.sage` line ~166 - limits by queue element count rather than memory footprint.
- **Fix recommendation**: Implement backpressure or rate limiting based on total bytes in the queue, not just the raw message count.

---

## Performance Report

### 1. Polling Loop CPU Overhead
- **Bottlenecks**: Tight polling loops utilizing `while true: ... thread.sleep(0.005)` exist in `src/mux/stream.sage` (e.g., `stream_read_msg` and verifying `rekeying` locks).
- **Estimated impact**: High idle CPU utilization, especially on embedded environments like the OrangePi RV2, resulting in power drain and poor responsiveness.
- **Recommended fixes**: Implement proper condition variables or blocking channels to completely yield execution until events occur.

### 2. O(N) Array Operations (List Copying) Overhead
- **Bottlenecks**: Elements are manually copied using element-wise `push()` iteration across the repository (e.g., `src/transport/framing.sage` encryption buffers, `src/app/file.sage` chunk serialization, and `src/crypto/hash.sage` hex strings via string concatenation inside loops).
- **Estimated impact**: Decreased overall throughput limits and dramatically increased overhead when transmitting or serializing multi-megabyte payloads.
- **Recommended fixes**: Utilize native slice assignments or built-in memory utilities optimized for contiguous buffer manipulations. Use arrays and `join()` for string assembly instead of concatenating characters in loops.

### 3. Linear Probing Overhead in Stream ID Resolution
- **Bottlenecks**: In `src/mux/stream.sage`, `mux_open_stream` iterates sequentially testing up to 65536 times if a stream ID is available.
- **Estimated impact**: Noticeable delay when establishing streams under moderate concurrency.
- **Recommended fixes**: Maintain an independent free-list array or optimized random allocation scheme to avoid linear traversal.

### 4. Synchronous DH Computations
- **Bottlenecks**: In `src/mux/stream.sage` (`handle_rekey_responder`), the DH computation (`noise_ik.initialize_handshake`) blocks the entire reader thread while executing.
- **Estimated impact**: Stalls all concurrent streams for the duration of the DH computation.
- **Recommended fixes**: Dispatch rekeying handshakes to a background worker thread.

---

## Functionality Report

### Working features
- Mutual Authentication via Noise_IK with X25519 and ChaCha20-Poly1305.
- CMD execution with remote shell spawning and output capture.
- Replay Protection via a 64-entry sliding bitmap in the transport layer.
- Multiplexed Streams supporting overlapping operations on a single TCP socket.
- FILE transfers with streaming memory buffers.

### Broken features
- Inconsistent Execution Models in CMD Service: In `src/app/cmd.sage`, `sys.shell_exec(cmd)` restricts unsafe characters (e.g., `&&`), while `ffi_run_command(cmd)` executes them via libc `system()`. If a command contains restricted characters, it succeeds in `ffi_run_command` but throws an error in `sys.shell_exec`, leading to inconsistent state and missing standard output.
- Cross-Platform Breakage via Hardcoded Struct Offsets: In `src/app/file.sage`, `mem_read(stat_buf, 48, "u64")` assumes `st_size` is at offset 48, which is only valid on Linux x86_64, causing incorrect file size readings on other platforms (e.g., macOS or ARM64). Similarly, in `src/app/shell.sage`, the `winsize` struct manipulation relies on a hardcoded 8-byte format.

### Missing coverage
- Missing tests validating that maliciously oversized file chunks correctly trigger validation failures.
- Missing integration tests for the fallback of the `rekeying` logic under high load.
- No unit tests validating the failure paths of FFI system calls (e.g., `posix_openpt` returning < 0).
