# SageLink Comprehensive Audit Report

## Architecture Map

- **Major Subsystems**:
  - `src/handshake/` (Noise_IK state machine)
  - `src/transport/` (Framing and sliding window replay protection)
  - `src/mux/` (Stream multiplexer over TCP)
  - `src/app/` (Application Layer: CMD, FILE, SHELL services)
  - `src/cli/` (Command Line Interface entry points)
  - `crypto/` (Pure SageLang cryptographic primitives)
- **Runtime Architecture**: Single-threaded event loop combined with multi-threaded dispatch. Multiplexer operates on a shared TCP socket, dispatching authenticated payloads to isolated worker threads for each active service stream.
- **Communication Layers**: TCP -> Handshake (Noise_IK) -> Transport (ChaCha20-Poly1305 + Replay Window) -> Mux -> Application
- **External Dependencies**:
  - Requires SageLang (>= v4.0.2)
  - OS-level `libc` loaded dynamically via FFI (`ffi_open`)
- **Build Systems**: Custom `sagemake` Python script wrapping SageVM and Sage CLI.
- **Testing Infrastructure**: Built-in test suite executing RFC test vectors (`test_crypto.sage`) and integration flows (`test_handshake.sage`).

---

## Executive Summary

This comprehensive audit of the SageLink protocol suite identified several critical and high-severity risks, primarily stemming from unbounded resource allocations, Time-of-Check to Time-of-Use (TOCTOU) file permission vulnerabilities, and unsafe FFI usage on host systems. While the cryptographic primitives themselves strictly follow RFC specifications and lack external dependencies, the application-layer services (CMD, FILE, SHELL) expose the host to significant Denial of Service (DoS) attacks and resource leaks. The unified build system functions correctly, but the test suite currently fails globally due to syntax errors and unsupported FFI argument types. Immediate remediation of the unbounded allocations and child process management is required before SageLink can be considered secure for hostile LAN environments.

### Top 10 issues ranked by impact

1. **OOM / DoS via Unbounded Memory Allocation in File/Shell Transfers** (Critical) - Allows remote authenticated attackers to crash the host system by exhausting heap memory.
2. **Shell Process Leak (Orphan/Zombie) due to `system('/bin/sh')`** (High) - Leads to severe resource leaks when terminating shell sessions, leaving interactive bash instances running on the host.
3. **Double Execution of Commands** (High) - Executing commands twice in the CMD service causes unintended side-effects and desynced exit codes/outputs.
4. **Insecure Default Permissions (TOCTOU) for Identity Keys** (High) - Writing private keys with default permissions before restricting them allows local attackers a window to steal long-term identities.
5. **Cross-Platform Breakage via Hardcoded Struct Offsets** (High) - Manual C-struct offset calculations break functionality on macOS and ARM architectures.
6. **OOB Memory Read in PTY Name Resolution** (High) - Failing to check FFI return values from `ptsname_r` leads to out-of-bounds reads on uninitialized buffers.
7. **Process/Resource Leaks in Stream ID Resolution** (Medium) - Up to 65536 iterations of linear probing block stream establishment under load.
8. **DoS via Lack of Network Timeouts** (Medium) - Lack of TCP timeouts enables Slowloris-style attacks, exhausting connection limits.
9. **OOM / DoS via Stream Queue Message Accumulation** (Medium) - Unbounded message byte sizes in multiplexer queues allow memory exhaustion regardless of queue length limits.
10. **Unbounded Thread Spawn for Authenticated Clients** (Medium) - Spawning unconstrained threads per authenticated connection can lead to thread exhaustion attacks.

---

## Repository Health Score

- Security: 4/10
- Performance: 5/10
- Reliability: 4/10
- Maintainability: 6/10
- Documentation: 7/10

---

## Security Report

### 1. Incomplete Input Validation in CMD Service
- **Findings**: In `src/app/cmd.sage`, `handle_cmd_stream` constructs the command string by directly iterating over an unvalidated `cmd_bytes` array payload, without any bounds checking on the payload length. This opens the service to excessive memory consumption or hangs if a malformed payload is heavily padded.
- **Severity**: Low
- **Evidence**: `src/app/cmd.sage` lines 76-80 - `for i in range(len(cmd_bytes)): cmd = cmd + chr(cmd_bytes[i])` occurs before execution, without bounding `len(cmd_bytes)`.
- **Fix recommendation**: Implement a strict maximum length check on the CMD payload (e.g., 4096 bytes) before string assembly.

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
- **Findings**: In `src/cli/sagelink.sage`, `io.writefile(tmp_key, priv_b64 + "
")` writes the private key with default system permissions, followed by a `sys.shell_exec("chmod 600 " + tmp_key + " && mv ...")`. This creates a Time-of-Check to Time-of-Use (TOCTOU) race condition where a local attacker can read the private key.
- **Severity**: High
- **Evidence**: `src/cli/sagelink.sage` - `io.writefile(tmp_key, priv_b64 + "
")` followed by `sys.shell_exec("chmod 600 ...")`.
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
- Syntax error in `crypto/hash.sage`: A duplicate `rotate_left` definition is missing a body on line 28, causing `test_crypto` and `sagemake check` to fail.
- Unsupported `ffi_call` argument types in `crypto/rand.sage`: `get_urandom_bytes` calls `open` with `["/dev/urandom", 0]`, causing the Noise_IK handshake to crash and `test_handshake` to fail (due to `alice_keys` being undefined).

### Missing coverage
- Missing tests validating that maliciously oversized file chunks correctly trigger validation failures.
- Missing integration tests for the fallback of the `rekeying` logic under high load.
- No unit tests validating the failure paths of FFI system calls (e.g., `posix_openpt` returning < 0).
