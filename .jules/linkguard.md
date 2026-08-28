# LinkGuard Journal

## Security patterns
- Hand-rolled cryptographic primitives are used strictly without external FFI dependencies, reducing external attack surfaces.
- Sliding window replay protection is used for monotonic counters.
- Noise_IK handshake with X25519 and ChaCha20-Poly1305 is correctly applied for authenticated sessions.
- Authentication relies on pinned X25519 static keypairs configured via peers.toml.

## Recurring vulnerabilities
- **Process/Resource Leaks**: Using `system()` instead of `execve` to spawn long-running child processes causes the parent to lose direct tracking of the actual application (e.g., shell), leading to orphaned processes and resource leaks when the parent attempts to clean up the intermediate `system()` shell process.
- **TOCTOU File Permission Vulnerabilities**: File creations (e.g., identity keys) do not securely set atomic permissions during the `open` call.
- **Double-Execution Side Effects**: Command execution logic running commands twice to capture both exit codes and output separately (e.g., in `app/cmd.sage`).
- **Memory Allocation DoS**: Unvalidated payload sizes (up to 1MB) being read into memory before authentication is verified.
- **O(N^2) CPU Exhaustion DoS**: O(N^2) string concatenation when parsing `CHAN_OPEN` payloads can lead to CPU exhaustion.
- **Unhandled FFI Returns**: Failing to handle return values of critical FFI calls (e.g., `ptsname_r` in PTY setup) leading to out-of-bounds (OOB) memory reads on uninitialized buffers.
- **Slowloris DoS**: Lack of network timeouts during the handshake (`tcp.recvall()`).
- **Unbounded Thread Spawning**: `CHAN_OPEN` requests trigger unbounded thread creation for authenticated streams.
- **Incomplete Cleanup**: Aborted file transfers fail to delete partial files, leading to disk exhaustion.

## Performance bottlenecks
- O(N^2) or high O(N) Array Operations (List Copying/String Concatenation) overhead, especially noticeable when handling byte arrays in transport framing and serialization.
- Tight polling loops with `thread.sleep(0.005)` are used for stream reading and rekeying, causing unnecessary idle CPU load instead of event-driven blocking.
- Synchronous Diffie-Hellman (DH) computations blocking the main reader loops, reducing concurrency and throughput.
- Delayed list compaction (e.g., waiting until a queue reaches 1024 elements) retaining large memory objects longer than necessary.

## Architectural weaknesses
- System calls rely on hardcoded, platform-specific IOCTL values (e.g., TIOCSCTTY, TIOCSWINSZ) across OS bounds in the SHELL service.
- The CMD service executes operations twice (via libc `system()` and `sys.shell_exec`) to capture both exit code and output independently.
- Multiplexer queues do not restrict maximum byte size, only the element count.
- Hardcoded C struct offsets (e.g., `winsize` offset calculation) break cross-platform compatibility (e.g., between Linux and macOS or different architectures).

## Reliability risks
- PTY master/slave manipulation directly via FFI could leak file descriptors if errors occur mid-setup before cleanup is reached.
- Lack of timeouts on blocking `while true` synchronization structures (e.g., awaiting rekeying status).

## Build system pitfalls
- `sagemake` acts as a unified orchestrator but global test commands (`sagemake test`) risk timeouts if tests are not explicitly targeted.
- Submodules (like `sagelang-lib-gc` or `sagelang-lib-crypto`) require precise initialization to avoid missing dependencies during cross-compilation.
