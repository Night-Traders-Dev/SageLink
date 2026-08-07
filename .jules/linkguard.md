# LinkGuard Journal

## Security patterns
- Hand-rolled cryptographic primitives are used without external FFI dependencies.
- Sliding window replay protection is used for monotonic counters.
- Noise_IK handshake with X25519 and ChaCha20-Poly1305 for authenticated sessions.
- Authentication relies on pinned X25519 static keypairs configured via peers.toml.

## Recurring vulnerabilities
- Process/Resource Leaks: Using `system()` instead of `exec` to spawn long-running child processes causes the parent to lose direct tracking of the actual application (e.g., shell), leading to orphaned processes and resource leaks when the parent attempts to clean up the intermediate `system()` shell process. (e.g., `src/app/shell.sage`)
- Time-of-Check to Time-of-Use (TOCTOU) file permission vulnerabilities during sensitive file creation (e.g., identity keys in `src/cli/sagelink.sage`).
- Command execution risks involving double-execution patterns that could lead to unintended remote side-effects (e.g., `src/app/cmd.sage`).
- Denial of Service (DoS) risks due to lack of bounding on memory allocations (e.g., reading unvalidated payload sizes up to 1MB in `src/app/file.sage` and `src/app/shell.sage` or creating unbounded thread instances for authenticated streams in `src/cli/sagelink.sage`).
- Denial of Service (DoS) via unvalidated string concatenations processing up to 1MB payloads leading to O(N^2) memory allocations (e.g., `src/mux/stream.sage`).
- Unhandled FFI return values causing out-of-bounds (OOB) memory reads on uninitialized buffers (e.g., ignoring `ptsname_r` errors in PTY resolution in `src/app/shell.sage`).
- Denial of Service (DoS) via Slowloris-style attacks due to lack of network timeouts during handshake and stream reading (e.g., `tcp.recvall` in `src/cli/sagelink.sage` and `src/transport/framing.sage`).
- Incomplete disk cleanup on failed file transfers, leading to disk space resource exhaustion (e.g., not cleaning up correctly on all failure paths in `src/app/file.sage`).

## Performance bottlenecks
- O(N^2) or high O(N) Array Operations (List Copying/String Concatenation) overhead, especially noticeable when handling byte arrays in transport framing and serialization, or when generating UUID4s/hex strings via loops. Also noticeable in service type string assembly (`src/mux/stream.sage`).
- Tight polling loops with `thread.sleep()` are used for stream reading and rekeying, causing unnecessary idle CPU load (e.g., `src/mux/stream.sage`).
- Linear probing up to 65536 iterations is used for resolving stream IDs in multiplexing (e.g., `src/mux/stream.sage`).
- Synchronous Diffie-Hellman (DH) computations blocking the main reader loops, reducing concurrency and throughput.
- Delayed list compaction (e.g., waiting until a queue reaches 1024 elements) retaining large memory objects longer than necessary (e.g., `src/mux/stream.sage`).

## Architectural weaknesses
- System calls rely on hardcoded, platform-specific IOCTL values across OS bounds in the SHELL service (`src/app/shell.sage`).
- The CMD service executes operations twice (via libc `system()` and `sys.shell_exec`) to capture both exit code and output independently (`src/app/cmd.sage`).
- Multiplexer queues do not restrict maximum byte size, only the element count (`src/mux/stream.sage`).
- Inconsistent execution models in CMD Service: using FFI `system()` alongside `sys.shell_exec()` causes unpredictable execution behavior and desynced exit codes/outputs (`src/app/cmd.sage`).
- Hardcoded C struct offsets (e.g., `winsize` offset calculation or `st_size` in `fstat`) break cross-platform compatibility (e.g., between Linux and macOS or different architectures) (e.g., `src/app/file.sage` and `src/app/shell.sage`).

## Reliability risks
- PTY master/slave manipulation directly via FFI could leak file descriptors if errors occur mid-setup (`src/app/shell.sage`).
- Lack of timeouts on blocking `while true` synchronization structures (e.g., awaiting rekeying status in `src/mux/stream.sage`).

## Build system pitfalls
- `sagemake` acts as a unified orchestrator but global test commands (`sagemake test`) risk timeouts if tests are not explicitly targeted.
- Submodules (like `sagelang-lib-gc` or `sagelang-lib-crypto`) require precise initialization to avoid missing dependencies during cross-compilation.
