# LinkGuard Journal

## Security patterns
- Hand-rolled cryptographic primitives are used without external FFI dependencies.
- Sliding window replay protection is used for monotonic counters.
- Noise_IK handshake with X25519 and ChaCha20-Poly1305 for authenticated sessions.
- Authentication relies on pinned X25519 static keypairs configured via peers.toml.

## Recurring vulnerabilities
- Time-of-Check to Time-of-Use (TOCTOU) file permission vulnerabilities during sensitive file creation (e.g., identity keys).
- Command execution risks involving double-execution patterns that could lead to unintended remote side-effects.
- Denial of Service (DoS) risks due to lack of bounding on memory allocations (e.g., reading unvalidated payload sizes up to 1MB or creating unbounded thread instances for authenticated streams).

- Unhandled FFI return values causing out-of-bounds (OOB) memory reads on uninitialized buffers (e.g., ignoring `ptsname_r` errors in PTY resolution).
## Performance bottlenecks
- O(N) Array Operations (List Copying) overhead, especially noticeable when handling byte arrays in transport framing and serialization.
- Tight polling loops with `thread.sleep()` are used for stream reading and rekeying, causing unnecessary idle CPU load.
- Linear probing up to 65536 iterations is used for resolving stream IDs in multiplexing.

## Architectural weaknesses
- System calls rely on hardcoded, platform-specific IOCTL values across OS bounds in the SHELL service.
- The CMD service executes operations twice (via libc `system()` and `sys.shell_exec`) to capture both exit code and output independently.
- Multiplexer queues do not restrict maximum byte size, only the element count.

- Inconsistent execution models in CMD Service: using FFI `system()` (which allows all characters) alongside `sys.shell_exec()` (which restricts unsafe characters like `&&`), causing unpredictable execution behavior and desynced exit codes/outputs.
## Reliability risks
- PTY master/slave manipulation directly via FFI could leak file descriptors if errors occur mid-setup.
- Lack of timeouts on blocking `while true` synchronization structures (e.g., awaiting rekeying status).

## Build system pitfalls
- `sagemake` acts as a unified orchestrator but global test commands (`sagemake test`) risk timeouts if tests are not explicitly targeted.
- Submodules (like `sagelang-lib-gc` or `sagelang-lib-crypto`) require precise initialization to avoid missing dependencies during cross-compilation.
