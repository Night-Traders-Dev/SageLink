# LinkGuard Journal

## Security patterns
- Hand-rolled cryptographic primitives are strictly utilized without external FFI dependencies, reducing supply chain attack surface.
- Sliding 64-entry window replay protection effectively guarantees monotonic counter progression.
- Noise_IK handshakes (X25519 + ChaCha20-Poly1305 + BLAKE2s) ensure mutually authenticated and encrypted sessions.
- Authentication mechanisms exclusively rely on pinned X25519 static keypairs configured in `peers.toml`.
- No FFI calls are trusted for cryptography, aside from secure randomness retrieval (`/dev/urandom`).

## Recurring vulnerabilities
- **Process/Resource Leaks**: Relying on `system()` instead of `execve` to spawn long-running child processes results in the parent losing direct tracking of the actual application (e.g., interactive shell), causing orphaned processes.
- **TOCTOU Weaknesses**: Time-of-Check to Time-of-Use file permission vulnerabilities exist during sensitive file creation operations (e.g., identity key generation).
- **Double-Execution Risks**: Command execution workflows involve double-execution patterns (using `system()` then `shell_exec()`) that trigger unintended and duplicated remote side-effects.
- **DoS via Memory Exhaustion**: Lack of bounding on memory allocations (accepting payload sizes up to 1MB pre-authentication) and unbounded thread spawning expose the application to denial of service.
- **Unbounded Aggregate Mux Queue Byte Size DoS**: `src/mux/stream.sage` limits the stream queue element count to 1000 items, but does not bound the aggregate byte size, risking silent memory exhaustion.
- **DoS via CPU Exhaustion**: O(N^2) string concatenation when parsing large `CHAN_OPEN` payloads authenticated by malicious peers.
- **Unhandled FFI Returns**: Neglecting to validate FFI return values (e.g., ignoring `ptsname_r` errors) opens vectors for out-of-bounds (OOB) memory reads on uninitialized buffers.
- **DoS via Slowloris**: The application lacks network timeouts during handshakes and stream reading, making it susceptible to connection stagnation attacks.
- **Disk Space Exhaustion**: Incomplete disk cleanup on failed or aborted file transfers leads to gradual storage depletion.

- **Arbitrary File Overwrite via Path Traversal**: Unvalidated filenames received from peers in `FILE_META` messages can be used directly in file creation functions, leading to path traversal attacks (e.g. `src/app/file.sage`).
- **Stream ID Exhaustion DoS**: The multiplexer (e.g. `src/mux/stream.sage`) uses a predictable sequence for `next_stream_id` and linear probing, allowing an authenticated peer to open streams until no more IDs are available, locking up new connections and wasting CPU cycles.

## Performance bottlenecks
- **Hardcoded Memory Bounds**: Strict memory boundaries like the 16384-byte chunk limit in `src/app/file.sage` limit maximum theoretical throughput over high bandwidth links, degrading file transfer speeds.
- **Array Operations Overhead**: O(N^2) or high O(N) array operations (list copying and string concatenation) create significant overhead, especially when handling byte arrays in transport framing or UUID generation.
- **Busy Polling**: Tight polling loops relying heavily on `thread.sleep(0.005)` (e.g., `stream_read_msg` in `src/mux/stream.sage`) for stream reading and rekeying synchronization waste CPU cycles.
- **Synchronous Cryptography**: Heavy Diffie-Hellman (DH) computations are executed synchronously on the main reader loops, stalling multiplexing throughput.
- **Delayed Garbage Collection**: Delayed list compaction (waiting for a queue to hit 1024 elements) retains large memory blocks longer than necessary.
- **Inefficient Stream Resolution**: Linear probing up to 65536 iterations for resolving available stream IDs limits multiplexing efficiency under load.

## Architectural weaknesses
- **FFI Boundary Bypassing**: Heavy reliance on direct IPC via FFI (e.g., `ffi_call(libc, "system")` in `src/app/shell.sage`) bypasses standard SageLang sandbox limits and type safety boundaries, elevating risks of native crashes.
- **Platform-Dependent IOCTLs**: System calls inherently rely on hardcoded, platform-specific IOCTL values across OS boundaries in the SHELL service.
- **Inconsistent Execution Models**: The CMD service uses FFI `system()` (allowing all characters) alongside `sys.shell_exec()` (restricting unsafe characters like `&&`), causing desynchronized behavior. In `src/cli/sagelink.sage`, this blocking of `&&` actively breaks the atomic key generation.
- **Hardcoded Memory Offsets**: Relying on fixed C struct offsets (e.g., `winsize` offset calculations) completely breaks cross-platform compatibility across disparate architectures and OS kernels.
- **Unbounded Multiplexing Queues**: Multiplexer queues bound the element count but fail to restrict the aggregate byte size, leading to unpredictable memory usage.

## Reliability risks
- **Incomplete Write Handling**: `write()` syscalls via FFI lack validation for partial writes, risking truncated data streams during heavy loads.
- **File Descriptor Leaks**: PTY master/slave manipulation directly via FFI easily leaks file descriptors if mid-setup error pathways are triggered without cleanup.
- **FFI IPC Instability**: Spawning shells and interacting with PTYs via direct `libc` FFI calls (e.g. `src/app/shell.sage`) bypasses standard process boundaries, introducing silent truncation risks on partial writes.
- **Synchronization Deadlocks**: The absence of strict timeouts on blocking `while true` synchronization structures (e.g., awaiting rekeying status) risks indefinite hangs.

## Build system pitfalls
- **Un-targeted Test Execution**: `sagemake` acting as a unified orchestrator poses a risk of global test command timeouts (`sagemake test`) if tests are not explicitly targeted or parallelized.
- **Submodule Dependencies**: Essential submodules (`sagelang-lib-gc`, `sagelang-lib-crypto`) require highly precise initialization to avoid missing dependencies during AOT cross-compilation.
- **Environment Variable Silencing**: Cross-compilation workflows utilizing `sagevm` fail silently if the `SAGE_PATH` environment variable is not explicitly propagated to internal subprocesses, frequently breaking `sagelang-lib-crypto` submodule resolution.
