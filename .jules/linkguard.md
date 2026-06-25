# LinkGuard Journal

## Security Patterns & Recurring Vulnerabilities
- **Unauthenticated State Mutation:** The replay window (`transport/replay_window.sage`) mutates its state (`max_seen`, `bitmap`) in `check_replay()` *before* the payload's MAC is verified in `framing.sage`. This allows an attacker to send spoofed frames with high counter values, advancing the window and causing legitimate frames to be permanently dropped (DoS).
- **Unbounded Memory Allocation (OOM DoS):** In `transport/framing.sage` (`read_frame`), the 4-byte length prefix dictates how many bytes `tcp.recvall()` will allocate. An unauthenticated attacker can send a large length value (e.g., 4GB) to instantly exhaust server memory.
- **Path Traversal in File Transfer:** The `FILE` service (`app/file.sage`) directly uses the user-provided `filename` from the `FILE_META` payload in `io.writefile(filename, "")`. A malicious authenticated client can overwrite arbitrary files (e.g., `../../etc/passwd`).

## Performance Bottlenecks
- **O(N) Queue Shifting:** In `mux/stream.sage` (`stream_read_msg`), popping a message from the queue shifts all remaining elements by manually pushing them to a new list (`O(N)`). During high-throughput transfers (e.g., file transfers), this consumes massive CPU.
- **Busy-Wait Polling Loops:** Streams (`stream_read_msg`) and rekey coordination (`trigger_rekey`, `mux_send_frame`) use `while true: thread.sleep(0.005)` polling instead of condition variables, leading to high idle CPU usage and added latency.
- **Whole-file Memory Buffering:** In `app/file.sage`, verifying the file integrity reads the entire written file into memory at once (`io.readbytes(filename)`). This will OOM the application for large files.

## Architectural Weaknesses & Reliability Risks
- **Stream ID Wrap-Around/Collision:** In `mux/stream.sage`, `next_stream_id` increments indefinitely. If it wraps or exceeds normal bounds, it could collide with stream ID `0` (reserved for control/rekey messages) or existing active streams, leading to connection state corruption.
- **Deadlock on Disconnection During Rekeying:** The rekey loops in `mux/stream.sage` wait for `mux["rekeying"]` to become false. If the socket closes during a rekey, `rekeying` is never cleared, causing threads to deadlock forever.
- **No In-Band Rekey Timeout:** Rekey is triggered by message count (`rekey_threshold`). There is no time-based rekeying, and if the responder never receives the second rekey message, the initiator blocks indefinitely.

## Build System Pitfalls
- `sagemake` relies strictly on paths relative to the invocation directory and sets `SAGE_PATH` globally, making it brittle if run from outside the repository root.
- Linting is simplistic and counts warnings as failures without structured output.