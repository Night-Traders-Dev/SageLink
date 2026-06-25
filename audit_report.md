# SageLink Comprehensive Audit Report

## Executive Summary

LinkGuard has completed a full audit of the SageLink repository. While the cryptographic primitives appear theoretically sound (subject to RFC testing), the protocol implementation contains **critical architectural flaws and vulnerabilities** that undermine its security, reliability, and performance.

The protocol is currently unsuitable for hostile environments.

**Top Issues Ranked by Impact:**
1. **[Critical] Remote OOM DoS via Unbounded Frame Length** (Pre-Auth)
2. **[Critical] Replay Window DoS via Unauthenticated State Mutation** (Pre-Auth)
3. **[Critical] Arbitrary File Overwrite / Path Traversal** (Post-Auth)
4. **[High] Stream Muxing Deadlocks on Disconnection**
5. **[High] Stream ID Collision & State Corruption**
6. **[Medium] Excessive CPU Usage via O(N) Array Operations**
7. **[Medium] Excessive Memory Usage via Whole-File Buffering**

---

## Repository Health Score

| Category | Score | Notes |
|---|---|---|
| **Security** | 2/10 | Handshake works, but pre-auth DoS and post-auth RCE risks exist. |
| **Performance** | 4/10 | High CPU from polling; O(N) operations choke under load. |
| **Reliability** | 3/10 | Highly prone to deadlocks, state desync, and stream ID collisions. |
| **Maintainability** | 6/10 | Code is reasonably structured into modules but lacks safety primitives. |
| **Documentation** | 8/10 | Documentation accurately describes the protocol, even its flaws. |

---

## Phase 1: Architecture Map

```
[ CMD / FILE / SHELL ] (app layer)
       │
[ Stream Multiplexing ] (mux/stream.sage) <-- Flaw: O(N) queues, Deadlocks, Stream ID wrap
       │
[ Framing & Replay ] (transport) <-- Flaw: Pre-auth mutation, OOM allocation
       │
[ Noise_IK Handshake ] (handshake/noise_ik.sage)
       │
[ TCP Socket ]
```

---

## Phase 2: Security Report

### 1. Remote OOM DoS via Unbounded Allocation (Critical)
**Evidence:** `src/transport/framing.sage:128`
```python
let len_val = bytes_to_uint32(len_raw)
let payload_raw = tcp.recvall(sock, len_val, true)
```
**Impact:** Any unauthenticated TCP connection can send `0xFFFFFFFF` as the frame length. `tcp.recvall` will immediately attempt to allocate 4GB of RAM, crashing the process.
**Fix Recommendation:** Introduce a hard upper limit (e.g., 1MB) for `len_val` before calling `recvall`.

### 2. Replay Window DoS via Unauthenticated Mutation (Critical)
**Evidence:** `src/transport/framing.sage:103` & `src/transport/replay_window.sage:13`
`decrypt_frame` calls `replay_window.check_replay(window, counter)`. This function immediately mutates `max_seen` and the `bitmap` array *before* `aead.chacha20_poly1305_decrypt` verifies the MAC tag.
**Impact:** An attacker can forge invalid packets with massively incremented counters. The window slides forward to accommodate the spoofed counter. When the MAC check inevitably fails, the frame is dropped, but the window has already moved, permanently bricking the connection for valid, lower-counter frames.
**Fix Recommendation:** Separate `check_replay` into a read-only `is_valid_counter` function, and a mutating `commit_counter` function called *only after* successful decryption.

### 3. Arbitrary File Overwrite / Path Traversal (Critical)
**Evidence:** `src/app/file.sage:152`
```python
let filename = ... # built from meta_payload
io.writefile(filename, "")
```
**Impact:** The server blindly trusts the filename provided by the client. An authenticated client can specify paths like `../../../../root/.ssh/authorized_keys`, allowing full system compromise.
**Fix Recommendation:** Strip directory traversal characters (`../`, `/`) and restrict file writes to a dedicated, sandboxed directory.

---

## Phase 3: Performance Report

### 1. O(N) Array Operations in Stream Queues (High Impact)
**Evidence:** `src/mux/stream.sage:296`
When popping a message from a stream queue, the code iterates over the remaining elements and creates a new array:
```python
let new_q = []
for i in range(1, len(s["queue"])):
    push(new_q, s["queue"][i])
```
**Impact:** Under heavy traffic (like `FILE` transfers), this degrades into `O(N^2)` time complexity, saturating the CPU.
**Recommended Fix:** Use a proper queue structure (ring buffer) or index tracking instead of rebuilding the list on every read.

### 2. Whole-File Buffering on Verification (High Impact)
**Evidence:** `src/app/file.sage:192`
```python
let written_bytes = io.readbytes(filename)
let actual_hash = hash.sha256(written_bytes)
```
**Impact:** Verifying a large file (e.g., 5GB) attempts to read all 5GB into memory at once, crashing the application.
**Recommended Fix:** Hash the file incrementally via a chunked streaming API.

### 3. Busy-Wait Polling (Medium Impact)
**Evidence:** `src/mux/stream.sage:311` (and `trigger_rekey`)
`while true: ... thread.sleep(0.005)`
**Impact:** Streams burn CPU cycles while waiting for messages.
**Recommended Fix:** Replace with blocking condition variables or semaphores.

---

## Phase 4: Functionality & Reliability Report

### Working Features
- **Mutual Authentication:** Successfully implemented using pinned X25519 static keys and Noise_IK.
- **CMD Service:** The remote command execution service works properly and returns outputs and exit codes.
- **SHELL Service:** The bidirectional PTY-based shell successfully spawns and accepts input.
- **Multiplexing:** The core framing allows multiplexing streams efficiently when load is low.

### Broken Features
- **Rekey Disconnect Deadlock (High Reliability Issue):** If the TCP connection drops during the rekey handshake, the reader thread exits, and `rekeying` is never set to false (`src/mux/stream.sage:130`). The sender thread blocks forever.
- **Stream ID Collision (Medium Reliability Issue):** No bounds checking or active stream checking exists on stream IDs (`src/mux/stream.sage:280`). If `next_stream_id` wraps around 65535, it can collide with stream ID 0 (control), breaking rekeying, or overwrite existing application streams in the `streams` dictionary.
- **FILE Service Integrity Check Memory Exhaustion:** Trying to verify a large file uses whole-file memory buffering.

### Missing Coverage
- **Timeout Management:** The protocol lacks timeouts for multiplexing rekey wait loops and TCP frame reception.
- **Input Sanitization Tests:** Path traversal in the FILE service is not caught by existing tests.
- **Memory Allocation Limits:** The system implicitly trusts unauthenticated client lengths.

---

## Phase 5: Build System & Dependencies

- **Dependencies:** The application has zero external cryptographic dependencies (all hand-rolled). While admirable, this requires continuous rigorous testing against published test vectors.
- **Build System:** `sagemake` functions adequately but has limited linting diagnostics.

---
**End of Report.**