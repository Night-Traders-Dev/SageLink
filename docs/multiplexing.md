# Stream Multiplexing

The multiplexing layer (`mux/stream.sage`) allows multiple logical streams to share a single encrypted TCP connection. Each stream is identified by a unique `stream_id` and carries its own message sequence.

## Message Types

| Constant | Value | Purpose |
|---|---|---|
| `CHAN_OPEN` | 0x01 | Open a new stream |
| `CHAN_DATA` | 0x02 | Stream data |
| `CHAN_CLOSE` | 0x03 | Close a stream |
| `CMD_EXEC` | 0x10 | Execute remote command |
| `CMD_RESULT` | 0x11 | Command execution result |
| `FILE_META` | 0x20 | File metadata (name, size, SHA-256) |
| `FILE_CHUNK` | 0x21 | File data chunk |
| `FILE_ACK` | 0x22 | File chunk acknowledgment |
| `SHELL_DATA` | 0x30 | PTY data (bidirectional) |
| `SHELL_RESIZE` | 0x31 | Terminal resize notification |
| `PING` | 0xF0 | Keepalive ping |
| `PONG` | 0xF1 | Keepalive pong |
| `REKEY_MSG1` | 0x40 | Rekey handshake message 1 |
| `REKEY_MSG2` | 0x41 | Rekey handshake message 2 |

## Inner Frame Format

```
+----------+-----------+-----------------+
| msg_type | stream_id | payload         |
| 1 byte   | 2 bytes   | variable        |
+----------+-----------+-----------------+
```

- **msg_type** — one of the message type constants
- **stream_id** — big-endian uint16; `0` is reserved for the control stream (rekeying)
- **payload** — service-specific bytes

## Multiplexer State

The multiplexer (`mux`) holds:

- **sock** — the underlying TCP socket
- **send_key / recv_key** — per-direction ChaCha20-Poly1305 keys
- **send_counter** — monotonic counter for outbound frames
- **recv_window** — replay window for inbound frames
- **streams** — map of active stream_id → stream objects
- **write_mutex** — serializes encrypted frame writes
- **reader_thread** — background thread running `mux_reader_loop`

## Reader Loop

The background reader thread (`mux_reader_loop`) continuously:

1. Reads and decrypts the next encrypted frame from TCP
2. Extracts `msg_type`, `stream_id`, and `payload`
3. For stream `0`: handles rekey messages
4. For other streams: dispatches to the stream's message queue
5. For unknown stream IDs with `CHAN_OPEN`: creates a new stream and calls the incoming callback

## Stream Lifecycle

1. **Open** — client calls `mux_open_stream(mux, service_type)`, sends `CHAN_OPEN`
2. **Data** — both sides send `CHAN_DATA` or service-specific messages
3. **Close** — either side calls `stream_close(mux, s)`, sends `CHAN_CLOSE`

## Rekeying

When the send counter reaches the configured threshold (default 1000 messages for the initiator), the multiplexer performs a fresh Noise_IK handshake over control stream `0`:

1. Initiator sends `REKEY_MSG1` with Noise_IK message 1
2. Responder processes, sends `REKEY_MSG2` with Noise_IK message 2
3. Both sides derive new keys and zero old keys from memory
4. Normal traffic resumes with new keys and counters reset to 0

During rekey, non-rekey messages are queued (blocked on a mutex) to ensure atomic key transition.

## Functions

| Function | Purpose |
|---|---|
| `create_mux(sock, send_key, recv_key, ...)` | Create multiplexer state |
| `mux_send_frame(mux, plaintext)` | Thread-safe encrypted frame write, triggers rekey if needed |
| `mux_send_msg(mux, stream_id, msg_type, payload)` | Pack and send a typed message |
| `mux_reader_loop(mux)` | Background decryption + dispatch loop |
| `mux_open_stream(mux, service_type)` | Open a new outgoing stream |
| `stream_read_msg(s)` | Blocking read from stream message queue |
| `stream_write_msg(mux, s, msg_type, payload)` | Write a message to a stream |
| `stream_close(mux, s)` | Close a stream and send CHAN_CLOSE |
| `trigger_rekey(mux)` | Initiator-driven rekey over control stream |
| `handle_rekey_responder(mux, payload)` | Responder processes incoming rekey request |
| `start_mux_reader(mux, incoming_callback)` | Spawn background reader thread |
