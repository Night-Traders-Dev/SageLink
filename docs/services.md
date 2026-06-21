# Application Services

Three application-level services run on top of the multiplexing layer: CMD, FILE, and SHELL.

---

## CMD Service (`app/cmd.sage`)

Fire-and-forget remote command execution. The client sends a shell command string, the server executes it via `sys.shell_exec()`, and returns the exit code plus stdout/stderr output.

### Protocol

```
Client                              Server
  │  CMD_EXEC(command)               │
  │ ───────────────────────────────> │
  │                                  │  sys.shell_exec(command)
  │         CMD_RESULT(status+out)   │
  │ <─────────────────────────────── │
  │  CHAN_CLOSE                      │
```

### Functions

| Function | Purpose |
|---|---|
| `run_remote_cmd(mux, cmd_string)` | Client: run a command, return `{exit_code, output}` |
| `handle_cmd_stream(mux, s)` | Server: read CMD_EXEC, execute, send CMD_RESULT |

---

## FILE Service (`app/file.sage`)

Chunked file transfer with SHA-256 integrity verification and sliding-window flow control. Supports sending files from client to server.

### Protocol

```
Client                              Server
  │  FILE_META(name, size, sha256)   │
  │ ───────────────────────────────> │
  │  FILE_CHUNK(offset, data)        │
  │ ───────────────────────────────> │
  │         FILE_ACK(bytes_written)  │
  │ <─────────────────────────────── │
  │  (repeat for each chunk)         │
  │  CHAN_CLOSE                      │
```

### Flow Control

A 64KB sliding window limits outstanding (unacknowledged) data. The sender blocks and waits for a `FILE_ACK` before sending beyond the window boundary. The receiver acknowledges cumulative bytes written after each in-order chunk.

### Integrity

The sender includes a SHA-256 hash of the complete file in the `FILE_META` message. After all chunks are received and written, the receiver re-hashes the file and compares. On mismatch, the target file is wiped.

### Chunk Size

Each chunk is 16KB (16384 bytes). The last chunk may be smaller.

### Functions

| Function | Purpose |
|---|---|
| `send_file(mux, local_path, remote_dest)` | Client: read local file, stream chunks, verify result |
| `handle_file_stream(mux, s)` | Server: receive chunks, write to file, verify SHA-256 |

---

## SHELL Service (`app/shell.sage`)

Interactive PTY-based shell session. The server spawns a real `/bin/sh` process attached to a pseudo-terminal (PTY), and the client communicates with it bidirectionally over the stream.

### Protocol

```
Client                              Server
  │  SHELL_DATA (keystrokes)         │
  │ ───────────────────────────────> │  write to PTY master
  │                                  │  read from PTY master
  │         SHELL_DATA (output)      │
  │ <─────────────────────────────── │
  │  SHELL_RESIZE(rows, cols)        │
  │ ───────────────────────────────> │  ioctl(TIOCSWINSZ)
```

### PTY Implementation

The server uses FFI (`ffi_open`/`ffi_call`) to call libc functions directly:

1. `posix_openpt(O_RDWR | O_NOCTTY)` — open PTY master
2. `grantpt(master_fd)` — grant slave access
3. `unlockpt(master_fd)` — unlock slave
4. `fork()` — spawn child process
5. Child: open slave PTY, `setsid()`, `ioctl(TIOCSCTTY)`, `dup2` for stdin/stdout/stderr, exec `/bin/sh`
6. Parent: spawn reader thread for PTY→stream, main loop for stream→PTY

### Terminal Resize

The client sends `SHELL_RESIZE` with `rows(2B) + cols(2B)`. The server calls `ioctl(master_fd, TIOCSWINSZ, winsize_struct)` to update the terminal dimensions.

### Functions

| Function | Purpose |
|---|---|
| `handle_shell_stream(mux, s)` | Server: spawn PTY, fork shell, bidirectional I/O |
| `pty_to_stream_loop(master_fd, mux, s)` | Server reader thread: PTY→stream |
| `run_client_shell(mux)` | Client: open SHELL stream, stdin→stream, stream→stdout |
