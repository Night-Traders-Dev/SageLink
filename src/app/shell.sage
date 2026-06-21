# sagelink/app/shell.sage
# SHELL service for interactive PTY shell execution via SageLink

import thread
import sagelink.mux.stream as stream
import sagelink.utils as utils

# Dedicated loop to read from PTY master and write to the multiplexed stream
proc pty_to_stream_loop(master_fd, mux, s):
    let read_buf = mem_alloc(4096)
    let libc = ffi_open("libc.so.6")
    if libc == nil:
        libc = ffi_open("libc.so")
    end
    if libc == nil:
        libc = ffi_open("")
    end
    
    while not s["closed"] and mux["running"]:
        let nread = ffi_call(libc, "read", "int", [master_fd, read_buf, 4096])
        if nread <= 0:
            break
        end
        
        # Build payload list
        let data = []
        for i in range(nread):
            push(data, mem_read(read_buf, i, "byte"))
        end
        
        # Write to stream
        if not stream.stream_write_msg(mux, s, stream.SHELL_DATA, utils.bytes(data)):
            break
        end
    end
    
    mem_free(read_buf)
    if libc != nil:
        ffi_close(libc)
    end
    stream.stream_close(mux, s)
end

# Server-side handler for a SHELL stream
proc handle_shell_stream(mux, s):
    let libc = ffi_open("libc.so.6")
    if libc == nil:
        libc = ffi_open("libc.so")
    end
    if libc == nil:
        libc = ffi_open("")
    end
    if libc == nil:
        print "Error: libc FFI not available on server"
        stream.stream_close(mux, s)
        return
    end

    # 1. Open master PTY
    let master_fd = ffi_call(libc, "posix_openpt", "int", [258]) # O_RDWR | O_NOCTTY = 2 | 256 = 258
    if master_fd < 0:
        print "Error: posix_openpt failed"
        stream.stream_close(mux, s)
        ffi_close(libc)
        return
    end

    ffi_call(libc, "grantpt", "int", [master_fd])
    ffi_call(libc, "unlockpt", "int", [master_fd])

    # 2. Get slave PTY name
    let name_buf = mem_alloc(256)
    ffi_call(libc, "ptsname_r", "int", [master_fd, name_buf, 256])
    let slave_name = ""
    let idx = 0
    while true:
        let char_val = mem_read(name_buf, idx, "byte")
        if char_val == 0:
            break
        end
        slave_name = slave_name + chr(char_val)
        idx = idx + 1
    end
    mem_free(name_buf)

    # 3. Fork shell process
    let pid = ffi_call(libc, "fork", "int", [])
    if pid < 0:
        print "Error: fork failed"
        ffi_call(libc, "close", "int", [master_fd])
        stream.stream_close(mux, s)
        ffi_close(libc)
        return
    end

    if pid == 0:
        # ── Child Process ──
        # Open slave PTY: O_RDWR = 2
        let slave_fd = ffi_call(libc, "open", "int", [slave_name, 2])
        if slave_fd < 0:
            ffi_call(libc, "_exit", "void", [1])
            return
        end
        
        # Create session
        ffi_call(libc, "setsid", "int", [])
        
        # Set controlling terminal: TIOCSCTTY = 21518 (0x540E)
        ffi_call(libc, "ioctl", "int", [slave_fd, 21518, 0])
        
        # Redirect standard streams to slave PTY
        ffi_call(libc, "dup2", "int", [slave_fd, 0])
        ffi_call(libc, "dup2", "int", [slave_fd, 1])
        ffi_call(libc, "dup2", "int", [slave_fd, 2])
        
        ffi_call(libc, "close", "int", [slave_fd])
        ffi_call(libc, "close", "int", [master_fd])
        
        # Execute interactive shell
        ffi_call(libc, "system", "int", ["/bin/sh"])
        
        ffi_call(libc, "_exit", "void", [0])
        return
    end

    # ── Parent Process ──
    # Spawn PTY to Stream reader thread
    proc run_reader():
        pty_to_stream_loop(master_fd, mux, s)
    end
    thread.spawn(run_reader)
    
    # Process incoming messages from client (Stream -> PTY)
    while not s["closed"] and mux["running"]:
        let msg = stream.stream_read_msg(s)
        if msg == nil:
            break
        end
        
        if msg["msg_type"] == stream.SHELL_DATA:
            let payload = utils.to_list(msg["payload"])
            let count = len(payload)
            if count > 0:
                let write_buf = mem_alloc(count)
                for i in range(count):
                    mem_write(write_buf, i, "byte", payload[i])
                end
                ffi_call(libc, "write", "int", [master_fd, write_buf, count])
                mem_free(write_buf)
            end
        end
        
        if msg["msg_type"] == stream.SHELL_RESIZE:
            let payload = utils.to_list(msg["payload"])
            if len(payload) >= 4:
                let rows = payload[0] * 256 + payload[1]
                let cols = payload[2] * 256 + payload[3]
                
                # winsize struct is 8 bytes: row(2B), col(2B), xpixel(2B), ypixel(2B)
                # stored in platform endianness (little endian)
                let ws = mem_alloc(8)
                mem_write(ws, 0, "byte", rows & 255)
                mem_write(ws, 1, "byte", (rows >> 8) & 255)
                mem_write(ws, 2, "byte", cols & 255)
                mem_write(ws, 3, "byte", (cols >> 8) & 255)
                mem_write(ws, 4, "byte", 0)
                mem_write(ws, 5, "byte", 0)
                mem_write(ws, 6, "byte", 0)
                mem_write(ws, 7, "byte", 0)
                
                # TIOCSWINSZ = 21524 (0x5414)
                ffi_call(libc, "ioctl", "int", [master_fd, 21524, ws])
                mem_free(ws)
            end
        end
    end
    
    # Cleanup shell and close descriptors
    ffi_call(libc, "kill", "int", [pid, 9])
    ffi_call(libc, "close", "int", [master_fd])
    stream.stream_close(mux, s)
    ffi_close(libc)
end

# Client function to run an interactive shell session (stdin/stdout -> stream)
# Note: Caller should configure raw terminal mode if needed
proc run_client_shell(mux):
    let s = stream.mux_open_stream(mux, "SHELL")
    if s == nil:
        print "Error: Failed to open SHELL stream"
        return false
    end
    
    let libc = ffi_open("libc.so.6")
    if libc == nil:
        libc = ffi_open("libc.so")
    end
    if libc == nil:
        libc = ffi_open("")
    end
    if libc == nil:
        print "Error: libc FFI not available on client"
        stream.stream_close(mux, s)
        return false
    end

    # Thread to read from stream and write to client stdout
    proc stream_to_stdout():
        let write_buf = mem_alloc(4096)
        while not s["closed"] and mux["running"]:
            let msg = stream.stream_read_msg(s)
            if msg == nil:
                break
            end
            
            if msg["msg_type"] == stream.SHELL_DATA:
                let payload = utils.to_list(msg["payload"])
                let count = len(payload)
                if count > 0:
                    for i in range(count):
                        mem_write(write_buf, i, "byte", payload[i])
                    end
                    ffi_call(libc, "write", "int", [1, write_buf, count]) # write to fd 1 (stdout)
                end
            end
        end
        mem_free(write_buf)
    end
    thread.spawn(stream_to_stdout)
    
    # Main thread reads from client stdin (fd 0) and writes to stream
    let read_buf = mem_alloc(4096)
    while not s["closed"] and mux["running"]:
        let nread = ffi_call(libc, "read", "int", [0, read_buf, 4096]) # read from fd 0 (stdin)
        if nread <= 0:
            break
        end
        
        let data = []
        for i in range(nread):
            push(data, mem_read(read_buf, i, "byte"))
        end
        
        if not stream.stream_write_msg(mux, s, stream.SHELL_DATA, utils.bytes(data)):
            break
        end
    end
    
    mem_free(read_buf)
    ffi_close(libc)
    stream.stream_close(mux, s)
    return true
end
