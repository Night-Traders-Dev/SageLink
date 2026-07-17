# sagelink/app/file.sage
# FILE service for chunked file transfer via SageLink

import io
import crypto.hash as hash
import sagelink.mux.stream as stream
import sagelink.transport.framing as framing
import sagelink.utils as utils

# FFI helpers for file I/O
proc ffi_open_libc():
    let libc = ffi_open("libc.so.6")
    if libc == nil:
        libc = ffi_open("libc.so")
    end
    if libc == nil:
        libc = ffi_open("")
    end
    return libc
end

proc ffi_open_write(filename):
    let libc = ffi_open_libc()
    if libc == nil:
        return {"ok": false}
    end
    # O_WRONLY | O_CREAT | O_TRUNC = 1 | 64 | 512 = 577
    let fd = ffi_call(libc, "open", "int", [filename, 577, 438])  # 438 = 0o666
    if fd < 0:
        ffi_close(libc)
        return {"ok": false}
    end
    return {"ok": true, "fd": fd, "libc": libc}
end

proc ffi_open_read(filename):
    let libc = ffi_open_libc()
    if libc == nil:
        return {"ok": false}
    end
    # O_RDONLY = 0
    let fd = ffi_call(libc, "open", "int", [filename, 0])
    if fd < 0:
        ffi_close(libc)
        return {"ok": false}
    end
    return {"ok": true, "fd": fd, "libc": libc}
end

proc ffi_read(libc, fd, buf, count):
    return ffi_call(libc, "read", "int", [fd, buf, count])
end

proc ffi_write(libc, fd, buf, count):
    return ffi_call(libc, "write", "int", [fd, buf, count])
end

proc ffi_close_fd(libc, fd):
    if libc != nil and fd >= 0:
        ffi_call(libc, "close", "int", [fd])
    end
    if libc != nil:
        ffi_close(libc)
    end
end

# Client function to send a file to the remote side
# Returns true on success, false on failure
proc send_file(mux, local_path, remote_dest):
    # 1. Open local file for streaming read via FFI
    let open_res = ffi_open_read(local_path)
    if not open_res["ok"]:
        print "Error: Failed to open local file " + local_path
        return false
    end
    let fd = open_res["fd"]
    let libc = open_res["libc"]
    
    # Get file size via fstat
    let stat_buf = mem_alloc(144)
    let fstat_res = ffi_call(libc, "fstat", "int", [fd, stat_buf])
    if fstat_res < 0:
        print "Error: Failed to stat file " + local_path
        ffi_close_fd(libc, fd)
        return false
    end
    let file_size = mem_read(stat_buf, 48, "u64")  # st_size offset on Linux x86_64
    mem_free(stat_buf)
    
    # Compute hash incrementally
    let hasher = hash.sha256_init()
    let read_buf = mem_alloc(16384)
    let total_read = 0
    
    while total_read < file_size:
        let nread = ffi_read(libc, fd, read_buf, 16384)
        if nread <= 0:
            break
        end
        let chunk = []
        for i in range(nread):
            push(chunk, mem_read(read_buf, i, "byte"))
        end
        hash.sha256_update(hasher, chunk)
        total_read = total_read + nread
    end
    
    let file_hash = hash.sha256_final(hasher)
    
    # Close and reopen for sending (or seek to start)
    ffi_close_fd(libc, fd)
    
    let open_res2 = ffi_open_read(local_path)
    if not open_res2["ok"]:
        print "Error: Failed to reopen local file " + local_path
        return false
    end
    let fd2 = open_res2["fd"]
    let libc2 = open_res2["libc"]
    
    # 2. Open a FILE stream
    let s = stream.mux_open_stream(mux, "FILE")
    if s == nil:
        print "Error: Failed to open FILE stream"
        ffi_close_fd(libc2, fd2)
        return false
    end
    
    # 3. Send FILE_META message
    # Format: filename_len (2B) + filename (str) + file_size (8B) + sha256 (32B)
    let dest_bytes = []
    for i in range(len(remote_dest)):
        push(dest_bytes, ord(remote_dest[i]))
    end
    let dest_len = len(dest_bytes)
    
    let meta_payload = []
    push(meta_payload, (dest_len >> 8) & 255)
    push(meta_payload, dest_len & 255)
    for i in range(dest_len):
        push(meta_payload, dest_bytes[i])
    end
    
    let size_bytes = framing.uint64_to_bytes(file_size)
    for i in range(8):
        push(meta_payload, size_bytes[i])
    end
    
    for i in range(32):
        push(meta_payload, file_hash[i])
    end
    
    if not stream.stream_write_msg(mux, s, stream.FILE_META, utils.bytes(meta_payload)):
        stream.stream_close(mux, s)
        ffi_close_fd(libc2, fd2)
        return false
    end
    
    # 4. Stream chunks with sliding-window flow control
    let chunk_size = 16384   # 16KB chunk size
    let window_size = 65536  # 64KB window size
    let sent_offset = 0
    let acked_offset = 0
    
    let read_buf2 = mem_alloc(16384)
    
    while sent_offset < file_size:
        # If the window is full, block and wait for an ACK
        while sent_offset - acked_offset + chunk_size > window_size:
            let msg = stream.stream_read_msg(s)
            if msg == nil:
                print "Error: Stream closed while waiting for ACK"
                stream.stream_close(mux, s)
                mem_free(read_buf2)
                ffi_close_fd(libc2, fd2)
                return false
            end
            if msg["msg_type"] == stream.FILE_ACK:
                acked_offset = framing.bytes_to_uint64(utils.to_list(msg["payload"]))
            end
        end
        
        # Read next chunk
        let current_chunk_size = chunk_size
        if sent_offset + current_chunk_size > file_size:
            current_chunk_size = file_size - sent_offset
        end
        
        let nread = ffi_read(libc2, fd2, read_buf2, current_chunk_size)
        if nread <= 0:
            print "Error: Failed to read chunk at offset " + str(sent_offset)
            stream.stream_close(mux, s)
            mem_free(read_buf2)
            ffi_close_fd(libc2, fd2)
            return false
        end
        
        let chunk_data = []
        for i in range(nread):
            push(chunk_data, mem_read(read_buf2, i, "byte"))
        end
        
        # FILE_CHUNK Format: offset (8B) + chunk bytes
        let chunk_payload = []
        let offset_bytes = framing.uint64_to_bytes(sent_offset)
        for i in range(8):
            push(chunk_payload, offset_bytes[i])
        end
        for i in range(len(chunk_data)):
            push(chunk_payload, chunk_data[i])
        end
        
        if not stream.stream_write_msg(mux, s, stream.FILE_CHUNK, utils.bytes(chunk_payload)):
            stream.stream_close(mux, s)
            mem_free(read_buf2)
            ffi_close_fd(libc2, fd2)
            return false
        end
        
        sent_offset = sent_offset + current_chunk_size
        
        # Drain any pending ACKs from the queue non-blockingly
        thread.lock(s["mutex"])
        let queue_len = len(s["queue"]) - s["queue_head"]
        thread.unlock(s["mutex"])
        
        while queue_len > 0:
            let msg = stream.stream_read_msg(s)
            if msg != nil and msg["msg_type"] == stream.FILE_ACK:
                acked_offset = framing.bytes_to_uint64(utils.to_list(msg["payload"]))
            end
            thread.lock(s["mutex"])
            queue_len = len(s["queue"]) - s["queue_head"]
            thread.unlock(s["mutex"])
        end
    end
    
    mem_free(read_buf2)
    ffi_close_fd(libc2, fd2)
    
    # 5. Wait for the final ACK confirming writing complete
    while acked_offset < file_size:
        let msg = stream.stream_read_msg(s)
        if msg == nil:
            break
        end
        if msg["msg_type"] == stream.FILE_ACK:
            acked_offset = framing.bytes_to_uint64(utils.to_list(msg["payload"]))
        end
    end
    
    stream.stream_close(mux, s)
    return acked_offset == file_size
end

# Server-side handler for a FILE stream
proc handle_file_stream(mux, s):
    # 1. Read FILE_META
    let msg = stream.stream_read_msg(s)
    if msg == nil or msg["msg_type"] != stream.FILE_META:
        stream.stream_close(mux, s)
        return
    end
    
    let meta_payload = utils.to_list(msg["payload"])
    if len(meta_payload) < 2 + 8 + 32:
        stream.stream_close(mux, s)
        return
    end
    
    let filename_len = meta_payload[0] * 256 + meta_payload[1]
    if len(meta_payload) < 2 + filename_len + 8 + 32:
        stream.stream_close(mux, s)
        return
    end
    
    let filename_raw = ""
    for i in range(filename_len):
        filename_raw = filename_raw + chr(meta_payload[2 + i])
    end

    let filename = ""
    for i in range(len(filename_raw)):
        let c = filename_raw[i]
        if c == "/" or c == "\\":
            filename = ""
        else:
            filename = filename + c
        end
    end
    if filename == "":
        filename = "downloaded_file"
    end
    
    let size_start = 2 + filename_len
    let size_bytes = slice(meta_payload, size_start, size_start + 8)
    let file_size = framing.bytes_to_uint64(size_bytes)
    
    let hash_start = size_start + 8
    let expected_hash = slice(meta_payload, hash_start, hash_start + 32)
    
    # 2. Open file for streaming write via FFI
    let open_res = ffi_open_write(filename)
    if not open_res["ok"]:
        print "Error: Failed to create output file " + filename
        stream.stream_close(mux, s)
        return
    end
    let fd = open_res["fd"]
    let libc = open_res["libc"]
    
    let bytes_written = 0
    let hasher = hash.sha256_init()
    
    # 3. Read incoming chunks
    while bytes_written < file_size:
        let chunk_msg = stream.stream_read_msg(s)
        if chunk_msg == nil:
            break
        end
        
        if chunk_msg["msg_type"] == stream.FILE_CHUNK:
            let chunk_payload = utils.to_list(chunk_msg["payload"])
            if len(chunk_payload) < 8:
                break
            end
            
            let offset_bytes = slice(chunk_payload, 0, 8)
            let offset = framing.bytes_to_uint64(offset_bytes)
            let chunk_data = slice(chunk_payload, 8, len(chunk_payload))
            
            # Verify sequential delivery offset
            if offset == bytes_written:
                # Boundary check: reject chunks that would exceed declared file size
                if bytes_written + len(chunk_data) > file_size:
                    print "Error: Chunk exceeds declared file size"
                    ffi_close_fd(libc, fd)
                    io.remove(filename)
                    stream.stream_close(mux, s)
                    return
                end
                
                # Write chunk to file via FFI
                let write_buf = mem_alloc(len(chunk_data))
                for i in range(len(chunk_data)):
                    mem_write(write_buf, i, "byte", chunk_data[i])
                end
                
                let nwritten = ffi_write(libc, fd, write_buf, len(chunk_data))
                mem_free(write_buf)
                
                if nwritten != len(chunk_data):
                    print "Error: Failed to write chunk to file"
                    ffi_close_fd(libc, fd)
                    io.remove(filename)
                    stream.stream_close(mux, s)
                    return
                end
                
                # Update hash incrementally
                hash.sha256_update(hasher, chunk_data)
                
                bytes_written = bytes_written + len(chunk_data)
                
                # Acknowledge the current cumulative offset
                let ack_payload = framing.uint64_to_bytes(bytes_written)
                stream.stream_write_msg(mux, s, stream.FILE_ACK, utils.bytes(ack_payload))
            else:
                print "Error: Out-of-order chunk offset: " + str(offset) + " expected: " + str(bytes_written)
                break
            end
        end
    end
    
    # 4. Close file
    ffi_close_fd(libc, fd)
    
    # 5. Perform integrity check on file completion
    if bytes_written >= file_size:
        if bytes_written > file_size:
            print "Error: File size exceeded declared size"
            io.remove(filename)
        else:
            let actual_hash = hash.sha256_final(hasher)
            
            let hash_ok = true
            for i in range(32):
                if actual_hash[i] != expected_hash[i]:
                    hash_ok = false
                end
            end
            
            if not hash_ok:
                print "Error: Integrity check failed for " + filename
                # Wipe target file if integrity check failed
                io.remove(filename)
            end
        end
    end
    
    stream.stream_close(mux, s)
end
