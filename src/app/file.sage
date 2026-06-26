# sagelink/app/file.sage
# FILE service for chunked file transfer via SageLink

import io
import crypto.hash as hash
import sagelink.mux.stream as stream
import sagelink.transport.framing as framing
import sagelink.utils as utils

# Client function to send a file to the remote side
# Returns true on success, false on failure
proc send_file(mux, local_path, remote_dest):
    # 1. Read the local file into memory
    let file_bytes = io.readbytes(local_path)
    if file_bytes == nil:
        print "Error: Failed to read local file " + local_path
        return false
    end
    
    let file_size = len(file_bytes)
    let file_hash = hash.sha256(file_bytes)
    
    # 2. Open a FILE stream
    let s = stream.mux_open_stream(mux, "FILE")
    if s == nil:
        print "Error: Failed to open FILE stream"
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
        return false
    end
    
    # 4. Stream chunks with sliding-window flow control
    let chunk_size = 16384   # 16KB chunk size
    let window_size = 65536  # 64KB window size
    let sent_offset = 0
    let acked_offset = 0
    
    while sent_offset < file_size:
        # If the window is full, block and wait for an ACK
        while sent_offset - acked_offset + chunk_size > window_size:
            let msg = stream.stream_read_msg(s)
            if msg == nil:
                print "Error: Stream closed while waiting for ACK"
                stream.stream_close(mux, s)
                return false
            end
            if msg["msg_type"] == stream.FILE_ACK:
                acked_offset = framing.bytes_to_uint64(utils.to_list(msg["payload"]))
            end
        end
        
        # Read next chunk slice
        let current_chunk_size = chunk_size
        if sent_offset + current_chunk_size > file_size:
            current_chunk_size = file_size - sent_offset
        end
        
        let chunk_data = slice(file_bytes, sent_offset, sent_offset + current_chunk_size)
        
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
    
    # 2. Initialize target file to be empty
    io.writefile(filename, "")
    let bytes_written = 0
    
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
                io.appendbytes(filename, chunk_data)
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
    
    # 4. Perform integrity check on file completion
    if bytes_written == file_size:
        let written_bytes = io.readbytes(filename)
        let actual_hash = hash.sha256(written_bytes)
        
        let hash_ok = true
        for i in range(32):
            if actual_hash[i] != expected_hash[i]:
                hash_ok = false
            end
        end
        
        if not hash_ok:
            print "Error: Integrity check failed for " + filename
            # Wipe target file if integrity check failed
            io.writefile(filename, "")
        end
    end
    
    stream.stream_close(mux, s)
