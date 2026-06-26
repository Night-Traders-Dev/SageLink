# sagelink/transport/framing.sage
# Wire framing and transport encryption/decryption for SageLink

import crypto.aead as aead
import sagelink.transport.replay_window as replay_window
import sagelink.utils as utils

proc uint32_to_bytes(val):
    let b = [0, 0, 0, 0]
    let temp = val
    for i in range(4):
        let byte_val = temp % 256
        b[3 - i] = byte_val
        temp = (temp - byte_val) / 256
    end
    return b

proc bytes_to_uint32(b):
    let val = 0
    for i in range(4):
        val = val * 256 + b[i]
    end
    return val

proc uint64_to_bytes(val):
    let b = [0, 0, 0, 0, 0, 0, 0, 0]
    let temp = val
    for i in range(8):
        let byte_val = temp % 256
        b[7 - i] = byte_val
        temp = (temp - byte_val) / 256
    end
    return b

proc bytes_to_uint64(b):
    let val = 0
    for i in range(8):
        val = val * 256 + b[i]
    end
    return val

# Encrypts a plaintext (list of bytes or bytes object) into an outer frame (bytes object)
proc encrypt_frame(key, counter, plaintext):
    # Nonce format: 0x00000000 || counter (8 bytes, big-endian)
    let nonce = [0, 0, 0, 0]
    let counter_bytes = uint64_to_bytes(counter)
    for i in range(8):
        push(nonce, counter_bytes[i])
    end
    
    # AEAD encrypt
    let aead_out = aead.chacha20_poly1305_encrypt(key, nonce, plaintext, [])
    let ciphertext = aead_out["ciphertext"]
    let tag = aead_out["tag"]
    
    # Construct final frame payload: counter (8 bytes) + ciphertext + tag
    let payload = []
    for i in range(8):
        push(payload, counter_bytes[i])
    end
    for i in range(len(ciphertext)):
        push(payload, ciphertext[i])
    end
    for i in range(len(tag)):
        push(payload, tag[i])
    end
    
    # Total length of payload is 8 + len(ciphertext) + 16
    let len_bytes = uint32_to_bytes(len(payload))
    
    # Prefix with length (4 bytes)
    let frame_bytes = []
    for i in range(4):
        push(frame_bytes, len_bytes[i])
    end
    for i in range(len(payload)):
        push(frame_bytes, payload[i])
    end
    
    return utils.bytes(frame_bytes)

# Decrypts a frame payload (excluding the length prefix, which was read from the socket)
proc decrypt_frame(key, window, frame_payload_bytes):
    if len(frame_payload_bytes) < 8 + 16:
        return nil
    end
    
    let counter_bytes = []
    for i in range(8):
        push(counter_bytes, frame_payload_bytes[i])
    end
    let counter = bytes_to_uint64(counter_bytes)
    
    if not replay_window.check_replay(window, counter):
        return nil
    end
    
    let ciphertext = []
    let tag_start = len(frame_payload_bytes) - 16
    for i in range(8, tag_start):
        push(ciphertext, frame_payload_bytes[i])
    end
    
    let tag = []
    for i in range(tag_start, len(frame_payload_bytes)):
        push(tag, frame_payload_bytes[i])
    end
    
    let nonce = [0, 0, 0, 0]
    for i in range(8):
        push(nonce, counter_bytes[i])
    end
    
    let decrypted = aead.chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, [])
    if decrypted == nil:
        return nil
    end
    
    replay_window.commit_replay(window, counter)

    return {"plaintext": decrypted, "counter": counter}

# Helper to read one full decrypted frame from a socket
proc read_frame(sock, key, window):
    import tcp
    # Read length prefix (4 bytes) as bytes
    let len_raw = tcp.recvall(sock, 4, true)
    if len_raw == nil or len(len_raw) < 4:
        return nil
    end
    
    let len_val = bytes_to_uint32(len_raw)
    if len_val < 8 + 16:
        return nil
    end
    if len_val > 1048576: # 1MB limit
        return nil
    end
    
    # Read payload bytes
    let payload_raw = tcp.recvall(sock, len_val, true)
    if payload_raw == nil or len(payload_raw) < len_val:
        return nil
    end
    
    return decrypt_frame(key, window, payload_raw)

# Helper to write one frame to a socket
proc write_frame(sock, key, counter, plaintext):
    import tcp
    let frame = encrypt_frame(key, counter, plaintext)
    return tcp.sendall(sock, frame)
