# sagelink/mux/stream.sage
# Stream multiplexing layer for SageLink

import thread
import sagelink.transport.framing as framing
import sagelink.handshake.noise_ik as noise_ik
import sagelink.utils as utils

# Msg Types
let CHAN_OPEN = 0x01
let CHAN_DATA = 0x02
let CHAN_CLOSE = 0x03
let CMD_EXEC = 0x10
let CMD_RESULT = 0x11
let FILE_META = 0x20
let FILE_CHUNK = 0x21
let FILE_ACK = 0x22
let SHELL_DATA = 0x30
let SHELL_RESIZE = 0x31
let PING = 0xF0
let PONG = 0xF1
let REKEY_MSG1 = 0x40
let REKEY_MSG2 = 0x41

proc create_mux(sock, send_key, recv_key, role = nil, local_keys = nil, remote_pub = nil):
    let mux = {}
    mux["sock"] = sock
    mux["send_key"] = send_key
    mux["recv_key"] = recv_key
    mux["send_counter"] = 0
    mux["recv_window"] = framing.replay_window.create_replay_window()
    
    mux["write_mutex"] = thread.mutex()
    mux["streams_mutex"] = thread.mutex()
    mux["streams"] = {}
    mux["next_stream_id"] = 1
    
    mux["reader_thread"] = nil
    mux["running"] = true
    mux["incoming_callback"] = nil
    
    # Rekeying context
    mux["role"] = role
    mux["local_keys"] = local_keys
    mux["remote_pub"] = remote_pub
    mux["rekey_threshold"] = nil
    mux["rekeying"] = false
    mux["rekey_mutex"] = thread.mutex()
    mux["rekey_hs"] = nil
    
    # Pre-populate Control Stream "0"
    mux["streams"]["0"] = create_stream(0, "CONTROL")
    
    return mux

proc zero_key(key):
    if key != nil:
        for i in range(len(key)):
            key[i] = 0
        end
    end
end

proc is_rekey_message(plaintext):
    if len(plaintext) < 3:
        return false
    end
    let msg_type = plaintext[0]
    let stream_id = plaintext[1] * 256 + plaintext[2]
    if stream_id == 0:
        if msg_type == REKEY_MSG1 or msg_type == REKEY_MSG2:
            return true
        end
    end
    return false
end

# Send a raw encrypted frame
proc mux_send_frame(mux, plaintext):
    let is_rekey = is_rekey_message(plaintext)
    
    # If it is a normal message and rekey is in progress, block until rekey is done
    if not is_rekey:
        while true:
            thread.lock(mux["rekey_mutex"])
            let rekeying = mux["rekeying"]
            thread.unlock(mux["rekey_mutex"])
            if not rekeying:
                break
            end
            thread.sleep(0.005)
        end
    end

    thread.lock(mux["write_mutex"])
    let counter = mux["send_counter"]
    mux["send_counter"] = mux["send_counter"] + 1
    let ok = framing.write_frame(mux["sock"], mux["send_key"], counter, plaintext)
    thread.unlock(mux["write_mutex"])
    
    # Check if we should trigger rekey (only if threshold is set, we are initiator, and not already rekeying)
    if ok and not is_rekey and mux["role"] == "initiator" and mux["rekey_threshold"] != nil:
        thread.lock(mux["rekey_mutex"])
        let should_rekey = (mux["send_counter"] >= mux["rekey_threshold"]) and not mux["rekeying"]
        if should_rekey:
            mux["rekeying"] = true
        end
        thread.unlock(mux["rekey_mutex"])
        
        if should_rekey:
            proc run_rekey_async():
                trigger_rekey(mux)
            end
            thread.spawn(run_rekey_async)
        end
    end
    return ok
end

proc trigger_rekey(mux):
    print "Initiator: Triggering rekey process..."
    let hs = noise_ik.initialize_handshake("initiator", mux["local_keys"], mux["remote_pub"])
    mux["rekey_hs"] = hs
    
    let msg1 = noise_ik.write_message_1(hs, "rekey_msg1")
    mux_send_msg(mux, 0, REKEY_MSG1, utils.bytes(msg1))
    
    # The reader thread will receive REKEY_MSG2, process it, and clear mux["rekeying"] to false.
    while true:
        thread.lock(mux["rekey_mutex"])
        let rekeying = mux["rekeying"]
        thread.unlock(mux["rekey_mutex"])
        if not rekeying:
            break
        end
        thread.sleep(0.005)
    end
    print "Initiator: Rekey handshake finished and verified."
end

proc handle_rekey_responder(mux, payload_bytes):
    thread.lock(mux["rekey_mutex"])
    mux["rekeying"] = true
    thread.unlock(mux["rekey_mutex"])
    
    print "Responder: Processing rekey request..."
    let hs = noise_ik.initialize_handshake("responder", mux["local_keys"])
    let msg1_list = utils.to_list(payload_bytes)
    let read1 = noise_ik.read_message_1(hs, msg1_list)
    if read1 == nil:
        print "Responder: Rekey failed to parse Msg 1"
        thread.lock(mux["rekey_mutex"])
        mux["rekeying"] = false
        thread.unlock(mux["rekey_mutex"])
        return
    end
    
    let msg2 = noise_ik.write_message_2(hs, "rekey_msg2")
    mux_send_msg(mux, 0, REKEY_MSG2, utils.bytes(msg2))
    
    let new_keys = noise_ik.split_handshake(hs)
    let old_send = mux["send_key"]
    let old_recv = mux["recv_key"]
    
    thread.lock(mux["write_mutex"])
    mux["send_key"] = new_keys["send"]
    mux["send_counter"] = 0
    thread.unlock(mux["write_mutex"])
    
    mux["recv_key"] = new_keys["recv"]
    mux["recv_window"] = framing.replay_window.create_replay_window()
    
    zero_key(old_send)
    zero_key(old_recv)
    
    print "Responder: Rekey completed successfully!"
    thread.lock(mux["rekey_mutex"])
    mux["rekeying"] = false
    thread.unlock(mux["rekey_mutex"])
end

# Pack and send a message on a stream
proc mux_send_msg(mux, stream_id, msg_type, payload):
    # Pack msg_type (1B) + stream_id (2B) + payload
    let msg = [msg_type, (stream_id >> 8) & 255, stream_id & 255]
    for i in range(len(payload)):
        push(msg, payload[i])
    end
    return mux_send_frame(mux, utils.bytes(msg))

proc create_stream(stream_id, service_type):
    let s = {}
    s["id"] = stream_id
    s["service"] = service_type
    s["queue"] = []
    s["queue_head"] = 0
    s["mutex"] = thread.mutex()
    s["closed"] = false
    return s

# Read loop run by reader thread
proc mux_reader_loop(mux):
    while mux["running"]:
        let frame = framing.read_frame(mux["sock"], mux["recv_key"], mux["recv_window"])
        if frame == nil:
            # Connection lost or decryption failed
            mux["running"] = false
            # Close all streams
            thread.lock(mux["streams_mutex"])
            let ids = dict_keys(mux["streams"])
            for i in range(len(ids)):
                let s = mux["streams"][ids[i]]
                if s != nil:
                    thread.lock(s["mutex"])
                    s["closed"] = true
                    thread.unlock(s["mutex"])
                end
            end
            thread.unlock(mux["streams_mutex"])

            thread.lock(mux["rekey_mutex"])
            mux["rekeying"] = false
            thread.unlock(mux["rekey_mutex"])
            break
        end
        
        let plaintext = frame["plaintext"]
        if len(plaintext) < 3:
            continue
        end
        
        let msg_type = plaintext[0]
        let stream_id = plaintext[1] * 256 + plaintext[2]
        
        # Extract payload
        let payload = []
        for i in range(3, len(plaintext)):
            push(payload, plaintext[i])
        end
        let payload_bytes = utils.bytes(payload)
        
        if stream_id == 0:
            if msg_type == REKEY_MSG1:
                handle_rekey_responder(mux, payload_bytes)
            else:
                if msg_type == REKEY_MSG2:
                    let hs = mux["rekey_hs"]
                    if hs != nil:
                        let msg2_list = utils.to_list(payload_bytes)
                        let read2 = noise_ik.read_message_2(hs, msg2_list)
                        if read2 != nil:
                            let new_keys = noise_ik.split_handshake(hs)
                            let old_send = mux["send_key"]
                            let old_recv = mux["recv_key"]
                            
                            thread.lock(mux["write_mutex"])
                            mux["send_key"] = new_keys["send"]
                            mux["send_counter"] = 0
                            thread.unlock(mux["write_mutex"])
                            
                            mux["recv_key"] = new_keys["recv"]
                            mux["recv_window"] = framing.replay_window.create_replay_window()
                            
                            zero_key(old_send)
                            zero_key(old_recv)
                            
                            print "Initiator: Rekey completed successfully!"
                        else:
                            print "Initiator: Rekey failed to parse Msg 2"
                        end
                        mux["rekey_hs"] = nil
                        thread.lock(mux["rekey_mutex"])
                        mux["rekeying"] = false
                        thread.unlock(mux["rekey_mutex"])
                    end
                end
            end
            continue
        end
        
        thread.lock(mux["streams_mutex"])
        let stream = mux["streams"][str(stream_id)]
        thread.unlock(mux["streams_mutex"])
        
        if stream != nil:
            if msg_type == CHAN_CLOSE:
                thread.lock(stream["mutex"])
                stream["closed"] = true
                thread.unlock(stream["mutex"])
            else:
                thread.lock(stream["mutex"])
                push(stream["queue"], {"msg_type": msg_type, "payload": payload_bytes})
                thread.unlock(stream["mutex"])
            end
        else:
            # New incoming stream open request (for responder side)
            if msg_type == CHAN_OPEN:
                let service_type = ""
                for i in range(len(payload_bytes)):
                    service_type = service_type + chr(payload_bytes[i])
                end
                
                let new_s = create_stream(stream_id, service_type)
                thread.lock(mux["streams_mutex"])
                mux["streams"][str(stream_id)] = new_s
                thread.unlock(mux["streams_mutex"])
                
                if mux["incoming_callback"] != nil:
                    mux["incoming_callback"](mux, new_s)
                end
            end
        end
    end

proc start_mux_reader(mux, incoming_callback = nil):
    mux["incoming_callback"] = incoming_callback
    proc run_reader():
        mux_reader_loop(mux)
    end
    mux["reader_thread"] = thread.spawn(run_reader)

# Client opens a stream
proc mux_open_stream(mux, service_type):
    thread.lock(mux["streams_mutex"])
    let stream_id = mux["next_stream_id"]

    let attempts = 0
    while stream_id == 0 or mux["streams"][str(stream_id)] != nil:
        stream_id = stream_id + 1
        if stream_id >= 65536:
            stream_id = 1
        end
        attempts = attempts + 1
        if attempts >= 65536:
            thread.unlock(mux["streams_mutex"])
            return nil
        end
    end

    mux["next_stream_id"] = stream_id + 1
    if mux["next_stream_id"] >= 65536:
        mux["next_stream_id"] = 1
    end

    let s = create_stream(stream_id, service_type)
    mux["streams"][str(stream_id)] = s
    thread.unlock(mux["streams_mutex"])
    
    # Send CHAN_OPEN
    let payload = []
    for i in range(len(service_type)):
        push(payload, ord(service_type[i]))
    end
    mux_send_msg(mux, stream_id, CHAN_OPEN, utils.bytes(payload))
    return s

# Read next message from a stream (blocks until message arrives or stream is closed)
proc stream_read_msg(s):
    while true:
        thread.lock(s["mutex"])
        if len(s["queue"]) > s["queue_head"]:
            let msg = s["queue"][s["queue_head"]]
            s["queue_head"] = s["queue_head"] + 1

            # compact to avoid unbounded growth
            if s["queue_head"] >= 1024:
                let new_q = []
                for i in range(s["queue_head"], len(s["queue"])):
                    push(new_q, s["queue"][i])
                end
                s["queue"] = new_q
                s["queue_head"] = 0
            end

            thread.unlock(s["mutex"])
            return msg
        end
        if s["closed"]:
            thread.unlock(s["mutex"])
            return nil
        end
        thread.unlock(s["mutex"])
        thread.sleep(0.005)
    end

# Write message to a stream
proc stream_write_msg(mux, s, msg_type, payload):
    return mux_send_msg(mux, s["id"], msg_type, payload)

# Close a stream
proc stream_close(mux, s):
    thread.lock(s["mutex"])
    s["closed"] = true
    thread.unlock(s["mutex"])
    
    # Send CHAN_CLOSE
    mux_send_msg(mux, s["id"], CHAN_CLOSE, [])
    
    # Remove from streams map
    thread.lock(mux["streams_mutex"])
    mux["streams"][str(s["id"])] = nil
    thread.unlock(mux["streams_mutex"])
