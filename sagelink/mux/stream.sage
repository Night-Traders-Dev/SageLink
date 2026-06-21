# sagelink/mux/stream.sage
# Stream multiplexing layer for SageLink

import thread
import sagelink.transport.framing as framing

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

proc create_mux(sock, send_key, recv_key):
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
    return mux

# Send a raw encrypted frame
proc mux_send_frame(mux, plaintext):
    thread.lock(mux["write_mutex"])
    let counter = mux["send_counter"]
    mux["send_counter"] = mux["send_counter"] + 1
    let ok = framing.write_frame(mux["sock"], mux["send_key"], counter, plaintext)
    thread.unlock(mux["write_mutex"])
    return ok

# Pack and send a message on a stream
proc mux_send_msg(mux, stream_id, msg_type, payload):
    # Pack msg_type (1B) + stream_id (2B) + payload
    let msg = [msg_type, (stream_id >> 8) & 255, stream_id & 255]
    for i in range(len(payload)):
        push(msg, payload[i])
    end
    return mux_send_frame(mux, bytes(msg))

proc create_stream(stream_id, service_type):
    let s = {}
    s["id"] = stream_id
    s["service"] = service_type
    s["queue"] = []
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
        let payload_bytes = bytes(payload)
        
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
    mux["next_stream_id"] = mux["next_stream_id"] + 1
    let s = create_stream(stream_id, service_type)
    mux["streams"][str(stream_id)] = s
    thread.unlock(mux["streams_mutex"])
    
    # Send CHAN_OPEN
    let payload = []
    for i in range(len(service_type)):
        push(payload, ord(service_type[i]))
    end
    mux_send_msg(mux, stream_id, CHAN_OPEN, bytes(payload))
    return s

# Read next message from a stream (blocks until message arrives or stream is closed)
proc stream_read_msg(s):
    while true:
        thread.lock(s["mutex"])
        if len(s["queue"]) > 0:
            let msg = s["queue"][0]
            # shift element
            let new_q = []
            for i in range(1, len(s["queue"])):
                push(new_q, s["queue"][i])
            end
            s["queue"] = new_q
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
