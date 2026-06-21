# sagelink/cli/sagelink.sage
# CLI for SageLink keygen, connect, and listen subcommands

import sys
import tcp
import thread
import io
import sagelink.handshake.noise_ik as noise_ik
import sagelink.mux.stream as stream
import sagelink.app.cmd as cmd
import sagelink.app.file as file_app
import sagelink.app.shell as shell_app
import sagelink.utils as utils

let B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

proc b64_encode(data):
    let out = ""
    let i = 0
    let n = len(data)
    while i < n:
        let b1 = data[i]
        let b2 = 0
        if i + 1 < n: b2 = data[i+1] end
        let b3 = 0
        if i + 2 < n: b3 = data[i+2] end
        
        let c1 = b1 >> 2
        let c2 = ((b1 & 3) << 4) | (b2 >> 4)
        let c3 = ((b2 & 15) << 2) | (b3 >> 6)
        let c4 = b3 & 63
        
        out = out + B64_CHARS[c1]
        out = out + B64_CHARS[c2]
        
        if i + 1 < n:
            out = out + B64_CHARS[c3]
        else:
            out = out + "="
        end
        if i + 2 < n:
            out = out + B64_CHARS[c4]
        else:
            out = out + "="
        end
        
        i = i + 3
    end
    return out
end

proc b64_decode(s):
    let data = []
    let i = 0
    let n = len(s)
    let char_map = {}
    for idx in range(len(B64_CHARS)):
        char_map[B64_CHARS[idx]] = idx
    end
    
    while i < n:
        if s[i] == "\n" or s[i] == "\r" or s[i] == " " or s[i] == "\t":
            i = i + 1
            continue
        end
        if i + 3 >= n:
            break
        end
        let c1 = s[i]
        let c2 = s[i+1]
        let c3 = s[i+2]
        let c4 = s[i+3]
        
        # Safe lookup
        let val1 = char_map[c1]
        let val2 = char_map[c2]
        let val3 = 0
        if c3 != "=": val3 = char_map[c3] end
        let val4 = 0
        if c4 != "=": val4 = char_map[c4] end
        
        let b1 = (val1 << 2) | (val2 >> 4)
        let b2 = ((val2 & 15) << 4) | (val3 >> 2)
        let b3 = ((val3 & 3) << 6) | val4
        
        push(data, b1)
        if c3 != "=":
            push(data, b2)
        end
        if c4 != "=":
            push(data, b3)
        end
        i = i + 4
    end
    return data
end

proc str_slice(s, start, end_idx):
    let out = ""
    for i in range(start, end_idx):
        out = out + s[i]
    end
    return out
end

proc parse_peers_toml(content):
    let peers = {}
    let lines = []
    let current_line = ""
    for i in range(len(content)):
        if content[i] == "\n":
            push(lines, current_line)
            current_line = ""
        else:
            if content[i] != "\r":
                current_line = current_line + content[i]
            end
        end
    end
    if len(current_line) > 0:
        push(lines, current_line)
    end
    
    let current_peer = nil
    for idx in range(len(lines)):
        let line = lines[idx]
        
        # Trim leading/trailing spaces
        let start = 0
        while start < len(line) and (line[start] == " " or line[start] == "\t"):
            start = start + 1
        end
        let end_p = len(line)
        while end_p > start and (line[end_p - 1] == " " or line[end_p - 1] == "\t"):
            end_p = end_p - 1
        end
        let trimmed = str_slice(line, start, end_p)
        
        if len(trimmed) == 0 or trimmed[0] == "#":
            continue
        end
        
        if trimmed[0] == "[" and trimmed[len(trimmed)-1] == "]":
            current_peer = str_slice(trimmed, 1, len(trimmed)-1)
            peers[current_peer] = {}
        else:
            if current_peer != nil:
                # Find "="
                let eq_idx = -1
                for j in range(len(trimmed)):
                    if trimmed[j] == "=":
                        eq_idx = j
                        break
                    end
                end
                if eq_idx != -1:
                    let key = str_slice(trimmed, 0, eq_idx)
                    let val = str_slice(trimmed, eq_idx + 1, len(trimmed))
                    
                    # Trim spaces around key and val
                    let k_start = 0
                    while k_start < len(key) and (key[k_start] == " " or key[k_start] == "\t"):
                        k_start = k_start + 1
                    end
                    let k_end = len(key)
                    while k_end > k_start and (key[k_end - 1] == " " or key[k_end - 1] == "\t"):
                        k_end = k_end - 1
                    end
                    key = str_slice(key, k_start, k_end)
                    
                    let v_start = 0
                    while v_start < len(val) and (val[v_start] == " " or val[v_start] == "\t"):
                        v_start = v_start + 1
                    end
                    let v_end = len(val)
                    while v_end > v_start and (val[v_end - 1] == " " or val[v_end - 1] == "\t"):
                        v_end = v_end - 1
                    end
                    val = str_slice(val, v_start, v_end)
                    
                    # Strip quotes from val
                    if len(val) >= 2 and val[0] == "\"" and val[len(val)-1] == "\"":
                        val = str_slice(val, 1, len(val)-1)
                    end
                    peers[current_peer][key] = val
                end
            end
        end
    end
    return peers
end

proc keys_equal(k1, k2):
    if len(k1) != len(k2):
        return false
    end
    for i in range(len(k1)):
        if k1[i] != k2[i]:
            return false
        end
    end
    return true
end

proc run_keygen():
    print "Generating static X25519 keypair..."
    let keypair = noise_ik.generate_keypair()
    let priv_b64 = b64_encode(keypair["priv"])
    let pub_b64 = b64_encode(keypair["pub"])
    
    io.writefile("identity.key", priv_b64 + "\n")
    io.writefile("identity.pub", pub_b64 + "\n")
    sys.shell_exec("chmod 600 identity.key")
    
    print "Keypair generated successfully."
    print "Private key saved to identity.key (mode 0600)."
    print "Public key saved to identity.pub."
    print "Your public key is: " + pub_b64
end

proc load_local_keys():
    let content_bytes = io.readbytes("identity.key")
    if content_bytes == nil:
        print "Error: identity.key not found. Run keygen first."
        return nil
    end
    let priv_b64 = ""
    for i in range(len(content_bytes)):
        priv_b64 = priv_b64 + chr(content_bytes[i])
    end
    let priv_bytes = b64_decode(priv_b64)
    if len(priv_bytes) != 32:
        print "Error: Invalid private key size in identity.key"
        return nil
    end
    let pub_bytes = noise_ik.x25519.x25519(priv_bytes, noise_ik.get_u_base())
    return {"priv": priv_bytes, "pub": pub_bytes}
end

proc load_peers():
    let content_bytes = io.readbytes("peers.toml")
    if content_bytes == nil:
        print "Error: peers.toml not found."
        return nil
    end
    let content = ""
    for i in range(len(content_bytes)):
        content = content + chr(content_bytes[i])
    end
    return parse_peers_toml(content)
end

proc run_listen(port_str = nil):
    let local_keys = load_local_keys()
    if local_keys == nil: return end
    
    let peers = load_peers()
    if peers == nil: return end
    
    let port = 7420
    if port_str != nil:
        let val = 0
        for i in range(len(port_str)):
            val = val * 10 + (ord(port_str[i]) - 48)
        end
        port = val
    end
    
    print "Listening on port " + str(port) + "..."
    let listener = tcp.listen("0.0.0.0", port)
    if listener == nil:
        print "Error: Failed to listen on port " + str(port)
        return
    end
    
    while true:
        let sock = tcp.accept(listener)
        if sock == nil:
            continue
        end
        
        proc handle_client():
            print "Incoming connection accepted. Performing Noise_IK handshake..."
            let bob_hs = noise_ik.initialize_handshake("responder", local_keys)
            
            # Read Msg 1 (expecting 128 bytes: 32 ephemeral + 48 encrypted static + 32 payload + 16 tag)
            let msg1 = utils.to_list(tcp.recvall(sock, 128, true))
            if msg1 == nil:
                print "Error: Handshake failed to read Msg 1"
                tcp.close(sock)
                return
            end
            
            let read1 = noise_ik.read_message_1(bob_hs, msg1)
            if read1 == nil:
                print "Error: Handshake failed to parse Msg 1"
                tcp.close(sock)
                return
            end
            
            let client_pub = read1["rs"]
            let matched_peer = nil
            let peer_keys = dict_keys(peers)
            for i in range(len(peer_keys)):
                let p_name = peer_keys[i]
                let peer_pub_b64 = peers[p_name]["pubkey"]
                if peer_pub_b64 != nil:
                    let peer_pub = b64_decode(peer_pub_b64)
                    if keys_equal(client_pub, peer_pub):
                        matched_peer = p_name
                        break
                    end
                end
            end
            
            if matched_peer == nil:
                print "Authentication Failed: Pinned key mismatch. Dropping connection."
                tcp.close(sock)
                return
            end
            
            print "Peer authenticated successfully: " + matched_peer
            
            # Write Msg 2 with 32-byte padded payload
            let resp_payload = []
            let welcome_str = "welcome"
            for i in range(len(welcome_str)):
                push(resp_payload, ord(welcome_str[i]))
            end
            while len(resp_payload) < 32:
                push(resp_payload, 0)
            end
            
            let msg2 = noise_ik.write_message_2(bob_hs, utils.bytes(resp_payload))
            tcp.sendall(sock, utils.bytes(msg2))
            
            let bob_transport = noise_ik.split_handshake(bob_hs)
            let mux = stream.create_mux(sock, bob_transport["send"], bob_transport["recv"], "responder", local_keys)
            
            proc server_stream_dispatcher(m, s):
                if s["service"] == "CMD":
                    proc run_cmd():
                        cmd.handle_cmd_stream(m, s)
                    end
                    thread.spawn(run_cmd)
                end
                if s["service"] == "FILE":
                    proc run_file():
                        file_app.handle_file_stream(m, s)
                    end
                    thread.spawn(run_file)
                end
                if s["service"] == "SHELL":
                    proc run_shell():
                        shell_app.handle_shell_stream(m, s)
                    end
                    thread.spawn(run_shell)
                end
            end
            
            stream.start_mux_reader(mux, server_stream_dispatcher)
            while mux["running"]:
                thread.sleep(0.5)
            end
            tcp.close(sock)
            print "Connection with " + matched_peer + " closed."
        end
        
        thread.spawn(handle_client)
    end
end

proc parse_addr(addr_str):
    let col_idx = -1
    for i in range(len(addr_str)):
        if addr_str[i] == ":":
            col_idx = i
            break
        end
    end
    if col_idx == -1:
        return {"host": addr_str, "port": 7420}
    end
    let host = str_slice(addr_str, 0, col_idx)
    let port_str = str_slice(addr_str, col_idx + 1, len(addr_str))
    let port = 0
    for i in range(len(port_str)):
        port = port * 10 + (ord(port_str[i]) - 48)
    end
    return {"host": host, "port": port}
end

proc run_connect(peer_name, mode = nil, p1 = nil, p2 = nil):
    let local_keys = load_local_keys()
    if local_keys == nil: return end
    
    let peers = load_peers()
    if peers == nil: return end
    
    let peer = peers[peer_name]
    if peer == nil:
        print "Error: Peer '" + peer_name + "' not found in peers.toml"
        return
    end
    
    let addr_info = parse_addr(peer["addr"])
    let peer_pub = b64_decode(peer["pubkey"])
    
    print "Connecting to " + peer_name + " at " + peer["addr"] + "..."
    let sock = tcp.connect(addr_info["host"], addr_info["port"])
    if sock == nil:
        print "Error: Connection failed"
        return
    end
    
    print "Initiating handshake..."
    let alice_hs = noise_ik.initialize_handshake("initiator", local_keys, peer_pub)
    
    # Write Msg 1 with 32-byte padded payload
    let init_payload = []
    let connect_str = "connect"
    for i in range(len(connect_str)):
        push(init_payload, ord(connect_str[i]))
    end
    while len(init_payload) < 32:
        push(init_payload, 0)
    end
    
    let msg1 = noise_ik.write_message_1(alice_hs, utils.bytes(init_payload))
    tcp.sendall(sock, utils.bytes(msg1))
    
    # Read Msg 2 (expecting 80 bytes: 32 ephemeral + 32 payload + 16 tag)
    let msg2 = utils.to_list(tcp.recvall(sock, 80, true))
    if msg2 == nil:
        print "Error: Handshake failed to read Msg 2"
        tcp.close(sock)
        return
    end
    
    let read2 = noise_ik.read_message_2(alice_hs, msg2)
    if read2 == nil:
        print "Error: Handshake failed to parse Msg 2"
        tcp.close(sock)
        return
    end
    
    let alice_transport = noise_ik.split_handshake(alice_hs)
    print "Handshake completed successfully! Session keys established."
    
    let mux = stream.create_mux(sock, alice_transport["send"], alice_transport["recv"], "initiator", local_keys, peer_pub)
    mux["rekey_threshold"] = 1000
    stream.start_mux_reader(mux)
    
    if mode == nil or mode == "shell":
        print "Opening interactive shell..."
        shell_app.run_client_shell(mux)
    else:
        if mode == "cmd":
            if p1 == nil:
                print "Error: No command specified for cmd mode"
            else:
                print "Running remote command: " + p1
                let res = cmd.run_remote_cmd(mux, p1)
                print "Exit code: " + str(res["exit_code"])
                print "Output:\n" + res["output"]
            end
        else:
            if mode == "file_send":
                if p1 == nil or p2 == nil:
                    print "Error: Usage: connect <peer> file_send <local_path> <remote_path>"
                else:
                    print "Sending file '" + p1 + "' to '" + p2 + "'..."
                    let ok = file_app.send_file(mux, p1, p2)
                    if ok:
                        print "File sent successfully!"
                    else:
                        print "Error: File transfer failed"
                    end
                end
            else:
                print "Error: Unknown connection mode: " + mode
            end
        end
    end
    
    mux["running"] = false
    thread.sleep(0.2)
    tcp.close(sock)
end

proc print_usage():
    print "SageLink CLI Usage:"
    print "  sage sagelink/cli/sagelink.sage keygen"
    print "  sage sagelink/cli/sagelink.sage listen [port]"
    print "  sage sagelink/cli/sagelink.sage connect <peer_name> [mode] [args...]"
    print "Modes for connect:"
    print "  shell (default)                     - Start interactive shell"
    print "  cmd \"<command>\"                     - Run remote command"
    print "  file_send <local_path> <remote_path> - Transfer a file"
end

proc cli_main():
    let args = sys.args()
    if len(args) < 3:
        print_usage()
        return
    end
    
    let cmd = args[2]
    if cmd == "keygen":
        run_keygen()
    else:
        if cmd == "listen":
            let port_str = nil
            if len(args) >= 4:
                port_str = args[3]
            end
            run_listen(port_str)
        else:
            if cmd == "connect":
                if len(args) < 4:
                    print "Error: Specify peer name to connect to."
                    print_usage()
                    return
                end
                let peer_name = args[3]
                let mode = nil
                let p1 = nil
                let p2 = nil
                if len(args) >= 5:
                    mode = args[4]
                end
                if len(args) >= 6:
                    p1 = args[5]
                end
                if len(args) >= 7:
                    p2 = args[6]
                end
                run_connect(peer_name, mode, p1, p2)
            else:
                print "Error: Unknown command: " + cmd
                print_usage()
            end
        end
    end
end

cli_main()
