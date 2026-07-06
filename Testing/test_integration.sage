# test_integration.sage
# Integration test for SageLink handshake, multiplexing, and CMD service

import tcp
import thread
import sys
import io
import sagelink.handshake.noise_ik as noise_ik
import sagelink.mux.stream as stream
import sagelink.app.cmd as cmd
import sagelink.app.file as file_app
import sagelink.app.shell as shell_app

proc to_list(b):
    if b == nil:
        return nil
    end
    let out = []
    for i in range(len(b)):
        push(out, b[i])
    end
    return out

print "========================================="
print "Running SageLink Integration Tests..."
print "========================================="

# 1. Static Keys (Deterministic for separate process support)
let alice_priv = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
]
let alice_pub = noise_ik.x25519.x25519(alice_priv, noise_ik.get_u_base())
let alice_keys = {"priv": alice_priv, "pub": alice_pub}

let bob_priv = [
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2
]
let bob_pub = noise_ik.x25519.x25519(bob_priv, noise_ik.get_u_base())
let bob_keys = {"priv": bob_priv, "pub": bob_pub}

# Server (Bob) execution target
proc run_server():
    print "Server: Listening on 127.0.0.1:7420..."
    let listener = tcp.listen("127.0.0.1", 7420)
    if listener == nil:
        print "Server: Failed to listen"
        return
    end
    
    let sock = tcp.accept(listener)
    if sock == nil:
        print "Server: Failed to accept connection"
        tcp.close(listener)
        return
    end
    print "Server: Client connected! Performing Noise_IK handshake..."
    
    # Handshake (Responder)
    let bob_hs = noise_ik.initialize_handshake("responder", bob_keys)
    
    # Read Msg 1 (Alice -> Bob)
    # Wait, how long is msg1? 119 bytes. We can read it from socket using recvall
    print "Server: Reading Msg 1 (expecting 119 bytes)..."
    let msg1 = to_list(tcp.recvall(sock, 119, true))
    if msg1 == nil:
        print "Server: Handshake failed to read Msg 1"
        tcp.close(sock)
        tcp.close(listener)
        return
    end
    print "Server: Msg 1 read (length: " + str(len(msg1)) + "). Parsing..."
    
    let read1 = noise_ik.read_message_1(bob_hs, msg1)
    if read1 == nil:
        print "Server: Handshake failed to parse Msg 1"
        tcp.close(sock)
        tcp.close(listener)
        return
    end
    
    # Write Msg 2 (Bob -> Alice)
    let msg2 = noise_ik.write_message_2(bob_hs, "Welcome, Alice! Glad to establish connection.")
    tcp.sendall(sock, bytes(msg2))
    
    # Deriving split keys
    let bob_transport = noise_ik.split_handshake(bob_hs)
    print "Server: Handshake completed successfully!"
    
    # Initialize Mux
    let mux = stream.create_mux(
        sock, bob_transport["send"], bob_transport["recv"],
        "responder", bob_keys
    )
    
    # Setup Incoming Stream Callback
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
    
    # Wait for client to finish
    while mux["running"]:
        thread.sleep(0.1)
    end
    
    print "Server: Stopping..."
    tcp.close(sock)
    tcp.close(listener)

# Client (Alice) execution target
proc run_client():
    thread.sleep(0.1) # Let server start
    print "Client: Connecting to 127.0.0.1:7420..."
    let sock = tcp.connect("127.0.0.1", 7420)
    if sock == nil:
        print "Client: Connection failed"
        return
    end
    
    print "Client: Initiating Noise_IK handshake..."
    # Handshake (Initiator)
    let alice_hs = noise_ik.initialize_handshake("initiator", alice_keys, bob_keys["pub"])
    print "Client: Handshake initialized. Writing message 1..."
    let msg1 = noise_ik.write_message_1(alice_hs, "Hello, Bob! I am Alice.")
    print "Client: Message 1 written. Sending message 1 (length: " + str(len(msg1)) + ")..."
    tcp.sendall(sock, bytes(msg1))
    print "Client: Message 1 sent. Reading message 2 (expecting 93 bytes)..."
    # Read Msg 2 (Bob -> Alice)
    let msg2 = to_list(tcp.recvall(sock, 93, true))
    if msg2 == nil:
        print "Client: Handshake failed to read Msg 2"
        tcp.close(sock)
        return
    end
    
    let read2 = noise_ik.read_message_2(alice_hs, msg2)
    if read2 == nil:
        print "Client: Handshake failed to parse Msg 2"
        tcp.close(sock)
        return
    end
    
    # Deriving split keys
    let alice_transport = noise_ik.split_handshake(alice_hs)
    print "Client: Handshake completed successfully!"
    
    # Initialize Mux
    let mux = stream.create_mux(
        sock, alice_transport["send"], alice_transport["recv"],
        "initiator", alice_keys, bob_keys["pub"]
    )
    mux["rekey_threshold"] = 5
    stream.start_mux_reader(mux)
    
    # ── Test Remote Command Execution ──
    print "Client: Running remote command 'uname -a'..."
    let res1 = cmd.run_remote_cmd(mux, "uname -a")
    print "Client: Result status: " + str(res1["exit_code"])
    print "Client: Result output:\n" + res1["output"]
    
    print "Client: Running remote command 'ls -la /etc/resolv.conf'..."
    let res2 = cmd.run_remote_cmd(mux, "ls -la /etc/resolv.conf")
    print "Client: Result status: " + str(res2["exit_code"])
    print "Client: Result output:\n" + res2["output"]
    
    # ── Test File Transfer ──
    print "Client: Creating a local test file..."
    let test_content = "Hello! This is a test file for the SageLink chunked FILE transfer service. It is sent over the multiplexed Noise channel!"
    io.writefile("test_send.txt", test_content)
    
    print "Client: Transferring test_send.txt to remote target test_recv.txt..."
    let transfer_ok = file_app.send_file(mux, "test_send.txt", "test_recv.txt")
    print "Client: File transfer status: " + str(transfer_ok)
    
    if transfer_ok:
        print "Client: Verifying remote file contents via CMD..."
        let cat_res = cmd.run_remote_cmd(mux, "cat test_recv.txt")
        print "Client: Remote file contents:\n" + cat_res["output"]
        
        # Clean up files
        sys.shell_exec("rm test_send.txt")
        cmd.run_remote_cmd(mux, "rm test_recv.txt")
    else:
        print "Client: FILE TRANSFER FAILED!"
    end
    
    # ── Test Interactive Shell Execution ──
    print "Client: Opening SHELL stream..."
    let shell_s = stream.mux_open_stream(mux, "SHELL")
    if shell_s != nil:
        # Wait a bit for shell to start
        thread.sleep(0.5)
        
        # Write command to shell
        let shell_cmd = "echo shell_test_confirm\n"
        let cmd_payload = []
        for i in range(len(shell_cmd)):
            push(cmd_payload, ord(shell_cmd[i]))
        end
        stream.stream_write_msg(mux, shell_s, stream.SHELL_DATA, bytes(cmd_payload))
        
        # Read response
        thread.sleep(0.5)
        
        thread.lock(shell_s["mutex"])
        let q_len = len(shell_s["queue"]) - shell_s["queue_head"]
        thread.unlock(shell_s["mutex"])
        
        print "Client: Reading SHELL responses (queue size: " + str(q_len) + ")..."
        while q_len > 0:
            let msg = stream.stream_read_msg(shell_s)
            if msg != nil and msg["msg_type"] == stream.SHELL_DATA:
                let p = to_list(msg["payload"])
                let s_out = ""
                for i in range(len(p)):
                    s_out = s_out + chr(p[i])
                end
                print "Client: Shell output chunk:\n" + s_out
            end
            thread.lock(shell_s["mutex"])
            q_len = len(shell_s["queue"]) - shell_s["queue_head"]
            thread.unlock(shell_s["mutex"])
        end
        
        stream.stream_close(mux, shell_s)
        print "Client: SHELL stream closed."
    else:
        print "Client: Failed to open SHELL stream"
    end
    
    # Shut down mux
    mux["running"] = false
    thread.sleep(0.2)
    tcp.close(sock)
    print "Client: Stopped."

# Execute based on ROLE environment variable or spawn threads as fallback
let role = sys.getenv("ROLE")
if role == "server":
    run_server()
else:
    if role == "client":
        run_client()
    else:
        # Spawn server and client threads
        let server_thread = thread.spawn(run_server)
        let client_thread = thread.spawn(run_client)
        thread.join(server_thread)
        thread.join(client_thread)
        print "========================================="
        print "All integration tests completed!"
        print "========================================="
    end
end
