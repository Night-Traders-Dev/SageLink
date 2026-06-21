# test_integration.sage
# Integration test for SageLink handshake, multiplexing, and CMD service

import tcp
import thread
import sys
import sagelink.handshake.noise_ik as noise_ik
import sagelink.mux.stream as stream
import sagelink.app.cmd as cmd

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
    let mux = stream.create_mux(sock, bob_transport["send"], bob_transport["recv"])
    
    # Setup Incoming Stream Callback
    proc server_stream_dispatcher(m, s):
        if s["service"] == "CMD":
            proc run_cmd():
                cmd.handle_cmd_stream(m, s)
            end
            thread.spawn(run_cmd)
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
    let mux = stream.create_mux(sock, alice_transport["send"], alice_transport["recv"])
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
