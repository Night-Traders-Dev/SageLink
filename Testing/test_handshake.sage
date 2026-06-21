# test_handshake.sage
import sagelink.handshake.noise_ik as noise_ik
import crypto.aead as aead
import sys

proc bytes_equal(a, b):
    if len(a) != len(b):
        return false
    for i in range(len(a)):
        if a[i] != b[i]:
            return false
    return true

proc print_hex(bytes):
    let hex_chars = "0123456789abcdef"
    let s = ""
    for i in range(len(bytes)):
        s = s + hex_chars[(bytes[i] >> 4) & 15] + hex_chars[bytes[i] & 15]
    print s

print "========================================="
print "Running SageLink Handshake Integration Tests..."
print "========================================="

# Generate keypairs
print "Generating keypairs..."
let alice_keys = noise_ik.generate_keypair()
let bob_keys = noise_ik.generate_keypair()

print "Alice public key:"
print_hex(alice_keys["pub"])
print "Bob public key:"
print_hex(bob_keys["pub"])

# Initialize handshake states
print "Initializing handshake states..."
let alice_hs = noise_ik.initialize_handshake("initiator", alice_keys, bob_keys["pub"])
let bob_hs = noise_ik.initialize_handshake("responder", bob_keys)

# Message 1
print "Writing message 1 (Alice -> Bob)..."
let payload_1 = "Hello, Bob! I am Alice."
let msg1 = noise_ik.write_message_1(alice_hs, payload_1)
print "Message 1 length: " + str(len(msg1))

print "Reading message 1 on Bob's side..."
let read1 = noise_ik.read_message_1(bob_hs, msg1)
if read1 == nil:
    print " [FAIL] Bob failed to parse message 1"
    sys.exit(1)
end

let parsed_payload_1 = ""
for i in range(len(read1["payload"])):
    parsed_payload_1 = parsed_payload_1 + chr(read1["payload"][i])
print "Bob parsed payload: '" + parsed_payload_1 + "'"

if parsed_payload_1 == payload_1:
    print " [PASS] Payload 1 decrypted successfully"
else:
    print " [FAIL] Payload 1 mismatch"
end

if bytes_equal(read1["rs"], alice_keys["pub"]):
    print " [PASS] Bob correctly identified Alice's static public key"
else:
    print " [FAIL] Static key mismatch"
end

# Message 2
print "Writing message 2 (Bob -> Alice)..."
let payload_2 = "Welcome, Alice! Glad to establish connection."
let msg2 = noise_ik.write_message_2(bob_hs, payload_2)
print "Message 2 length: " + str(len(msg2))

print "Reading message 2 on Alice's side..."
let read2 = noise_ik.read_message_2(alice_hs, msg2)
if read2 == nil:
    print " [FAIL] Alice failed to parse message 2"
    sys.exit(1)
end

let parsed_payload_2 = ""
for i in range(len(read2["payload"])):
    parsed_payload_2 = parsed_payload_2 + chr(read2["payload"][i])
print "Alice parsed payload: '" + parsed_payload_2 + "'"

if parsed_payload_2 == payload_2:
    print " [PASS] Payload 2 decrypted successfully"
else:
    print " [FAIL] Payload 2 mismatch"
end

# Split keys
print "Splitting handshake keys..."
let alice_transport = noise_ik.split_handshake(alice_hs)
let bob_transport = noise_ik.split_handshake(bob_hs)

print "Alice send key:"
print_hex(alice_transport["send"])
print "Bob recv key:"
print_hex(bob_transport["recv"])

print "Alice recv key:"
print_hex(alice_transport["recv"])
print "Bob send key:"
print_hex(bob_transport["send"])

if bytes_equal(alice_transport["send"], bob_transport["recv"]):
    print " [PASS] Alice send key matches Bob recv key"
else:
    print " [FAIL] Key mismatch (A_send vs B_recv)"
end

if bytes_equal(alice_transport["recv"], bob_transport["send"]):
    print " [PASS] Alice recv key matches Bob send key"
else:
    print " [FAIL] Key mismatch (A_recv vs B_send)"
end

# Test transport data frame encryption
print "Testing post-handshake transport encryption..."
let pt = "Top-secret data transmission"
let nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
let aad = []

# Alice encrypts
let enc_out = aead.chacha20_poly1305_encrypt(alice_transport["send"], nonce, pt, aad)

# Bob decrypts
let dec_pt = aead.chacha20_poly1305_decrypt(bob_transport["recv"], nonce, enc_out["ciphertext"], enc_out["tag"], aad)
if dec_pt != nil:
    let dec_str = ""
    for i in range(len(dec_pt)):
        dec_str = dec_str + chr(dec_pt[i])
    if dec_str == pt:
        print " [PASS] Transport encryption and decryption verified"
    else:
        print " [FAIL] Transport plaintext mismatch"
    end
else:
    print " [FAIL] Transport decryption failed"
end

print "========================================="
print "Handshake tests finished."
print "========================================="
