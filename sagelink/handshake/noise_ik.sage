# sagelink/handshake/noise_ik.sage
# Noise_IK_25519_ChaChaPoly_BLAKE2s Handshake State Machine

import crypto.x25519 as x25519
import crypto.blake2s as blake2s
import crypto.hkdf as hkdf
import crypto.aead as aead
import crypto.rand as rand

let PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_BLAKE2s"

proc concat_bytes(a, b):
    let r = []
    let a_bytes = blake2s.to_byte_list(a)
    let b_bytes = blake2s.to_byte_list(b)
    for i in range(len(a_bytes)):
        push(r, a_bytes[i])
    end
    for i in range(len(b_bytes)):
        push(r, b_bytes[i])
    end
    return r

proc mix_hash(hs, data):
    let data_bytes = blake2s.to_byte_list(data)
    hs["h"] = blake2s.blake2s(concat_bytes(hs["h"], data_bytes))

proc mix_key(hs, ikm):
    let temp = hkdf.hkdf_extract(hs["ck"], ikm)
    let okm = hkdf.hkdf_expand(temp, [], 64)
    hs["ck"] = slice(okm, 0, 32)
    hs["k"] = slice(okm, 32, 64)
    hs["n"] = 0

proc encrypt_and_hash(hs, plaintext):
    let pt_bytes = blake2s.to_byte_list(plaintext)
    if hs["k"] == nil:
        mix_hash(hs, pt_bytes)
        return pt_bytes
    end
    
    # encode hs["n"] as 12-byte big-endian nonce
    let nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let val = hs["n"]
    for i in range(8):
        let byte_val = val % 256
        nonce[11 - i] = byte_val
        val = (val - byte_val) / 256
    end
    
    let aead_out = aead.chacha20_poly1305_encrypt(hs["k"], nonce, pt_bytes, hs["h"])
    let ciphertext = concat_bytes(aead_out["ciphertext"], aead_out["tag"])
    mix_hash(hs, ciphertext)
    hs["n"] = hs["n"] + 1
    return ciphertext

proc decrypt_and_hash(hs, ciphertext):
    let ct_bytes = blake2s.to_byte_list(ciphertext)
    if hs["k"] == nil:
        mix_hash(hs, ct_bytes)
        return ct_bytes
    end
    
    if len(ct_bytes) < 16:
        return nil
    end
    let tag_start = len(ct_bytes) - 16
    let ct = slice(ct_bytes, 0, tag_start)
    let tag = slice(ct_bytes, tag_start, len(ct_bytes))
    
    # encode hs["n"] as 12-byte big-endian nonce
    let nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let val = hs["n"]
    for i in range(8):
        let byte_val = val % 256
        nonce[11 - i] = byte_val
        val = (val - byte_val) / 256
    end
    
    let decrypted = aead.chacha20_poly1305_decrypt(hs["k"], nonce, ct, tag, hs["h"])
    if decrypted == nil:
        return nil
    end
    mix_hash(hs, ct_bytes)
    hs["n"] = hs["n"] + 1
    return decrypted

proc get_u_base():
    let u_base = []
    push(u_base, 9)
    for i in range(31):
        push(u_base, 0)
    end
    return u_base

proc generate_keypair():
    let priv = rand.get_urandom_bytes(32)
    let pub = x25519.x25519(priv, get_u_base())
    return {"priv": priv, "pub": pub}

proc initialize_handshake(role, static_keypair, remote_static_pub = nil):
    let hs = {}
    hs["role"] = role
    hs["s_a"] = static_keypair
    hs["s_b"] = remote_static_pub
    
    # Initialize symmetric state
    let proto_hash = blake2s.blake2s(PROTOCOL_NAME)
    hs["h"] = proto_hash
    hs["ck"] = proto_hash
    hs["k"] = nil
    hs["n"] = 0
    
    # Mix B's static public key (pre-shared)
    if role == "initiator":
        mix_hash(hs, remote_static_pub)
    else:
        mix_hash(hs, static_keypair["pub"])
    end
    
    return hs

proc write_message_1(hs, payload):
    # -> e, es, s, ss
    hs["e"] = generate_keypair()
    let msg = concat_bytes([], hs["e"]["pub"])
    mix_hash(hs, hs["e"]["pub"])
    
    let dh_es = x25519.x25519(hs["e"]["priv"], hs["s_b"])
    mix_key(hs, dh_es)
    
    let encrypted_s = encrypt_and_hash(hs, hs["s_a"]["pub"])
    msg = concat_bytes(msg, encrypted_s)
    
    let dh_ss = x25519.x25519(hs["s_a"]["priv"], hs["s_b"])
    mix_key(hs, dh_ss)
    
    let encrypted_payload = encrypt_and_hash(hs, payload)
    msg = concat_bytes(msg, encrypted_payload)
    return msg

proc read_message_1(hs, msg):
    # -> e, es, s, ss
    if len(msg) < 80:
        return nil
    end
    
    let re_pub = slice(msg, 0, 32)
    hs["re"] = re_pub
    mix_hash(hs, re_pub)
    
    let dh_es = x25519.x25519(hs["s_a"]["priv"], re_pub)
    mix_key(hs, dh_es)
    
    let encrypted_s = slice(msg, 32, 80)
    let rs_pub = decrypt_and_hash(hs, encrypted_s)
    if rs_pub == nil:
        return nil
    end
    hs["rs"] = rs_pub
    
    let dh_ss = x25519.x25519(hs["s_a"]["priv"], rs_pub)
    mix_key(hs, dh_ss)
    
    let encrypted_payload = slice(msg, 80, len(msg))
    let payload = decrypt_and_hash(hs, encrypted_payload)
    if payload == nil:
        return nil
    end
    
    return {"payload": payload, "rs": rs_pub}

proc write_message_2(hs, payload):
    # <- e, ee, se
    hs["e"] = generate_keypair()
    let msg = concat_bytes([], hs["e"]["pub"])
    mix_hash(hs, hs["e"]["pub"])
    
    let dh_ee = x25519.x25519(hs["e"]["priv"], hs["re"])
    mix_key(hs, dh_ee)
    
    let dh_se = x25519.x25519(hs["e"]["priv"], hs["rs"])
    mix_key(hs, dh_se)
    
    let encrypted_payload = encrypt_and_hash(hs, payload)
    msg = concat_bytes(msg, encrypted_payload)
    return msg

proc read_message_2(hs, msg):
    # <- e, ee, se
    if len(msg) < 48:
        return nil
    end
    
    let re_pub = slice(msg, 0, 32)
    hs["re"] = re_pub
    mix_hash(hs, re_pub)
    
    let dh_ee = x25519.x25519(hs["e"]["priv"], re_pub)
    mix_key(hs, dh_ee)
    
    let dh_se = x25519.x25519(hs["s_a"]["priv"], re_pub)
    mix_key(hs, dh_se)
    
    let encrypted_payload = slice(msg, 32, len(msg))
    let payload = decrypt_and_hash(hs, encrypted_payload)
    if payload == nil:
        return nil
    end
    
    return {"payload": payload}

proc split_handshake(hs):
    let temp = hkdf.hkdf_extract(hs["ck"], [])
    let okm = hkdf.hkdf_expand(temp, [], 64)
    let send_key = slice(okm, 0, 32)
    let recv_key = slice(okm, 32, 64)
    if hs["role"] == "responder":
        let temp_k = send_key
        send_key = recv_key
        recv_key = temp_k
    end
    return {"send": send_key, "recv": recv_key}
