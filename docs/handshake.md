# Handshake — Noise_IK

## Protocol

`Noise_IK_25519_ChaChaPoly_BLAKE2s` — a 1-round-trip mutual-authenticated key agreement protocol defined in the [Noise Protocol Framework](https://noiseprotocol.org/noise.html).

Both parties already know each other's static X25519 public key (pinned in `peers.toml`). The handshake provides mutual authentication and a shared secret in a single round trip, with the initiator's identity hidden from passive observers.

### Message Flow

```
Initiator (A)                          Responder (B)
  e = generate_keypair()
  msg1 = e.pub
       || AEAD_encrypt(k_es, A.static.pub)
       || AEAD_encrypt(k_ss, payload)
  ------------------------------------->
                                         verify A.static.pub against peers
                                         e' = generate_keypair()
  <-------------------------------------
  msg2 = e'.pub || AEAD_encrypt(k_se, payload)

  Both sides derive send_key and recv_key via HKDF
```

### Token Sequence

| Message | Tokens | DH Operations |
|---|---|---|
| msg1 → | `e, es, s, ss` | DH(e, B_static), DH(A_static, B_static) |
| msg2 ← | `e, ee, se` | DH(e, e'), DH(B_static, e') |

### Symmetric State

The handshake maintains four state variables per the Noise spec:

- **`h`** (hash) — chaining hash of all exchanged data, used as AEAD associated data
- **`ck`** (chaining key) — mixed via DH outputs, used as input keying material for HKDF
- **`k`** (cipher key) — current AEAD key; nil until first `mix_key` call
- **`n`** (nonce) — resets to 0 each time `k` is updated

### Key Derivation

After msg2 is processed, `split_handshake()` produces two 32-byte keys:

```
temp  = HKDF_extract(ck, [])
okm   = HKDF_expand(temp, [], 64)
send_key = okm[0:32]
recv_key = okm[32:64]
```

For the responder, send and recv are swapped so that each direction has its own key+counter pair.

### Functions

| Function | Purpose |
|---|---|
| `initialize_handshake(role, static_keypair, remote_pub)` | Create initial handshake state with protocol hash |
| `write_message_1(hs, payload)` | Initiator builds msg1 (ephemeral + encrypted static + encrypted payload) |
| `read_message_1(hs, msg)` | Responder parses msg1, returns remote static key + payload |
| `write_message_2(hs, payload)` | Responder builds msg2 (ephemeral + encrypted payload) |
| `read_message_2(hs, msg)` | Initiator parses msg2, returns payload |
| `split_handshake(hs)` | Derive per-direction transport keys |
| `generate_keypair()` | Generate ephemeral X25519 keypair from `/dev/urandom` |
| `mix_hash(hs, data)` | Hash chaining step |
| `mix_key(hs, ikm)` | DH output mixed into chaining key + cipher key via HKDF |
| `encrypt_and_hash(hs, plaintext)` | AEAD encrypt with current key, then mix_hash ciphertext |
| `decrypt_and_hash(hs, ciphertext)` | AEAD decrypt, then mix_hash ciphertext |
