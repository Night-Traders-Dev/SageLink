# sagelink/utils.sage
# Common compiler compatibility utilities for SageLink

# Renamed from `bytes` to `to_bytes`.
#
# This proc used to be called `bytes`, which shadowed the builtin of the same
# name. Inside the proc, `bytes_new(arr)` was called to reach the real
# constructor -- but there is no `bytes_new` builtin (the constructor is
# registered as `bytes`), so it raised "Undefined variable 'bytes_new'" and the
# proc always returned nil. Rewriting the call to `bytes(arr)` was not an option
# either: the proc shadows the builtin, so that recurses until the stack limit.
#
# Every caller already used the qualified form `utils.to_bytes(...)`, so the rename
# is mechanical. With the shadowing gone the real builtin is reachable and this
# actually produces a bytes object.
proc to_bytes(data):
    if data == nil:
        return nil
    let t = type(data)
    if t == "bytes":
        return data
    let arr = []
    if t == "string" or t == "str":
        for i in range(len(data)):
            push(arr, ord(data[i]))
    else:
        for i in range(len(data)):
            push(arr, data[i])
    return bytes(arr)

# Convert a string or bytes object to a list of byte values.
#
# The nil-guard below used to substitute 0 for a character ord() could not
# decode, which turns a parse error into silently corrupted binary data. This is
# applied to handshake static public keys and nonce material, so a byte that
# fails to decode would become 0x00 inside a key rather than failing the parse.
# It now raises instead: a key that cannot be decoded must not be used.
proc to_list(b):
    if b == nil:
        return nil
    let out = []
    let t = type(b)
    if t == "string" or t == "str":
        for i in range(len(b)):
            let c = ord(b[i])
            if c == nil:
                raise "to_list: cannot decode byte at offset " + str(i) + " (type " + t + ")"
            push(out, c)
    else:
        for i in range(len(b)):
            push(out, b[i])
    return out
