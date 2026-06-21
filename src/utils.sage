# sagelink/utils.sage
# Common compiler compatibility utilities for SageLink

proc bytes(data):
    let s = ""
    for i in range(len(data)):
        s = s + chr(data[i])
    end
    return s
end

proc to_list(b):
    if b == nil:
        return nil
    end
    let out = []
    let t = type(b)
    if t == "string" or t == "str":
        for i in range(len(b)):
            push(out, ord(b[i]))
        end
    else:
        for i in range(len(b)):
            push(out, b[i])
        end
    end
    return out
end
