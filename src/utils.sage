# sagelink/utils.sage
# Common compiler compatibility utilities for SageLink

proc bytes(data):
    if data == nil:
        return nil
    end
    let t = type(data)
    if t == "bytes":
        return data
    end
    let arr = []
    if t == "string" or t == "str":
        for i in range(len(data)):
            push(arr, ord(data[i]))
        end
    else:
        for i in range(len(data)):
            push(arr, data[i])
        end
    end
    return bytes_new(arr)
end

proc to_list(b):
    if b == nil:
        return nil
    end
    let out = []
    let t = type(b)
    if t == "string" or t == "str":
        for i in range(len(b)):
            let c = ord(b[i])
            if c == nil:
                push(out, 0)
            else:
                push(out, c)
            end
        end
    else:
        for i in range(len(b)):
            push(out, b[i])
        end
    end
    return out
end
