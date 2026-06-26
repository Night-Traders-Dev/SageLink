# sagelink/transport/replay_window.sage
# Sliding window replay protection for SageLink transport frames

proc create_replay_window():
    let w = {}
    w["max_seen"] = -1
    let bitmap = []
    for i in range(64):
        push(bitmap, false)
    end
    w["bitmap"] = bitmap
    return w

proc check_replay(w, counter):
    if counter < 0:
        return false
    end
    
    if w["max_seen"] == -1:
        return true
    end

    if counter > w["max_seen"]:
        return true
    end

    let diff = w["max_seen"] - counter
    if diff >= 64:
        return false
    end

    if w["bitmap"][diff]:
        return false
    end

    return true

proc commit_replay(w, counter):
    if w["max_seen"] == -1:
        w["max_seen"] = counter
        w["bitmap"][0] = true
        return
    end
    
    if counter > w["max_seen"]:
        let diff = counter - w["max_seen"]
        if diff >= 64:
            for i in range(64):
                w["bitmap"][i] = false
            end
        else:
            let new_bitmap = []
            for i in range(64):
                push(new_bitmap, false)
            end
            for i in range(64 - diff):
                new_bitmap[i + diff] = w["bitmap"][i]
            end
            w["bitmap"] = new_bitmap
        end
        w["max_seen"] = counter
        w["bitmap"][0] = true
        return
    end
    
    let diff = w["max_seen"] - counter
    if diff >= 64:
        return
    end
    
    w["bitmap"][diff] = true
