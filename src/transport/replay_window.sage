# sagelink/transport/replay_window.sage
# Sliding window replay protection for SageLink transport frames

proc create_replay_window():
    let w = {}
    w["max_seen"] = -1
    let bitmap = []
    for i in range(64):
        push(bitmap, false)
    w["bitmap"] = bitmap
    return w

proc check_replay(w, counter):
    if counter < 0:
        return false
    
    if w["max_seen"] == -1:
        return true

    if counter > w["max_seen"]:
        return true

    let diff = w["max_seen"] - counter
    if diff >= 64:
        return false

    if w["bitmap"][diff]:
        return false

    return true

proc commit_replay(w, counter):
    if w["max_seen"] == -1:
        w["max_seen"] = counter
        w["bitmap"][0] = true
        return
    
    if counter > w["max_seen"]:
        let diff = counter - w["max_seen"]
        if diff >= 64:
            for i in range(64):
                w["bitmap"][i] = false
        else:
            let new_bitmap = []
            for i in range(64):
                push(new_bitmap, false)
            for i in range(64 - diff):
                new_bitmap[i + diff] = w["bitmap"][i]
            w["bitmap"] = new_bitmap
        w["max_seen"] = counter
        w["bitmap"][0] = true
        return
    
    let diff = w["max_seen"] - counter
    if diff >= 64:
        return
    
    w["bitmap"][diff] = true
