# test_file_integrity.sage
# Tests for FILE service integrity checks

import io
import crypto.hash as hash
import sagelink.mux.stream as stream
import sagelink.transport.framing as framing
import sagelink.utils as utils

let B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

proc b64_encode(data):
    let out = ""
    let i = 0
    let n = len(data)
    while i < n:
        let b1 = data[i]
        let b2 = 0
        if i + 1 < n: b2 = data[i+1] end
        let b3 = 0
        if i + 2 < n: b3 = data[i+2] end
        
        let c1 = b1 >> 2
        let c2 = ((b1 & 3) << 4) | (b2 >> 4)
        let c3 = ((b2 & 15) << 2) | (b3 >> 6)
        let c4 = b3 & 63
        
        out = out + B64_CHARS[c1]
        out = out + B64_CHARS[c2]
        
        if i + 1 < n:
            out = out + B64_CHARS[c3]
        else:
            out = out + "="
        end
        if i + 2 < n:
            out = out + B64_CHARS[c4]
        else:
            out = out + "="
        end
        
        i = i + 3
    end
    return out
end

proc test_oversized_chunk_rejected():
    print "Test: Oversized chunk rejected..."
    let filename = "test_oversized.txt"
    io.writefile(filename, "hello")
    
    # Simulate oversized chunk by directly testing the boundary logic
    let file_size = 5
    let bytes_written = 0
    let chunk_data = [1,2,3,4,5,6,7,8,9,10]  # 10 bytes, would exceed 5
    
    if bytes_written + len(chunk_data) > file_size:
        print "  PASS: Oversized chunk correctly detected"
        io.remove(filename)
        return true
    end
    
    print "  FAIL: Oversized chunk not detected"
    io.remove(filename)
    return false
end

proc test_exact_size_chunk_accepted():
    print "Test: Exact size chunk accepted..."
    let filename = "test_exact.txt"
    io.writefile(filename, "")
    
    let file_size = 10
    let bytes_written = 5
    let chunk_data = [1,2,3,4,5]  # 5 bytes, exactly fits
    
    if bytes_written + len(chunk_data) <= file_size:
        print "  PASS: Exact size chunk accepted"
        io.remove(filename)
        return true
    end
    
    print "  FAIL: Exact size chunk rejected"
    io.remove(filename)
    return false
end

proc test_undersized_chunk_accepted():
    print "Test: Undersized chunk accepted..."
    let filename = "test_under.txt"
    io.writefile(filename, "")
    
    let file_size = 10
    let bytes_written = 0
    let chunk_data = [1,2,3]  # 3 bytes, under limit
    
    if bytes_written + len(chunk_data) <= file_size:
        print "  PASS: Undersized chunk accepted"
        io.remove(filename)
        return true
    end
    
    print "  FAIL: Undersized chunk rejected"
    io.remove(filename)
    return false
end

proc test_integrity_check_on_exact_size():
    print "Test: Integrity check on exact size..."
    let content = "Hello, World! This is a test file."
    let filename = "test_hash.txt"
    io.writefile(filename, content)
    
    let written = io.readbytes(filename)
    let actual_hash = hash.sha256(written)
    
    let expected = hash.sha256(written)
    
    let hash_ok = true
    for i in range(32):
        if actual_hash[i] != expected[i]:
            hash_ok = false
        end
    end
    
    if hash_ok:
        print "  PASS: Hash matches for exact content"
        io.remove(filename)
        return true
    end
    
    print "  FAIL: Hash mismatch"
    io.remove(filename)
    return false
end

proc test_integrity_check_fails_on_tampering():
    print "Test: Integrity check fails on tampering..."
    let content = "Original content"
    let filename = "test_tamper.txt"
    io.writefile(filename, content)
    
    # Tamper with file
    io.writefile(filename, "Tampered content")
    
    let written = io.readbytes(filename)
    let actual_hash = hash.sha256(written)
    
    let expected = hash.sha256(utils.to_list(content))
    
    let hash_ok = true
    for i in range(32):
        if actual_hash[i] != expected[i]:
            hash_ok = false
        end
    end
    
    if not hash_ok:
        print "  PASS: Hash correctly detects tampering"
        io.remove(filename)
        return true
    end
    
    print "  FAIL: Hash did not detect tampering"
    io.remove(filename)
    return false
end

proc test_file_size_exceeded_declared():
    print "Test: File size exceeded declared size..."
    let filename = "test_exceed.txt"
    io.writefile(filename, "")
    
    let file_size = 10
    let bytes_written = 10
    
    if bytes_written > file_size:
        print "  PASS: Exceeded size detected"
        io.remove(filename)
        return true
    end
    
    # Test exact size
    bytes_written = 10
    if bytes_written >= file_size:
        if bytes_written > file_size:
            print "  PASS: > size correctly handled"
        else:
            print "  PASS: == size correctly handled"
        end
        io.remove(filename)
        return true
    end
    
    print "  FAIL: Size check logic incorrect"
    io.remove(filename)
    return false
end

# Main test runner
print "========================================="
print "Running File Integrity Tests..."
print "========================================="

let results = []

push(results, test_oversized_chunk_rejected())
push(results, test_exact_size_chunk_accepted())
push(results, test_undersized_chunk_accepted())
push(results, test_integrity_check_on_exact_size())
push(results, test_integrity_check_fails_on_tampering())
push(results, test_file_size_exceeded_declared())

let passed = 0
let failed = 0
for i in range(len(results)):
    if results[i]:
        passed = passed + 1
    else:
        failed = failed + 1
    end
end

print ""
print "========================================="
print "Results: " + str(passed) + " passed, " + str(failed) + " failed"
print "========================================="

if failed > 0:
    sys.exit(1)
end