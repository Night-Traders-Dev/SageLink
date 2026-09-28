# sagelink/app/cmd.sage
# CMD service for running remote shell commands via SageLink

import sys
import sagelink.mux.stream as stream
import sagelink.utils as utils

# FFI helpers for command execution with exit code
proc ffi_run_command(cmd):
    let libc = ffi_open("libc.so.6")
    if libc == nil:
        libc = ffi_open("libc.so")
    if libc == nil:
        libc = ffi_open("")
    if libc == nil:
        return {"exit_code": -1, "output": "Error: libc not available"}
    
    # system() returns the exit status shifted by 8 bits
    # Use WEXITSTATUS to extract the actual exit code
    let result = ffi_call(libc, "system", "int", [cmd])
    ffi_close(libc)
    
    if result < 0:
        return {"exit_code": -1, "output": "Error: system() failed"}
    
    # Extract exit code: system() returns status, use WEXITSTATUS
    # On Linux: exit_code = (result >> 8) & 0xFF
    let exit_code = (result >> 8) & 255
    
    # For output, we'd need popen - for now just return exit code
    return {"exit_code": exit_code, "output": ""}

# Client function to run a command remotely
# Returns a dict with "exit_code" and "output" (string)
proc run_remote_cmd(mux, cmd_string):
    let s = stream.mux_open_stream(mux, "CMD")
    if s == nil:
        return {"exit_code": -1, "output": "Error: Failed to open CMD stream"}
    
    # Send CMD_EXEC payload (cmd_string)
    let payload = []
    for i in range(len(cmd_string)):
        push(payload, ord(cmd_string[i]))
    stream.stream_write_msg(mux, s, stream.CMD_EXEC, utils.to_bytes(payload))
    
    # Read CMD_RESULT response
    let msg = stream.stream_read_msg(s)
    if msg == nil or msg["msg_type"] != stream.CMD_RESULT:
        stream.stream_close(mux, s)
        return {"exit_code": -1, "output": "Error: Connection lost or invalid response"}
    
    let resp_payload = msg["payload"]
    if len(resp_payload) < 1:
        stream.stream_close(mux, s)
        return {"exit_code": -1, "output": "Error: Empty result response"}
    
    let exit_code = resp_payload[0]
    let output = ""
    for i in range(1, len(resp_payload)):
        output = output + chr(resp_payload[i])
    
    stream.stream_close(mux, s)
    return {"exit_code": exit_code, "output": output}

# Server-side handler for a CMD stream
proc handle_cmd_stream(mux, s):
    # Read CMD_EXEC message
    let msg = stream.stream_read_msg(s)
    if msg == nil or msg["msg_type"] != stream.CMD_EXEC:
        stream.stream_close(mux, s)
        return
    
    let cmd_bytes = msg["payload"]
    let cmd = ""
    for i in range(len(cmd_bytes)):
        cmd = cmd + chr(cmd_bytes[i])
    
    # Run command via FFI to capture exit code
    let result = ffi_run_command(cmd)
    
    # For output, also run with shell_exec (safe commands only)
    let output = sys.shell_exec(cmd)
    
    # Build response: exit_code (1B) + output
    let resp = [result["exit_code"]]
    for i in range(len(output)):
        push(resp, ord(output[i]))
    
    stream.stream_write_msg(mux, s, stream.CMD_RESULT, utils.to_bytes(resp))
    stream.stream_close(mux, s)