# sagelink/app/cmd.sage
# CMD service for running remote shell commands via SageLink

import sys
import sagelink.mux.stream as stream
import sagelink.utils as utils

# Client function to run a command remotely
# Returns a dict with "exit_code" and "output" (string)
proc run_remote_cmd(mux, cmd_string):
    let s = stream.mux_open_stream(mux, "CMD")
    if s == nil:
        return {"exit_code": -1, "output": "Error: Failed to open CMD stream"}
    end
    
    # Send CMD_EXEC payload (cmd_string)
    let payload = []
    for i in range(len(cmd_string)):
        push(payload, ord(cmd_string[i]))
    end
    stream.stream_write_msg(mux, s, stream.CMD_EXEC, utils.bytes(payload))
    
    # Read CMD_RESULT response
    let msg = stream.stream_read_msg(s)
    if msg == nil or msg["msg_type"] != stream.CMD_RESULT:
        stream.stream_close(mux, s)
        return {"exit_code": -1, "output": "Error: Connection lost or invalid response"}
    end
    
    let resp_payload = msg["payload"]
    if len(resp_payload) < 1:
        stream.stream_close(mux, s)
        return {"exit_code": -1, "output": "Error: Empty result response"}
    end
    
    let exit_code = resp_payload[0]
    let output = ""
    for i in range(1, len(resp_payload)):
        output = output + chr(resp_payload[i])
    end
    
    stream.stream_close(mux, s)
    return {"exit_code": exit_code, "output": output}

# Server-side handler for a CMD stream
proc handle_cmd_stream(mux, s):
    # Read CMD_EXEC message
    let msg = stream.stream_read_msg(s)
    if msg == nil or msg["msg_type"] != stream.CMD_EXEC:
        stream.stream_close(mux, s)
        return
    end
    
    let cmd_bytes = msg["payload"]
    let cmd = ""
    for i in range(len(cmd_bytes)):
        cmd = cmd + chr(cmd_bytes[i])
    end
    
    # Run command and capture output
    let output = sys.shell_exec(cmd)
    
    # Build response: exit_code (1B) + output
    let resp = [0]
    for i in range(len(output)):
        push(resp, ord(output[i]))
    end
    
    stream.stream_write_msg(mux, s, stream.CMD_RESULT, utils.bytes(resp))
    stream.stream_close(mux, s)
