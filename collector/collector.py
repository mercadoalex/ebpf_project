from bcc import BPF  # Import BCC Python bindings for eBPF
from flask import Flask, jsonify, request  # Import Flask web framework and helpers
from flask_cors import CORS  # Import CORS support for Flask
import ctypes  # Import ctypes for correct map value types

# Load the eBPF program from the specified C file
bpf = BPF(src_file="ebpf/click_counter.bpf.c")

# Attach the eBPF program's 'trace' function to the 'sys_enter_clone' tracepoint
# This means the eBPF code runs every time a process is created (clone syscall)
bpf.attach_tracepoint(tp="syscalls:sys_enter_clone", fn_name="trace")

# Get a reference to the eBPF map named 'click_count_map'
# This map is used to store and retrieve the click count between kernel and user space
click_count_map = bpf.get_table("click_count_map")

# Create a Flask web application
app = Flask(__name__)

# Enable Cross-Origin Resource Sharing (CORS) for the Flask app
CORS(app)

@app.route("/clicks", methods=["GET"])
def get_clicks():
    """
    HTTP GET endpoint to return the current click count as JSON.
    Reads the value from the eBPF map (key=0).
    """
    key = 0
    count = click_count_map[key].value  # Retrieve the current count from the map
    return jsonify({"clicks": count})   # Return as JSON

@app.route("/clicks", methods=["POST"])
def register_click():
    """
    HTTP POST endpoint to increment the click count.
    This simulates a click event for demonstration purposes.
    Increments the value in the eBPF map (key=0).
    """
    key = 0
    value = click_count_map[key].value + 1  # Increment the count
    click_count_map[key] = ctypes.c_ulonglong(value)  # Update the map with the new value (as ctypes)
    return jsonify({"clicks": value})       # Return the new count as JSON

if __name__ == "__main__":
    # Start the Flask web server on all interfaces, port 8080
    # This will serve the /clicks API endpoints for GET and POST requests
    app.run(host="0.0.0.0", port=8080)