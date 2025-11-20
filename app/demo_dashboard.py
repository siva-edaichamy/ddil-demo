"""
demo_dashboard.py
-----------------
Flask app for the demo dashboard (port 5002).
Visualizes C2, Aircraft, and Submarine nodes and
performs GemFire operations via gfsh commands.
"""

import os
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import paramiko
import requests
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# Configuration
SESSION_FILE = "config/last_session.json"
REGION_NAME = "TestRegion"
LOCATOR_BASE_PORT = 10336
REST_API_PORT_OFFSET = 8080

NODE_DATA = {"C2": {}, "Aircraft": {}, "Submarine": {}}
node_counters = {"C2": 0, "Aircraft": 0, "Submarine": 0}
node_counters_lock = threading.Lock()  # Thread-safe counter access
region_cleared = False
gfsh_cache = {}  # Cache gfsh query results: {node_name: {"data": {...}, "timestamp": ...}}
gfsh_cache_lock = threading.Lock()  # Thread-safe cache access
GFSH_CACHE_TTL = 0.5  # Cache TTL in seconds (reduced for faster updates)

# Region to demo role mapping
REGION_TO_ROLE = {
    "US East": "C2",
    "US West": "Aircraft",
    "EU": "Submarine",
}


def load_session():
    """Load session configuration from file."""
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, "r") as f:
            return json.load(f)
    return {}


def get_node_config():
    """Get node configuration for demo dashboard with SSH info."""
    try:
        session = load_session()
        nodes = session.get("nodes", [])
        ssh_user = session.get("ssh_user", "ec2-user")
        ssh_key = session.get("ssh_key", "")
        node_config = {}

        for node in nodes:
            region = node.get("region", "")
            role = REGION_TO_ROLE.get(region, "")
            if role:
                idx = nodes.index(node)
                rest_port = REST_API_PORT_OFFSET + idx
                public_ip = node.get("public_ip", "")
                node_config[role] = {
                    "public_ip": public_ip,
                    "private_ip": node.get("private_ip", ""),
                    "region": region,
                    "idx": idx,
                    "ssh_user": ssh_user,
                    "ssh_key": ssh_key,
                    "rest_url": f"http://{public_ip}:{rest_port}/geode/v1" if public_ip else None,
                }

        return node_config
    except Exception as e:
        return {}


def connect_node_ssh(node_config):
    """Establish SSH connection to a node."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            node_config["public_ip"],
            username=node_config["ssh_user"],
            key_filename=node_config["ssh_key"],
            timeout=10,
        )
        return ssh
    except Exception:
        return None


def get_private_ip(ssh):
    """Get private IP address of the node."""
    try:
        stdin, stdout, stderr = ssh.exec_command("hostname -I | awk '{print $1}'")
        private_ip = stdout.read().decode().strip()
        return private_ip
    except Exception:
        return None


def run_gfsh_query(ssh, private_ip, locator_port, query):
    """Execute a gfsh query and return parsed results."""
    try:
        cmd = (
            f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' "
            f"-e \"query --query='{query}'\""
        )
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
        stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        
        # Parse gfsh query output
        # Format: key | value
        #         --- | ---
        #         c2_1 | hi
        #         aircraft_1 | hello
        keys_values = {}
        lines = output.split('\n')
        in_data_section = False
        
        for line in lines:
            if 'key' in line.lower() and 'value' in line.lower():
                in_data_section = True
                continue
            if '---' in line:
                continue
            if in_data_section and line.strip():
                parts = line.split('|')
                if len(parts) >= 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    if key and key not in ['key', '---', '']:
                        keys_values[key] = value
        
        return keys_values
    except Exception:
        return {}


def get_unique_key(node_name):
    """Generate a unique sequential key for the node (thread-safe). Format: {node}_{counter}"""
    with node_counters_lock:
        # Get current counter
        current_max = node_counters.get(node_name, 0)
        
        # Check existing entries in NODE_DATA to find highest index
        existing_entries = NODE_DATA.get(node_name, {})
        prefix = f"{node_name.lower()}_"

        for existing_key in existing_entries.keys():
            if existing_key.lower().startswith(prefix):
                try:
                    # Extract index from keys like "c2_1" or "c2_2"
                    key_parts = existing_key.split("_")
                    if len(key_parts) >= 2:
                        idx = int(key_parts[1])
                        current_max = max(current_max, idx)
                except (ValueError, IndexError):
                    continue

        # Increment counter
        current_max += 1
        node_counters[node_name] = current_max
        
        # Generate simple unique key: {node}_{counter}
        unique_key = f"{node_name.lower()}_{current_max}"
        
        return unique_key


def clear_region_on_startup():
    """Legacy cleanup hook (no-op now that setup handles region creation)."""
    return


@app.before_request
def clear_region_once():
    """Destroy and recreate region once on first request."""
    global region_cleared
    if not region_cleared:
        clear_region_on_startup()
        region_cleared = True


@app.route("/")
def index():
    """Render the demo dashboard."""
    try:
        node_config = get_node_config()
        return render_template("demo_index.html", nodes=node_config)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return f"Error loading page: {str(e)}", 500


@app.route("/add_data", methods=["POST"])
def add_data():
    """
    Add data to a specific node via gfsh put command.
    
    Uses gfsh put --region=TestRegion --key={key} --value={value}
    This ensures our string keys are used directly (no auto-generated integer keys).
    """
    try:
        if not request.is_json:
            return jsonify({"status": "Request must be JSON"}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"status": "Invalid JSON data"}), 400
        
        node = data.get("node")
        value = data.get("value")

        if not node or not value:
            return jsonify({"status": "Missing node or value"}), 400

        node_config = get_node_config()
        if node not in node_config:
            return jsonify({"status": f"Node {node} not found"}), 404

        config = node_config[node]
        
        def get_next_available_key():
            """Query region via gfsh to find next available key."""
            ssh = None
            try:
                ssh = connect_node_ssh(config)
                if not ssh:
                    return get_unique_key(node)
                
                # Get private IP if not already set
                private_ip = config.get("private_ip")
                if not private_ip:
                    private_ip = get_private_ip(ssh)
                    if not private_ip:
                        return get_unique_key(node)
                
                locator_port = LOCATOR_BASE_PORT + config["idx"]
                
                # Query all entries
                query = f"SELECT entry.key, entry.value FROM /{REGION_NAME}.entries entry"
                keys_values = run_gfsh_query(ssh, private_ip, locator_port, query)
                
                # Find highest counter for this node
                prefix = f"{node.lower()}_"
                max_counter = 0
                for key in keys_values.keys():
                    if key.lower().startswith(prefix):
                        try:
                            parts = key.split("_")
                            if len(parts) >= 2:
                                counter = int(parts[1])
                                max_counter = max(max_counter, counter)
                        except (ValueError, IndexError):
                            continue
                
                return f"{node.lower()}_{max_counter + 1}"
            except Exception:
                pass
            finally:
                if ssh:
                    ssh.close()
            
            # Fallback if query failed
            return get_unique_key(node)
        
        # Get next available key
        key = get_next_available_key()
        
        # Connect via SSH
        ssh = connect_node_ssh(config)
        if not ssh:
            return jsonify({"status": "error", "message": "Failed to connect via SSH"}), 500
        
        try:
            # Get private IP if not already set
            private_ip = config.get("private_ip")
            if not private_ip:
                private_ip = get_private_ip(ssh)
                if not private_ip:
                    return jsonify({"status": "error", "message": "Failed to get private IP"}), 500
                config["private_ip"] = private_ip
            
            locator_port = LOCATOR_BASE_PORT + config["idx"]
            
            # Escape value for shell command - need to properly escape single quotes
            escaped_value = str(value).replace("'", "'\\''")
            escaped_key = key.replace("'", "'\\''")
            
            # Use gfsh put command - connect to locator first, then execute put
            cmd = (
                f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' "
                f"-e \"put --region={REGION_NAME} --key='{escaped_key}' --value='{escaped_value}'\""
            )
            
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=30)
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            # Check for connection errors
            if "failed to connect" in output.lower() or "could not connect" in output.lower() or "connection refused" in output.lower():
                return jsonify({"status": "error", "message": f"Failed to connect to locator: {output[:200]}"}), 500
            
            # Check for success - gfsh put returns "Result : true" on success
            if exit_status == 0 and ("Result : true" in output or "put successfully" in output.lower() or "updated" in output.lower() or "Value " in output or "Key " in output):
                # Update local counter
                with node_counters_lock:
                    try:
                        parts = key.split("_")
                        if len(parts) >= 2:
                            counter = int(parts[1])
                            node_counters[node] = max(node_counters.get(node, 0), counter)
                    except (ValueError, IndexError):
                        pass
                
                # Invalidate cache for the node where data was added
                with gfsh_cache_lock:
                    if node in gfsh_cache:
                        del gfsh_cache[node]
                
                # Emit success log message
                socketio.emit("log", {"message": f"✅ [{node}] Successfully posted {key}={value}"})
                
                # Refresh immediately with force refresh for the node where data was added
                try:
                    node_config = get_node_config()
                    # Force refresh the node where data was added
                    refresh_node_data(node, node_config.get(node, {}), force_refresh=True)
                    # Also refresh other nodes (they'll use cache if recent)
                    for refresh_node, refresh_config in node_config.items():
                        if refresh_node != node:
                            refresh_node_data(refresh_node, refresh_config)
                except Exception:
                    pass
                
                return jsonify({"status": f"Added {key}={value} to {node}"}), 200
            else:
                return jsonify({"status": "error", "message": f"gfsh put failed: {output[:200]}"}), 500
        
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to add data: {str(e)}"}), 500
        finally:
            ssh.close()

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": f"Error: {str(e)}"}), 500


@app.route("/toggle_submarine", methods=["POST"])
def toggle_submarine():
    """Toggle submarine dive/surface by stopping/starting gateway components."""
    data = request.json
    action = data.get("action", "dive")

    session = load_session()
    ssh_user = session.get("ssh_user", "ec2-user")
    ssh_key = session.get("ssh_key", "")
    nodes = session.get("nodes", [])

    # Find submarine by region (EU)
    submarine_node = next((n for n in nodes if n.get("region") == "EU"), None)

    if not submarine_node or not ssh_key:
        return jsonify({"status": "Cannot control submarine - missing config"}), 500

    # Determine submarine's index in the nodes list for port calculation
    submarine_idx = next(
        (idx for idx, n in enumerate(nodes) if n.get("region") == "EU"), 2
    )
    public_ip = submarine_node.get("public_ip", "")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(public_ip, username=ssh_user, key_filename=ssh_key, timeout=10)

        stdin, stdout, stderr = ssh.exec_command("hostname -I | awk '{print $1}'")
        private_ip = stdout.read().decode().strip()

        locator_port = 10336 + submarine_idx  # Dynamically calculate based on index

        if action == "dive":
            # Stop gateway receiver (blocks incoming data)
            cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'stop gateway-receiver'"
            ssh.exec_command(cmd, timeout=30)

            # Pause gateway senders (blocks outgoing data)
            for sender_id in ["ToUSEast", "ToUSWest"]:
                cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'pause gateway-sender --id={sender_id}'"
                ssh.exec_command(cmd, timeout=30)

            msg = "🌊 Submarine DIVING - Fully disconnected (no incoming/outgoing replication)"

        else:
            # Start gateway receiver (allows incoming data)
            cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'start gateway-receiver'"
            ssh.exec_command(cmd, timeout=30)

            # Resume gateway senders (allows outgoing data)
            for sender_id in ["ToUSEast", "ToUSWest"]:
                cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'resume gateway-sender --id={sender_id}'"
                ssh.exec_command(cmd, timeout=30)

            msg = "🌊 Submarine SURFACING - Reconnected! Syncing queued data in both directions..."

        ssh.close()

        return jsonify({"status": msg})

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        return jsonify({"status": f"Error: {str(e)}"}), 500


@app.route("/toggle_receiver", methods=["POST"])
def toggle_receiver():
    """Simulate intermittent network on Aircraft by stopping gateway components."""
    data = request.json
    node = data.get("node")

    if node != "Aircraft":
        return jsonify({"status": "This feature is only for Aircraft"}), 400

    session = load_session()
    ssh_user = session.get("ssh_user", "ec2-user")
    ssh_key = session.get("ssh_key", "")
    nodes = session.get("nodes", [])

    # Find aircraft by region (US West)
    aircraft_node = next((n for n in nodes if n.get("region") == "US West"), None)

    if not aircraft_node or not ssh_key:
        return jsonify({"status": "Cannot control - missing config"}), 500

    # Determine aircraft's index in the nodes list for port calculation
    aircraft_idx = next(
        (idx for idx, n in enumerate(nodes) if n.get("region") == "US West"), 1
    )
    public_ip = aircraft_node.get("public_ip", "")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(public_ip, username=ssh_user, key_filename=ssh_key, timeout=10)

        stdin, stdout, stderr = ssh.exec_command("hostname -I | awk '{print $1}'")
        private_ip = stdout.read().decode().strip()

        locator_port = 10336 + aircraft_idx

        # Stop gateway receiver (blocks incoming data)
        cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'stop gateway-receiver'"
        ssh.exec_command(cmd, timeout=30)

        # Pause gateway senders (blocks outgoing data)
        for sender_id in ["ToUSEast", "ToEU"]:
            cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'pause gateway-sender --id={sender_id}'"
            ssh.exec_command(cmd, timeout=30)

        ssh.close()

        # Schedule auto-recovery after 30 seconds
        import threading

        def auto_recover():
            time.sleep(30)
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(public_ip, username=ssh_user, key_filename=ssh_key, timeout=10)

                stdin, stdout, stderr = ssh.exec_command("hostname -I | awk '{print $1}'")
                private_ip = stdout.read().decode().strip()

                locator_port = 10336 + aircraft_idx

                # Start gateway receiver (allows incoming data)
                cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'start gateway-receiver'"
                ssh.exec_command(cmd, timeout=30)

                # Resume gateway senders (allows outgoing data)
                for sender_id in ["ToUSEast", "ToEU"]:
                    cmd = f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' -e 'resume gateway-sender --id={sender_id}'"
                    ssh.exec_command(cmd, timeout=30)

                ssh.close()
            except Exception:
                pass

        threading.Thread(target=auto_recover, daemon=True).start()

        msg = "⚠️ Aircraft network DISCONNECTED - Will auto-recover in 30 seconds"
        return jsonify({"status": msg})

    except Exception as e:
        return jsonify({"status": f"Error: {str(e)}"}), 500


def get_gfsh_data_cached(node_name, node_config, force_refresh=False):
    """Get data via gfsh query with caching to avoid redundant queries."""
    import time
    current_time = time.time()
    
    # Check cache unless forced refresh
    if not force_refresh:
        with gfsh_cache_lock:
            cached = gfsh_cache.get(node_name)
            if cached and (current_time - cached["timestamp"]) < GFSH_CACHE_TTL:
                return cached["data"]
    
    # Query via gfsh (skip if we just queried very recently to avoid hammering)
    try:
        ssh = connect_node_ssh(node_config)
        if not ssh:
            # Return cached data if available, even if expired
            with gfsh_cache_lock:
                cached = gfsh_cache.get(node_name)
                if cached:
                    return cached["data"]
            return {}
        
        private_ip = get_private_ip(ssh) or node_config.get("private_ip", "")
        if not private_ip:
            ssh.close()
            with gfsh_cache_lock:
                cached = gfsh_cache.get(node_name)
                if cached:
                    return cached["data"]
            return {}
        
        locator_port = LOCATOR_BASE_PORT + node_config.get("idx", 0)
        query = f"SELECT entry.key, entry.value FROM /{REGION_NAME}.entries entry"
        gfsh_data = run_gfsh_query(ssh, private_ip, locator_port, query)
        ssh.close()
        
        # Cache the result
        with gfsh_cache_lock:
            gfsh_cache[node_name] = {"data": gfsh_data, "timestamp": current_time}
        
        return gfsh_data
    except Exception:
        # Return stale cache on error rather than empty
        with gfsh_cache_lock:
            cached = gfsh_cache.get(node_name)
            if cached:
                return cached["data"]
        return {}


def refresh_node_data(node_name, node_config, force_refresh=False):
    """
    Refresh data for a specific node via REST API and emit update immediately.
    """
    try:
        rest_url = node_config.get("rest_url")
        if not rest_url:
            return
        
        region_url = f"{rest_url}/{REGION_NAME}"
        response = requests.get(region_url, timeout=2)
        
        if response.status_code == 200:
            result = response.json()
            node_data = {}
            
            # Parse REST API response
            if REGION_NAME in result:
                region_data = result[REGION_NAME]
                
                if isinstance(region_data, dict):
                    # Format: {"c2_1": "hi", "aircraft_1": "hello", ...}
                    node_data.update(region_data)
                elif isinstance(region_data, list) and len(region_data) > 0:
                    # Check if list contains dicts with keys or just string values
                    has_keys = False
                    for item in region_data:
                        if isinstance(item, dict):
                            # Check if dict has region keys (not just "msg")
                            if any(k not in ["msg", "value"] for k in item.keys()):
                                node_data.update(item)
                                has_keys = True
                                break
                    
                    # If no keys found, use cached gfsh query (force refresh if requested)
                    if not has_keys:
                        gfsh_data = get_gfsh_data_cached(node_name, node_config, force_refresh=force_refresh)
                        if gfsh_data:
                            node_data.update(gfsh_data)
            
            NODE_DATA[node_name] = node_data
            socketio.emit("update_data", NODE_DATA)
    except Exception:
        pass


def poll_single_node(node_name, config):
    """Poll a single node and return its data. Used for parallel polling."""
    node_data = {}
    rest_url = config.get("rest_url")
    
    if not rest_url:
        return node_name, node_data
    
    try:
        region_url = f"{rest_url}/{REGION_NAME}"
        response = requests.get(region_url, timeout=1)  # Reduced timeout for faster polling

        if response.status_code == 200:
            result = response.json()

            # Parse REST API response
            if REGION_NAME in result:
                region_data = result[REGION_NAME]
                
                if isinstance(region_data, dict):
                    # Format: {"c2_1": "hi", "aircraft_1": "hello", ...}
                    node_data.update(region_data)
                elif isinstance(region_data, list) and len(region_data) > 0:
                    # Check if list contains dicts with keys or just string values
                    has_keys = False
                    for item in region_data:
                        if isinstance(item, dict):
                            # Check if dict has region keys (not just "msg")
                            if any(k not in ["msg", "value"] for k in item.keys()):
                                node_data.update(item)
                                has_keys = True
                                break
                    
                    # If no keys found, use cached gfsh query
                    if not has_keys:
                        gfsh_data = get_gfsh_data_cached(node_name, config)
                        if gfsh_data:
                            node_data.update(gfsh_data)
    except Exception:
        pass
    
    return node_name, node_data


def poll_data():
    """
    Continuously poll all nodes via REST API in parallel (much faster than sequential).
    Uses cached gfsh queries when REST API returns values without keys.
    """
    # Create executor for parallel polling (kept alive for the lifetime of the background task)
    executor = None
    try:
        executor = ThreadPoolExecutor(max_workers=3)
        
        # Give server time to fully initialize
        time.sleep(1)
        
        while True:
            try:
                node_config = get_node_config()
                if not node_config:
                    time.sleep(0.5)
                    continue
                
                results = {}
                
                # Submit all polling tasks in parallel
                future_to_node = {
                    executor.submit(poll_single_node, node_name, config): node_name
                    for node_name, config in node_config.items()
                }
                
                # Collect results as they complete (with individual timeouts)
                for future in as_completed(future_to_node):
                    try:
                        node_name, node_data = future.result(timeout=1.0)
                        results[node_name] = node_data
                    except Exception:
                        # If a node fails, use empty dict
                        node_name = future_to_node.get(future, "unknown")
                        results[node_name] = {}
                
                # Update NODE_DATA with all results at once
                for node_name, node_data in results.items():
                    NODE_DATA[node_name] = node_data
                
                # Emit single update with all node data
                socketio.emit("update_data", NODE_DATA)

            except Exception as e:
                # Log error but continue polling
                import traceback
                print(f"Error in polling loop: {e}")
                traceback.print_exc()
                time.sleep(0.5)

            time.sleep(0.5)  # Faster polling for responsive UI updates
    except Exception as e:
        # Fatal error - log and exit
        import traceback
        print(f"Fatal error in poll_data: {e}")
        traceback.print_exc()
    finally:
        # Cleanup executor when background task exits
        if executor:
            executor.shutdown(wait=False)


_polling_started = False

@socketio.on("connect")
def connected():
    """Handle client connection."""
    socketio.emit("update_data", NODE_DATA)


@socketio.on("disconnect")
def disconnected():
    """Handle client disconnection."""
    pass


if __name__ == "__main__":
    try:
        print("Starting demo dashboard on http://0.0.0.0:5002")
        
        # Start polling task after a short delay to ensure server is ready
        def start_polling_delayed():
            time.sleep(1)  # Give server time to fully initialize
            try:
                poll_data()
            except Exception as e:
                print(f"Error in polling task: {e}")
                import traceback
                traceback.print_exc()
        
        socketio.start_background_task(start_polling_delayed)
        socketio.run(app, host="0.0.0.0", port=5002, debug=True)
    except Exception as e:
        print(f"Error starting demo dashboard: {e}")
        import traceback
        traceback.print_exc()
        raise
