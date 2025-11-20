import concurrent.futures
import json
import os
import threading
import time
import subprocess
import sys
import random
import string

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO
import paramiko
import requests

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
BASE_PATH = "/home/ec2-user/data/ddl-demo"
LOCATOR_PATH = f"{BASE_PATH}/locator"
SERVER_PATH = f"{BASE_PATH}/server"

DEMO_DASHBOARD_URL = os.environ.get("DEMO_DASHBOARD_URL", "http://localhost:5002")

STEPS = [
    "SSH Connectivity",
    "Prepare Hosts",
    "Start Locators",
    "Start Servers",
    "Start Gateways",
    "Start Receivers",
    "Create Regions",
    "WAN Setup",
    "WAN Read Check",
    "WAN Write Check",
    "Demo Environment Ready",
]

HARDCODED_SESSION = {
    "ssh_user": "ec2-user",
    "ssh_key": "/path/to/key.pem",
    "nodes": [
        {"name": "node1", "public_ip": "0.0.0.0", "region": "US East"},
        {"name": "node2", "public_ip": "0.0.0.0", "region": "US West"},
        {"name": "node3", "public_ip": "0.0.0.0", "region": "EU"},
    ],
}

CONFIG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config"))
LAST_SESSION_PATH = os.path.join(CONFIG_DIR, "last_session.json")

# Global cancellation event for aborting setup tasks
setup_cancellation_event = threading.Event()

# Global demo dashboard process
demo_dashboard_process = None
demo_dashboard_lock = threading.Lock()


def load_default_session():
    """Load session defaults, preferring values stored in last_session.json."""
    try:
        with open(LAST_SESSION_PATH, "r", encoding="utf-8") as fh:
            session = json.load(fh)

        required_keys = {"ssh_user", "ssh_key", "nodes"}
        if not required_keys.issubset(session):
            missing = ", ".join(sorted(required_keys - set(session)))
            raise KeyError(f"Missing keys: {missing}")

        nodes = session.get("nodes") or []
        if not isinstance(nodes, list) or not nodes:
            raise ValueError("Session must include at least one node definition")

        # Ensure expected keys are present on each node
        for idx, node in enumerate(nodes):
            if not all(k in node for k in ("name", "public_ip", "region")):
                raise KeyError(f"Node #{idx + 1} missing required fields")
        print(f"✅ Loaded session defaults from {LAST_SESSION_PATH}")
        return session
    except FileNotFoundError:
        print(f"ℹ️ last_session.json not found at {LAST_SESSION_PATH}, using defaults")
    except Exception as exc:
        print(f"⚠️ Could not load last_session.json: {exc}. Using built-in defaults.")

    return json.loads(json.dumps(HARDCODED_SESSION))


DEFAULT_SESSION = load_default_session()


# -----------------------------------------------------------------------------
# Status Emission Functions
# -----------------------------------------------------------------------------
def emit_status(region, step, color):
    """Emit status update for the grid"""
    payload = {"region": region, "step": step, "color": color}
    try:
        socketio.emit("status_update", payload)
    except Exception as e:
        print(f"❌ Failed to emit status: {e}")


def force_all_steps_green(nodes):
    """
    Force every known step to green for the provided nodes.
    WARNING: Only call this when ALL steps have succeeded!
    This will overwrite any red/orange statuses.
    """
    for node in nodes:
        region = node["region"]
        for step in STEPS:
            emit_status(region, step, "green")
            socketio.sleep(0.02)


def check_step_failures(results, step_name, nodes):
    """Check if any node failed in a critical step. Raise exception if failures found."""
    failed_nodes = []
    for node in nodes:
        node_result = results.get(node["name"], "red")
        if node_result == "red":
            failed_nodes.append(node["name"])
    
    if failed_nodes:
        error_msg = f"Critical failure at step '{step_name}'. Failed nodes: {', '.join(failed_nodes)}. Cannot proceed. Check logs for details."
        emit_log(f"❌ {error_msg}")
        print(f"\n❌ {error_msg}")
        raise RuntimeError(error_msg)


def emit_log(msg):
    """Emit log message"""
    payload = {"message": msg}
    try:
        socketio.emit("log", payload)
    except Exception as e:
        print(f"❌ Failed to emit log: {e}")


# -----------------------------------------------------------------------------
# SSH Utility Functions (from gemfire_ssh.py)
# -----------------------------------------------------------------------------
def run_ssh_cmd(ssh, cmd, timeout=90):
    """Run a remote SSH command and return (stdout, stderr)."""
    try:
        emit_log(f"💻 EXEC: {cmd[:100]}...")

        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        start = time.time()
        elapsed = 0

        while not stdout.channel.exit_status_ready():
            elapsed = time.time() - start
            if elapsed > timeout:
                print(f"⚠️ TIMEOUT after {elapsed:.1f} seconds")
                raise TimeoutError(f"⚠️ Timeout: {cmd}")
            time.sleep(1)

        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()

        if err:
            print(f"⚠️ Command stderr: {err[:200]}")

        return out, err
    except Exception as e:
        print(f"❌ EXCEPTION in run_ssh_cmd: {str(e)}")
        emit_log(f"❌ Error: {str(e)}")
        return "", str(e)


def connect_node(node, user, keyfile):
    """Establish SSH connection."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=node["public_ip"], username=user, key_filename=keyfile, timeout=10
        )
        return ssh
    except Exception as e:
        print(f"❌ Failed to connect to {node['name']}: {str(e)}")
        raise


def get_private_ip(ssh):
    """Try multiple methods to discover private IP."""
    cmds = [
        "hostname -I | awk '{print $1}'",
        "ip route get 8.8.8.8 | grep src | awk '{print $7}'",
        "ip addr show eth0 | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1",
    ]
    for cmd in cmds:
        out, err = run_ssh_cmd(ssh, cmd)
        if out and len(out.strip()) > 6:
            return out.strip()
    return None


def sanitize_node_name(name):
    """Remove spaces and special characters from node name for use in commands"""
    return name.replace(" ", "_").replace("-", "_")


def fix_hostname_resolution(ssh, node):
    """
    Fix hostname resolution by adding entry to /etc/hosts.
    Note: This is optional since we use IP addresses directly in GemFire config.
    If hostname resolution is not needed, this function can be skipped.
    """
    emit_log(f"[{node['name']}] 🔧 Fixing hostname resolution (optional - using IPs directly)...")

    out, err = run_ssh_cmd(ssh, "hostname")
    hostname = out.strip() if out else None

    if hostname and node.get("private_ip"):
        # Check if entry already exists to avoid duplicates
        check_cmd = f"grep -q '{node['private_ip']} {hostname}' /etc/hosts && echo 'exists' || echo 'not_exists'"
        check_out, _ = run_ssh_cmd(ssh, check_cmd)
        
        if 'exists' in check_out:
            emit_log(f"[{node['name']}] ℹ️ Hostname entry already exists in /etc/hosts")
            return
        
        cmd = f"echo '{node['private_ip']} {hostname}' | sudo tee -a /etc/hosts"
        run_ssh_cmd(ssh, cmd)
        emit_log(
            f"[{node['name']}] ✅ Added {node['private_ip']} {hostname} to /etc/hosts (can be removed after setup)"
        )


def gemfire_components_active(ssh):
    """Check if any GemFire locator or server processes are active."""
    checks = [
        "pgrep -f 'LocatorLauncher'",
        "pgrep -f 'ServerLauncher'",
    ]
    for cmd in checks:
        out, _ = run_ssh_cmd(ssh, f"{cmd} || true")
        if out.strip():
            return True
    return False


def run_gfsh_script(ssh, commands, timeout=120):
    """Execute a sequence of gfsh commands using a single session."""
    script = "\n".join(commands + ["exit"])
    gfsh_cmd = f"cat <<'EOF' | gfsh\n{script}\nEOF"
    return run_ssh_cmd(ssh, gfsh_cmd, timeout=timeout)


def cleanup_gemfire(ssh, node):
    """Hard reset: Kill all GemFire processes, free ports, and remove all directories."""
    node_name = node['name']
    idx = node.get("idx", 0)
    
    emit_log(f"[{node_name}] 🧹 Starting hard reset - killing processes and removing directories...")
    
    check_cmds = [
        ("LocatorLauncher", "pgrep -f 'LocatorLauncher' || echo 'none'"),
        ("ServerLauncher", "pgrep -f 'ServerLauncher' || echo 'none'"),
        ("gemfire", "pgrep -f 'gemfire' | head -5 || echo 'none'"),
        ("gfsh", "pgrep -f 'gfsh' || echo 'none'"),
    ]
    
    processes_found = {}
    for proc_name, cmd in check_cmds:
        out, err = run_ssh_cmd(ssh, cmd)
        if out.strip() and out.strip() != "none":
            processes_found[proc_name] = out.strip()
    
    # Kill all GemFire processes
    emit_log(f"[{node_name}] Killing GemFire processes...")
    kill_cmds = [
        ("gemfire", "pkill -9 -f 'gemfire' || true"),
        ("ServerLauncher", "pkill -9 -f 'ServerLauncher' || true"),
        ("LocatorLauncher", "pkill -9 -f 'LocatorLauncher' || true"),
        ("gfsh", "pkill -9 -f 'gfsh' || true"),
    ]
    
    for proc_name, cmd in kill_cmds:
        run_ssh_cmd(ssh, cmd)
    
    socketio.sleep(2)
    
    # Verify processes are killed
    for proc_name, cmd in check_cmds:
        out, err = run_ssh_cmd(ssh, cmd)
        if out.strip() and out.strip() != "none":
            emit_log(f"[{node_name}] ⚠️ WARNING: {proc_name} still running after kill")

    # Free up ports
    emit_log(f"[{node_name}] Freeing up ports...")
    ports_to_free = [
        (10336 + idx, "Locator"),
        (40404 + idx, "Server"),
        (55221 + idx, "Gateway receiver start"),
        (55222 + idx, "Gateway receiver end"),
        (8080 + idx, "REST API"),
        (10931 + idx, "JMX manager"),
        (7071 + idx, "HTTP service"),
    ]

    for port, port_name in ports_to_free:
        check_cmd = f"/usr/sbin/lsof -ti:{port} 2>/dev/null || /usr/bin/lsof -ti:{port} 2>/dev/null || echo 'none'"
        out, err = run_ssh_cmd(ssh, check_cmd)
        if out.strip() and out.strip() != "none":
            pids = out.strip()
            emit_log(f"[{node_name}] Port {port} ({port_name}) in use by PIDs: {pids}")
            kill_cmd = f"/usr/sbin/lsof -ti:{port} | xargs kill -9 2>/dev/null || /usr/bin/lsof -ti:{port} | xargs kill -9 2>/dev/null || true"
            run_ssh_cmd(ssh, kill_cmd)
    
    socketio.sleep(1)

    # Delete and recreate directory
    emit_log(f"[{node_name}] Removing entire base directory and recreating...")
    remove_cmd = f"sudo rm -rf {BASE_PATH}"
    out, err = run_ssh_cmd(ssh, remove_cmd)
    if err:
        emit_log(f"[{node_name}] ⚠️ Warning during removal: {err[:100]}")
    
    socketio.sleep(1)
    
    recreate_cmd = f"mkdir -p {LOCATOR_PATH} {SERVER_PATH}"
    out, err = run_ssh_cmd(ssh, recreate_cmd)
    if err:
        emit_log(f"[{node_name}] ⚠️ Warning creating directories: {err[:100]}")
    else:
        emit_log(f"[{node_name}] ✅ Directory structure recreated")

    # Clean up hostname entries
    emit_log(f"[{node_name}] Cleaning up hostname entries from /etc/hosts...")
    out, err = run_ssh_cmd(ssh, "hostname")
    hostname = out.strip() if out else None
    
    if hostname and node.get("private_ip"):
        remove_cmd = f"sudo sed -i '/{node['private_ip']} {hostname}/d' /etc/hosts 2>/dev/null || true"
        run_ssh_cmd(ssh, remove_cmd)

    emit_log(f"[{node_name}] ✅ Hard reset complete")


def run_parallel(nodes, func, max_workers=None):
    """Execute func(node) across nodes in parallel, propagating exceptions."""
    if not nodes:
        return
    max_workers = max_workers or max(1, min(len(nodes), 8))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(func, node) for node in nodes]
        for future in concurrent.futures.as_completed(futures):
            future.result()


# -----------------------------------------------------------------------------
# Background Tasks
# -----------------------------------------------------------------------------
def verify_nodes_task(data):
    emit_log("🔍 Checking node connectivity...")
    nodes = data["nodes"]

    status_lock = threading.Lock()
    status_map = {}

    def verify_worker(node):
        name, ip, region = node["name"], node["public_ip"], node["region"]
        emit_status(region, "SSH Connectivity", "orange")
        try:
            ssh = connect_node(node, data["ssh_user"], data["ssh_key"])
            ssh.close()
            emit_log(f"✅ {name}: reachable ({ip})")
            with status_lock:
                status_map[name] = "green"
        except Exception as e:
            emit_log(f"❌ {name}: {str(e)}")
            with status_lock:
                status_map[name] = "red"

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, len(nodes))
    ) as executor:
        list(executor.map(verify_worker, nodes))

    for node in nodes:
        color = status_map.get(node["name"], "red")
        emit_status(node["region"], "SSH Connectivity", color)
        socketio.sleep(0.02)
    emit_log("✅ Node verification complete")


def prepare_hosts_task(data):
    emit_log("🧹 Cleaning up GemFire processes and folders...")

    connections = {}
    nodes = data["nodes"]
    cleanup_results = {}
    

    # Connect to all nodes and get private IPs
    connection_lock = threading.Lock()

    def connect_worker(args):
        idx, node = args
        name, ip, region = node["name"], node["public_ip"], node["region"]
        emit_status(region, "Prepare Hosts", "orange")
        try:
            ssh = connect_node(node, data["ssh_user"], data["ssh_key"])
            node["idx"] = idx
            node["private_ip"] = get_private_ip(ssh)
            with connection_lock:
                connections[name] = ssh
            emit_log(
                f"🔌 {name}: connected (private IP: {node.get('private_ip', 'unknown')})"
            )
        except Exception as e:
            emit_status(region, "Prepare Hosts", "red")
            emit_log(f"❌ {name}: connection failed - {str(e)}")
            with connection_lock:
                cleanup_results[name] = {"status": "red", "error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, len(nodes))
    ) as executor:
        executor.map(connect_worker, enumerate(nodes))
    
    if len(connections) < len(nodes):
        failed_nodes = [n['name'] for n in nodes if n['name'] not in connections]
        emit_log(f"⚠️ Failed to connect to: {', '.join(failed_nodes)}")

    def cleanup_wrapper(node):
        name = node["name"]
        region = node["region"]
        try:
            cleanup_gemfire(connections[name], node)
            cleanup_results[name] = {"status": "green"}
        except Exception as exc:
            cleanup_results[name] = {"status": "red", "error": str(exc)}
            emit_log(f"❌ {name}: cleanup failed - {str(exc)}")
    
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, len(connections))
    ) as executor:
        futures = [
            executor.submit(cleanup_wrapper, node)
            for node in nodes
            if node["name"] in connections
        ]
        for future in concurrent.futures.as_completed(futures):
            future.result()
    
    # Update statuses after cleanup
    for node in nodes:
        region = node["region"]
        result = cleanup_results.get(node["name"])
        if result and result["status"] == "green":
            emit_status(region, "Prepare Hosts", "green")
        else:
            emit_status(region, "Prepare Hosts", "red")
        socketio.sleep(0.1)

    # Close connections
    for ssh in connections.values():
        ssh.close()

    emit_log("🧹 Host preparation and cleanup complete")


def setup_wan_task(data):
    """
    Consolidated WAN setup task with the following order:
    1. Check SSH connection to each node
    2. Hard reset each node (in parallel)
    3. Setup locator, server, receiver, sender, region in each node
    4. Do a read test
    5. Do a WAN write test
    6. Only if all steps successful, show "Demo environment ready"
    """
    global setup_cancellation_event
    
    # Reset cancellation event at start
    setup_cancellation_event.clear()
    
    print("\n" + "=" * 100)
    print("🚀 STARTING CONSOLIDATED WAN SETUP TASK")
    print("=" * 100)

    emit_log("🚀 Starting consolidated WAN setup...")
    emit_log("--------------------------------------------------")

    nodes = data["nodes"]
    user = data["ssh_user"]
    keyfile = data["ssh_key"]
    connections = {}
    rest_api_working = {}
    all_passed = True
    
    def check_cancellation():
        """Check if setup has been cancelled."""
        if setup_cancellation_event.is_set():
            emit_log("⚠️ Setup cancelled by user")
            print("⚠️ Setup cancelled by user")
            raise KeyboardInterrupt("Setup cancelled")

    try:

        connection_lock = threading.Lock()
        for idx, node in enumerate(nodes):
            node["dsid"] = idx + 1
            node["idx"] = idx

        def connect_worker(node):
            name, region = node["name"], node["region"]
            emit_log(f"[{name}] 🔌 Connecting to {node['public_ip']}...")
            ssh = connect_node(node, user, keyfile)

            node["private_ip"] = get_private_ip(ssh)
            with connection_lock:
                connections[name] = ssh

            emit_log(
                f"[{name}] ✅ Connected → Private IP: {node['private_ip']} DSID: {node['dsid']}"
            )

        run_parallel(nodes, connect_worker)

        check_cancellation()

        # Set active_nodes for use in subsequent steps
        active_nodes = [node for node in nodes if node["name"] in connections]
        
        if not active_nodes:
            raise RuntimeError("No active nodes available - SSH connection failed for all nodes")

        emit_log("🧹 Starting hard reset on all nodes in parallel...")
        for node in active_nodes:
            emit_status(node["region"], "Prepare Hosts", "orange")

        cleanup_results = {}
        
        def cleanup_worker(node):
            try:
                ssh = connections[node["name"]]
                cleanup_gemfire(ssh, node)
                cleanup_results[node["name"]] = "green"
            except Exception as exc:
                emit_log(f"[{node['name']}] ❌ Cleanup failed: {str(exc)}")
                print(f"❌ Cleanup failed on {node['name']}: {exc}")
                cleanup_results[node["name"]] = "red"
        
        run_parallel(active_nodes, cleanup_worker)
        
        for node in active_nodes:
            emit_status(node["region"], "Prepare Hosts", cleanup_results.get(node["name"], "red"))
            socketio.sleep(0.02)
        
        # Check for failures - stop if any cleanup failed
        check_step_failures(cleanup_results, "Hard Reset", active_nodes)
        
        check_cancellation()

        # Start locators on all nodes

        emit_log("\n📍 STEP 1: Starting locators...")
        for node in active_nodes:
            emit_status(node["region"], "Start Locators", "orange")

        locator_results = {}

        def start_locator_worker(node):
            try:
                region = node["region"]
                locator_port = 10336 + node["idx"]
                print(
                    f"\n📍 Starting locator on {node['name']} (port {locator_port})..."
                )
                emit_log(f"[{node['name']}] Starting locator on port {locator_port}...")

                ssh = connections[node["name"]]

                remote_locators = [
                    f"{n['private_ip']}[{10336 + n['idx']}]"
                    for n in active_nodes
                    if n["name"] != node["name"]
                ]
                remote_locators_str = ",".join(remote_locators)

                safe_name = sanitize_node_name(node["name"])

                jmx_port = 10931 + node["idx"]
                http_port = 7071 + node["idx"]

                cmd = (
                    f"gfsh -e 'start locator "
                    f"--name={safe_name}_locator "
                    f"--port={locator_port} "
                    f"--dir={LOCATOR_PATH} "
                    f"--bind-address={node['private_ip']} "
                    f"--http-service-port={http_port} "
                    f"--J=-Dgemfire.distributed-system-id={node['dsid']} "
                    f"--J=-Dgemfire.remote-locators={remote_locators_str} "
                    f"--J=-Dgemfire.jmx-manager-port={jmx_port}'"
                )

                out, err = run_ssh_cmd(connections[node["name"]], cmd, timeout=120)

                if (
                    "successfully started" in out.lower()
                    or "is currently online" in out.lower()
                ):
                    emit_log(f"[{node['name']}] ✅ Locator started successfully")
                    locator_results[node["name"]] = "green"
                else:
                    emit_log(f"[{node['name']}] ⚠️ Locator output: {out[:200]}")
                    locator_results[node["name"]] = "red"
            except Exception as exc:
                emit_log(f"[{node['name']}] ❌ Locator start failed: {str(exc)}")
                print(f"❌ Exception starting locator on {node['name']}: {exc}")
                locator_results[node["name"]] = "red"

        run_parallel(active_nodes, start_locator_worker)
        for node in active_nodes:
            emit_status(node["region"], "Start Locators", locator_results.get(node["name"], "red"))
            socketio.sleep(0.02)
        socketio.sleep(1)
        
        # Check for failures - stop if any locator failed to start
        check_step_failures(locator_results, "Start Locators", active_nodes)
        
        check_cancellation()

        # Start servers on all nodes

        emit_log("\n🖥️  STEP 2: Starting servers...")
        for node in active_nodes:
            emit_status(node["region"], "Start Servers", "orange")

        server_results = {}

        def start_server_worker(node):
            try:
                region = node["region"]
                locator_port = 10336 + node["idx"]
                server_port = 40404 + node["idx"]
                rest_port = 8080 + node["idx"]


                emit_log(f"[{node['name']}] Starting server on port {server_port}...")

                safe_name = sanitize_node_name(node["name"])
                remote_locators = [
                    f"{n['private_ip']}[{10336 + n['idx']}]"
                    for n in active_nodes
                    if n["name"] != node["name"]
                ]
                remote_locators_str = ",".join(remote_locators)

                cmd = (
                    f"gfsh -e 'start server "
                    f"--name={safe_name}_server "
                    f"--dir={SERVER_PATH} "
                    f"--bind-address={node['private_ip']} "
                    f"--server-port={server_port} "
                    f"--locators={node['private_ip']}[{locator_port}] "
                    f"--J=-Dgemfire.distributed-system-id={node['dsid']} "
                    f"--J=-Dgemfire.remote-locators={remote_locators_str} "
                    f"--J=-Dgemfire.enable-time-statistics=true "
                    f"--J=-Dgemfire.pdx-serializer=org.apache.geode.pdx.ReflectionBasedAutoSerializer "
                    f"--start-rest-api=true "
                    f"--http-service-port={rest_port} "
                    f"--http-service-bind-address={node['private_ip']}'"
                )

                out, err = run_ssh_cmd(connections[node["name"]], cmd, timeout=120)

                if (
                    "successfully started" in out.lower()
                    or "is currently online" in out.lower()
                ):
                    emit_log(f"[{node['name']}] ✅ Server started successfully")
                    server_results[node["name"]] = "green"
                else:
                    emit_log(f"[{node['name']}] ⚠️ Server output: {out[:200]}")
                    print(f"⚠️ Unexpected output from server start on {node['name']}")
                    server_results[node["name"]] = "red"
            except Exception as exc:
                emit_log(f"[{node['name']}] ❌ Server start failed: {str(exc)}")
                print(f"❌ Server start failed on {node['name']}: {exc}")
                server_results[node["name"]] = "red"

        run_parallel(active_nodes, start_server_worker)
        for node in active_nodes:
            emit_status(node["region"], "Start Servers", server_results.get(node["name"], "red"))
            socketio.sleep(0.02)
        socketio.sleep(1.5)
        
        # Check for failures - stop if any server failed to start
        check_step_failures(server_results, "Start Servers", active_nodes)
        
        check_cancellation()

        # Create gateway senders (BEFORE receivers!)

        emit_log("\n🚀 STEP 3: Creating gateway senders...")
        for node in active_nodes:
            emit_status(node["region"], "Start Gateways", "orange")

        sender_results = {}

        def gateway_sender_worker(node):
            region = node["region"]
            locator_port = 10336 + node["idx"]
            emit_log(f"[{node['name']}] Creating gateway senders...")

            ssh = connections[node["name"]]
            node_success = True

            for target_node in active_nodes:
                if target_node["name"] == node["name"]:
                    continue

                target_dsid = target_node["dsid"]
                sender_region = target_node["region"].replace(" ", "")
                sender_id = f"To{sender_region}"

                cmd = (
                    f"gfsh -e 'connect --locator={node['private_ip']}[{locator_port}]' "
                    f"-e 'create gateway-sender --id={sender_id} "
                    f"--parallel=true "
                    f"--remote-distributed-system-id={target_dsid}'"
                )
                out, err = run_ssh_cmd(ssh, cmd, timeout=45)

                if "created successfully" in out.lower() or sender_id in out:
                    emit_log(f"[{node['name']}] ✅ Sender {sender_id} created")
                else:
                    emit_log(f"[{node['name']}] ⚠️ Sender creation: {out[:150]}")
                    node_success = False

            sender_results[node["name"]] = "green" if node_success else "red"
        run_parallel(active_nodes, gateway_sender_worker)
        for node in active_nodes:
            emit_status(node["region"], "Start Gateways", sender_results.get(node["name"], "red"))
            socketio.sleep(0.02)
        socketio.sleep(1)
        
        # Check for failures - stop if any gateway sender failed
        check_step_failures(sender_results, "Start Gateways", active_nodes)
        
        check_cancellation()

        # Create gateway receivers (AFTER senders!)

        emit_log("\n📡 STEP 4: Creating gateway receivers...")
        for node in active_nodes:
            emit_status(node["region"], "Start Receivers", "orange")

        receiver_results = {}

        def gateway_receiver_worker(node):
            region = node["region"]
            locator_port = 10336 + node["idx"]
            receiver_start_port = 55221 + node["idx"]
            receiver_end_port = receiver_start_port + 1

            emit_log(
                f"[{node['name']}] Creating gateway receiver on ports {receiver_start_port}-{receiver_end_port}..."
            )

            ssh = connections[node["name"]]
            cmd = (
                f"gfsh -e 'connect --locator={node['private_ip']}[{locator_port}]' "
                f"-e 'destroy gateway-receiver --if-exists' "
                f"-e 'create gateway-receiver "
                f"--start-port={receiver_start_port} "
                f"--end-port={receiver_end_port} "
                f"--bind-address={node['private_ip']}'"
            )

            out, err = run_ssh_cmd(ssh, cmd, timeout=60)

            if "created on" in out.lower() or "already exists" in out.lower():
                emit_log(f"[{node['name']}] ✅ Gateway receiver created")
                receiver_results[node["name"]] = "green"
            else:
                emit_log(f"[{node['name']}] ⚠️ Gateway receiver output: {out[:200]}")
                receiver_results[node["name"]] = "red"

        run_parallel(active_nodes, gateway_receiver_worker)
        for node in active_nodes:
            emit_status(node["region"], "Start Receivers", receiver_results.get(node["name"], "red"))
            socketio.sleep(0.02)
        socketio.sleep(1)

        # Check for failures - stop if any gateway receiver failed
        check_step_failures(receiver_results, "Start Receivers", active_nodes)
        
        check_cancellation()

        # Configure PDX serializer (needed for JSON serialization)
        emit_log("\n⚙️  Configuring PDX serializer...")
        for node in active_nodes:
            locator_port = 10336 + node["idx"]
            ssh = connections[node["name"]]
            cmd = (
                f"gfsh -e 'connect --locator={node['private_ip']}[{locator_port}]' "
                f"-e 'configure pdx --read-serialized=true --disk-store-name='"
            )
            run_ssh_cmd(ssh, cmd, timeout=30)

        # Create regions

        emit_log("\n🗂️  STEP 5: Creating regions...")
        for node in active_nodes:
            emit_status(node["region"], "Create Regions", "orange")

        region_results = {}

        def create_region_worker(node):
            region = node["region"]
            locator_port = 10336 + node["idx"]
            emit_log(f"[{node['name']}] Creating TestRegion...")

            ssh = connections[node["name"]]
            sender_ids = [
                f"To{n['region'].replace(' ', '')}"
                for n in active_nodes
                if n["name"] != node["name"]
            ]
            sender_ids_str = ",".join(sender_ids)

            cmd = (
                f"gfsh -e 'connect --locator={node['private_ip']}[{locator_port}]' "
                f"-e 'destroy region --name=TestRegion --if-exists' "
                f"-e 'create region "
                f"--name=TestRegion "
                f"--type=PARTITION "
                f"--key-constraint=java.lang.String "
                f"--gateway-sender-id={sender_ids_str}'"
            )

            out, err = run_ssh_cmd(ssh, cmd, timeout=45)

            if "created on" in out.lower() or "already exists" in out.lower():
                emit_log(f"[{node['name']}] ✅ TestRegion created")
                region_results[node["name"]] = "green"
            else:
                emit_log(f"[{node['name']}] ⚠️ Region creation: {out[:200]}")
                region_results[node["name"]] = "red"

        run_parallel(active_nodes, create_region_worker)
        for node in active_nodes:
            emit_status(node["region"], "Create Regions", region_results.get(node["name"], "red"))
            socketio.sleep(0.02)

        # Check for failures - stop if any region creation failed
        check_step_failures(region_results, "Create Regions", active_nodes)
        
        check_cancellation()

        # Verify setup is complete for all nodes before proceeding

        setup_complete = True
        failed_nodes = []
        for node in active_nodes:
            node_failed = False
            if locator_results.get(node["name"]) == "red":
                node_failed = True
            if server_results.get(node["name"]) == "red":
                node_failed = True
            if sender_results.get(node["name"]) == "red":
                node_failed = True
            if receiver_results.get(node["name"]) == "red":
                node_failed = True
            if region_results.get(node["name"]) == "red":
                node_failed = True
            
            if node_failed:
                setup_complete = False
                failed_nodes.append(node["name"])
        
        if not setup_complete:
            error_msg = f"Step 3 (Setup) incomplete - cannot proceed to read/write tests. Failed nodes: {', '.join(failed_nodes)}"
            emit_log(f"❌ {error_msg}")
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
        
        print("✅ Step 3 (Setup) complete for all nodes - proceeding to read/write tests")
        emit_log("✅ Step 3 (Setup) complete for all nodes - proceeding to read/write tests")
        
        check_cancellation()

        # Do a read test (only after Step 3 is complete for ALL nodes)
        
        emit_log("\n📖 Running WAN Read Check...")
        for node in active_nodes:
            emit_status(node["region"], "WAN Read Check", "orange")
        
        rest_lock = threading.Lock()
        read_test_passed = True
        
        def rest_check_worker(node):
            nonlocal read_test_passed
            region = node["region"]
            rest_port = 8080 + node.get("idx", 0)
            rest_url = f"http://{node['public_ip']}:{rest_port}/geode/v1"
            try:
                emit_log(f"[{node['name']}] Testing REST API at {rest_url}...")
                response = requests.get(f"{rest_url}/TestRegion", timeout=5)
                if response.status_code == 200:
                    emit_status(region, "WAN Read Check", "green")
                    with rest_lock:
                        rest_api_working[node["name"]] = rest_url
                    emit_log(f"[{node['name']}] ✅ REST API is responding")
                else:
                    emit_status(region, "WAN Read Check", "red")
                    emit_log(f"[{node['name']}] ⚠️ REST API returned HTTP {response.status_code}")
                    with rest_lock:
                        read_test_passed = False
            except Exception as e:
                emit_status(region, "WAN Read Check", "red")
                emit_log(f"[{node['name']}] ❌ REST API test failed: {e}")
                with rest_lock:
                    read_test_passed = False
        
        run_parallel(active_nodes, rest_check_worker)
        
        if not read_test_passed:
            error_msg = "WAN Read Test failed - REST API not responding on all nodes"
            emit_log(f"❌ {error_msg}")
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
        
        emit_log("✅ WAN Read Check complete")
        check_cancellation()

        # Do a WAN write test
        
        emit_log("\n✏️ Running WAN Write Check...")
        test_key = None
        test_value = None
        
        # Define cleanup function at outer scope so it's accessible everywhere
        def cleanup_test_entries(test_key_to_delete=None, delete_all=False, raise_errors=False):
            """Clean up WAN test entries - delete from first node only, WAN will replicate."""
            if test_key_to_delete is None and not delete_all:
                return
            
            if not active_nodes:
                return
            
            first_node = active_nodes[0]
            ssh = connections.get(first_node["name"])
            if not ssh:
                return
            
            try:
                locator_port = 10336 + first_node["idx"]
                if delete_all:
                    cmd = (
                        f"gfsh -e 'connect --locator={first_node['private_ip']}[{locator_port}]' "
                        f"-e 'destroy region --name=TestRegion --if-exists'"
                    )
                    run_ssh_cmd(ssh, cmd, timeout=30)
                else:
                    # Query all entries and find ones containing the test key
                    query_cmd = (
                        f"gfsh -e 'connect --locator={first_node['private_ip']}[{locator_port}]' "
                        f"-e \"query --query='SELECT entry.key, entry.value FROM /TestRegion.entries entry'\""
                    )
                    query_out, _ = run_ssh_cmd(ssh, query_cmd, timeout=30)
                    
                    # Parse query results to find actual keys
                    keys_to_delete = []
                    if query_out:
                        lines = query_out.split('\n')
                        in_data_section = False
                        for line in lines:
                            if 'key' in line.lower() and 'value' in line.lower():
                                in_data_section = True
                                continue
                            if '---' in line:
                                continue
                            if in_data_section and test_key_to_delete in line:
                                parts = line.split('|')
                                if len(parts) > 0:
                                    potential_key = parts[0].strip()
                                    if potential_key and potential_key not in ['key', '---', '']:
                                        keys_to_delete.append(potential_key)
                    
                    # Delete found keys
                    for actual_key in keys_to_delete:
                        escaped_key = actual_key.replace("'", "\\'")
                        remove_cmd = (
                            f"gfsh -e 'connect --locator={first_node['private_ip']}[{locator_port}]' "
                            f"-e \"remove --region=TestRegion --key='{escaped_key}'\""
                        )
                        run_ssh_cmd(ssh, remove_cmd, timeout=30)
            except Exception as cleanup_err:
                if raise_errors:
                    raise
        
        if len(rest_api_working) >= 2:
            try:
                # Write data to first node
                first_node = active_nodes[0]
                first_rest_url = rest_api_working.get(first_node["name"])
                
                if first_rest_url:
                    test_key = f"wan_test_{int(time.time())}"
                    test_value = f"test_data_{int(time.time())}"
                    
                    put_response = requests.post(
                        f"{first_rest_url}/TestRegion",
                        json={test_key: test_value},
                        headers={"Content-Type": "application/json"},
                        timeout=5,
                    )
                    
                    if put_response.status_code in [200, 201]:
                        socketio.sleep(3)  # Wait for replication
                        
                        write_test_passed = True
                        
                        for node in active_nodes:
                            emit_status(node["region"], "WAN Write Check", "orange")
                        
                        def replication_worker(node):
                            nonlocal write_test_passed
                            if node["name"] == first_node["name"]:
                                emit_status(node["region"], "WAN Write Check", "green")
                                return
                            
                            node_url = rest_api_working.get(node["name"])
                            if not node_url:
                                emit_status(node["region"], "WAN Write Check", "red")
                                with rest_lock:
                                    write_test_passed = False
                                return
                            
                            try:
                                get_response = requests.get(f"{node_url}/TestRegion", timeout=5)
                                
                                if get_response.status_code == 200:
                                    data_resp = get_response.json()
                                    found = False
                                    
                                    if (
                                        "TestRegion" in data_resp
                                        and isinstance(data_resp["TestRegion"], list)
                                    ):
                                        for item in data_resp["TestRegion"]:
                                            if (
                                                test_key in item
                                                and item[test_key] == test_value
                                            ):
                                                found = True
                                                break
                                    
                                    if found:
                                        emit_status(node["region"], "WAN Write Check", "green")
                                    else:
                                        emit_status(node["region"], "WAN Write Check", "red")
                                        with rest_lock:
                                            write_test_passed = False
                                else:
                                    emit_status(node["region"], "WAN Write Check", "red")
                                    with rest_lock:
                                        write_test_passed = False
                            except Exception as e:
                                emit_status(node["region"], "WAN Write Check", "red")
                                with rest_lock:
                                    write_test_passed = False
                        
                        run_parallel(active_nodes, replication_worker)
                        
                        if not write_test_passed:
                            error_msg = "WAN Write Test failed - data replication failed"
                            emit_log(f"❌ {error_msg}")
                            print(f"❌ {error_msg}")
                            raise RuntimeError(error_msg)
                    else:
                        error_msg = f"Failed to write test data - HTTP {put_response.status_code}"
                        emit_log(f"❌ {error_msg}")
                        print(f"❌ {error_msg}")
                        raise RuntimeError(error_msg)
            except Exception as e:
                error_msg = f"WAN Write Test failed: {str(e)}"
                emit_log(f"❌ {error_msg}")
                print(f"❌ {error_msg}")
                raise RuntimeError(error_msg)
        else:
            error_msg = f"Not enough REST APIs available for write test (need 2, got {len(rest_api_working)})"
            emit_log(f"❌ {error_msg}")
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
        
        # Cleanup test entry after successful test
        if test_key is not None:
            cleanup_test_entries(test_key_to_delete=test_key, delete_all=False, raise_errors=False)
        
        emit_log("✅ WAN Write Check complete")
        check_cancellation()

        # ========================================================================
        # Demo Environment Ready (only if all steps succeeded)
        
        # Verify all steps succeeded
        all_succeeded = True
        for node in active_nodes:
            if (cleanup_results.get(node["name"]) == "red" or
                locator_results.get(node["name"]) == "red" or 
                server_results.get(node["name"]) == "red" or
                sender_results.get(node["name"]) == "red" or
                receiver_results.get(node["name"]) == "red" or
                region_results.get(node["name"]) == "red"):
                all_succeeded = False
                print(f"   ⚠️ {node['name']} has failures")
        
        if not all_succeeded:
            error_msg = "Cannot mark demo as ready - failures detected in critical steps"
            emit_log(f"❌ {error_msg}")
            print(f"❌ {error_msg}")
            raise RuntimeError(error_msg)
        
        # All steps succeeded - mark demo environment as ready
        for node in active_nodes:
            emit_status(node["region"], "Demo Environment Ready", "green")
            socketio.sleep(0.1)

        force_all_steps_green(active_nodes)
        emit_log("🎯 Demo Environment Ready - All systems operational!")

    except KeyboardInterrupt as e:
        # Handle cancellation
        emit_log("⚠️ Setup cancelled by user")
        for node in nodes:
            emit_status(node["region"], "WAN Setup", "orange")
            socketio.sleep(0.1)
    except RuntimeError as e:
        # Handle critical step failures
        print(f"❌ Setup stopped: {str(e)}")
        emit_log(f"❌ {str(e)}")
        for node in nodes:
            emit_status(node["region"], "WAN Setup", "red")
            socketio.sleep(0.1)
    except Exception as e:
        # Handle other unexpected exceptions
        print(f"❌ Setup failed: {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()

        emit_log(f"❌ Setup failed: {str(e)}")
        for node in nodes:
            emit_status(node["region"], "WAN Setup", "red")
            socketio.sleep(0.1)

    finally:
        # Close all connections
        print("\n🔌 Closing all SSH connections...")
        for name, ssh in connections.items():
            print(f"   Closing connection to {name}")
            ssh.close()
        print("✅ All connections closed")


def verify_wan_task(data):
    emit_log("🔎 Verifying WAN connectivity...")

    nodes = data["nodes"]
    user = data["ssh_user"]
    keyfile = data["ssh_key"]
    connections = {}
    rest_api_working = {}
    all_passed = True

    try:
        # Connect to all nodes
        connection_lock = threading.Lock()

        def connect_worker(args):
            idx, node = args
            try:
                ssh = connect_node(node, user, keyfile)
                node["idx"] = idx
                # Get private IP for cleanup operations
                node["private_ip"] = get_private_ip(ssh)
                with connection_lock:
                    connections[node["name"]] = ssh
            except Exception as e:
                emit_log(f"[{node['name']}] ❌ Connection failed: {e}")
                with connection_lock:
                    nonlocal_all_passed[0] = False

        nonlocal_all_passed = [all_passed]
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, len(nodes))
        ) as executor:
            list(executor.map(connect_worker, enumerate(nodes)))
        all_passed = nonlocal_all_passed[0]

        # 1️⃣ WAN Read Check - Test REST API
        emit_log("\n📖 Running WAN Read Check...")
        for node in nodes:
            emit_status(node["region"], "WAN Read Check", "orange")

        rest_lock = threading.Lock()
        rest_pass_flag = [all_passed]

        def rest_check_worker(node):
            region = node["region"]
            rest_port = 8080 + node.get("idx", 0)
            rest_url = f"http://{node['public_ip']}:{rest_port}/geode/v1"
            try:
                emit_log(f"[{node['name']}] Testing REST API at {rest_url}...")
                response = requests.get(f"{rest_url}/TestRegion", timeout=5)
                if response.status_code == 200:
                    emit_status(region, "WAN Read Check", "green")
                    with rest_lock:
                        rest_api_working[node["name"]] = rest_url
                    emit_log(f"[{node['name']}] ✅ REST API is responding")
                else:
                    emit_status(region, "WAN Read Check", "red")
                    emit_log(
                        f"[{node['name']}] ⚠️ REST API returned HTTP {response.status_code}"
                    )
                    with rest_lock:
                        rest_pass_flag[0] = False
            except Exception as e:
                emit_status(region, "WAN Read Check", "red")
                emit_log(f"[{node['name']}] ❌ REST API test failed: {e}")
                with rest_lock:
                    rest_pass_flag[0] = False

        run_parallel(nodes, rest_check_worker)
        all_passed = rest_pass_flag[0]

        emit_log("✅ WAN Read Check complete")

        # 2️⃣ WAN Write Check - Test replication
        emit_log("\n✏️ Running WAN Write Check...")
        if len(rest_api_working) >= 2:
            try:
                # Write data to first node
                first_node = nodes[0]
                first_rest_url = rest_api_working.get(first_node["name"])

                if first_rest_url:
                    test_key = f"wan_test_{int(time.time())}"
                    test_value = f"test_data_{int(time.time())}"


                    def cleanup_test_entries(delete_all=False, raise_errors=False):
                        if not nodes:
                            return
                        
                        first_node = nodes[0]
                        ssh = connections.get(first_node["name"])
                        if not ssh:
                            return
                        
                        try:
                            locator_port = 10336 + first_node.get("idx", 0)
                            private_ip = first_node.get("private_ip")
                            if not private_ip:
                                return
                            
                            if delete_all:
                                cmd = (
                                    f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' "
                                    f"-e 'destroy region --name=TestRegion --if-exists'"
                                )
                                run_ssh_cmd(ssh, cmd, timeout=30)
                            else:
                                query_cmd = (
                                    f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' "
                                    f"-e \"query --query='SELECT entry.key, entry.value FROM /TestRegion.entries entry'\""
                                )
                                query_out, _ = run_ssh_cmd(ssh, query_cmd, timeout=30)
                                
                                keys_to_delete = []
                                if query_out:
                                    lines = query_out.split('\n')
                                    in_data_section = False
                                    for line in lines:
                                        if 'key' in line.lower() and 'value' in line.lower():
                                            in_data_section = True
                                            continue
                                        if '---' in line:
                                            continue
                                        if in_data_section and test_key in line:
                                            parts = line.split('|')
                                            if len(parts) > 0:
                                                potential_key = parts[0].strip()
                                                if potential_key and potential_key not in ['key', '---', '']:
                                                    keys_to_delete.append(potential_key)
                                
                                for actual_key in keys_to_delete:
                                    escaped_key = actual_key.replace("'", "\\'")
                                    remove_cmd = (
                                        f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' "
                                        f"-e \"remove --region=TestRegion --key='{escaped_key}'\""
                                    )
                                    run_ssh_cmd(ssh, remove_cmd, timeout=30)
                        except Exception as cleanup_err:
                            if raise_errors:
                                raise

                    try:
                        put_response = requests.post(
                            f"{first_rest_url}/TestRegion",
                            json={test_key: test_value},
                            headers={"Content-Type": "application/json"},
                            timeout=5,
                        )

                        if put_response.status_code in [200, 201]:
                            socketio.sleep(1.5)  # Wait for replication

                            replication_flag = [all_passed]

                            for node in nodes:
                                emit_status(node["region"], "WAN Write Check", "orange")

                            def replication_worker(node):
                                if node["name"] == first_node["name"]:
                                    emit_status(node["region"], "WAN Write Check", "green")
                                    return

                                node_url = rest_api_working.get(node["name"])
                                if not node_url:
                                    emit_status(node["region"], "WAN Write Check", "red")
                                    emit_log(
                                        f"   ❌ [{node['name']}] REST API unavailable for replication check"
                                    )
                                    with rest_lock:
                                        replication_flag[0] = False
                                    return

                                try:
                                    get_response = requests.get(
                                        f"{node_url}/TestRegion", timeout=5
                                    )

                                    if get_response.status_code == 200:
                                        data_resp = get_response.json()
                                        found = False

                                        if (
                                            "TestRegion" in data_resp
                                            and isinstance(data_resp["TestRegion"], list)
                                        ):
                                            for item in data_resp["TestRegion"]:
                                                if (
                                                    test_key in item
                                                    and item[test_key] == test_value
                                                ):
                                                    found = True
                                                    break

                                        if found:
                                            emit_status(
                                                node["region"], "WAN Write Check", "green"
                                            )
                                            emit_log(
                                                f"   ✅ [{node['name']}] Data replicated successfully!"
                                            )
                                        else:
                                            emit_status(
                                                node["region"], "WAN Write Check", "red"
                                            )
                                            emit_log(
                                                f"   ❌ [{node['name']}] Data not found"
                                            )
                                            with rest_lock:
                                                replication_flag[0] = False
                                    else:
                                        emit_status(node["region"], "WAN Write Check", "red")
                                        emit_log(
                                            f"   ❌ [{node['name']}] HTTP {get_response.status_code} during replication check"
                                        )
                                        with rest_lock:
                                            replication_flag[0] = False
                                except Exception as e:
                                    emit_status(node["region"], "WAN Write Check", "red")
                                    emit_log(f"   ❌ [{node['name']}] Error: {e}")
                                    with rest_lock:
                                        replication_flag[0] = False

                            run_parallel(nodes, replication_worker)
                            all_passed = all_passed and replication_flag[0]
                        else:
                            all_passed = False
                            for node in nodes:
                                emit_status(node["region"], "WAN Write Check", "red")
                                socketio.sleep(0.1)
                    finally:
                        cleanup_test_entries(delete_all=False, raise_errors=False)
            except Exception as e:
                emit_log(f"   ❌ Replication test failed: {e}")
                all_passed = False
                for node in nodes:
                    emit_status(node["region"], "WAN Write Check", "red")
                    socketio.sleep(0.1)
        else:
            emit_log("   ⚠️ Not enough working REST APIs to test replication")
            all_passed = False
            for node in nodes:
                emit_status(node["region"], "WAN Write Check", "red")
                socketio.sleep(0.1)

        emit_log("✅ WAN Write Check complete")
        # 3️⃣ Demo Environment Ready
        if all_passed:
            emit_log("🎯 Demo Environment Ready - All systems operational!")
            force_all_steps_green(nodes)
        else:
            emit_log("⚠️ Demo Environment has issues")

    except Exception as e:
        emit_log(f"❌ Verification failed: {str(e)}")
        for node in nodes:
            emit_status(node["region"], "Demo Environment Ready", "red")

    finally:
        # Close all connections
        for ssh in connections.values():
            ssh.close()


# -----------------------------------------------------------------------------
# SocketIO Event Handlers
# -----------------------------------------------------------------------------
@socketio.on("connect")
def handle_connect():
    pass


@socketio.on("disconnect")
def handle_disconnect():
    pass


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    try:
        session_data = load_default_session()
        return render_template(
            "control_index.html",
            session=session_data,
            steps=STEPS,
            demo_url=DEMO_DASHBOARD_URL,
        )
    except Exception as e:
        return f"Error loading page: {str(e)}", 500


@app.route("/test_status", methods=["POST"])
def test_status():
    """Test endpoint to verify WebSocket communication"""
    test_regions = ["US East", "US West", "EU"]
    test_steps = ["SSH Connectivity", "Start Locators", "Start Servers"]

    for region in test_regions:
        for step in test_steps:
            emit_status(region, step, "orange")
            time.sleep(0.5)
            emit_status(region, step, "green")
            time.sleep(0.5)

    emit_log("✅ Test completed - if you see colors changing, WebSocket is working!")
    return jsonify({"status": "test completed"})


@app.route("/verify_nodes", methods=["POST"])
def verify_nodes():
    try:
        data = request.get_json()
        if not data or "nodes" not in data:
            return jsonify({"status": "error", "message": "Invalid request data"}), 400
        
        emit_log("🔍 Starting node verification...")
        for node in data["nodes"]:
            emit_status(node["region"], "SSH Connectivity", "orange")

        socketio.start_background_task(verify_nodes_task, data)
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/prepare_hosts", methods=["POST"])
def prepare_hosts():
    try:
        data = request.get_json()
        if not data or "nodes" not in data:
            return jsonify({"status": "error", "message": "Invalid request data"}), 400

        emit_log("🧹 Starting host preparation and cleanup...")
        for node in data["nodes"]:
            emit_status(node["region"], "Prepare Hosts", "orange")

        socketio.start_background_task(prepare_hosts_task, data)
        return jsonify({"status": "started", "message": "Cleanup task started"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/start_demo", methods=["POST"])
def start_demo():
    try:
        data = request.get_json()
        if not data or "nodes" not in data:
            return jsonify({"status": "error", "message": "Invalid request data"}), 400

        emit_log("🚀 Starting WAN setup demo...")

        wan_setup_steps = [
            "Start Locators",
            "Start Servers",
            "Start Gateways",
            "Start Receivers",
            "Create Regions",
            "WAN Setup",
        ]

        for node in data["nodes"]:
            for step in wan_setup_steps:
                emit_status(node["region"], step, "orange")
                socketio.sleep(0.05)

        socketio.start_background_task(setup_wan_task, data)
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/verify_wan", methods=["POST"])
def verify_wan():
    try:
        data = request.get_json()
        if not data or "nodes" not in data:
            return jsonify({"status": "error", "message": "Invalid request data"}), 400

        emit_log("🔎 Starting WAN verification...")

        verification_steps = ["WAN Read Check", "WAN Write Check", "Demo Environment Ready"]

        for node in data["nodes"]:
            for step in verification_steps:
                emit_status(node["region"], step, "orange")
                socketio.sleep(0.05)

        socketio.start_background_task(verify_wan_task, data)
        return jsonify({"status": "started"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/abort_setup", methods=["POST"])
def abort_setup():
    """Abort the current setup by setting the cancellation event."""
    try:
        global setup_cancellation_event
        setup_cancellation_event.set()
        emit_log("⚠️ Setup cancellation requested by user")
        return jsonify({"status": "cancelled", "message": "Setup cancellation requested"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/cleanup_data", methods=["POST"])
def cleanup_data():
    """Clean up all data in TestRegion by destroying and recreating on all nodes."""
    try:
        emit_log("🧹 Starting data cleanup...")
        
        # Load session to get nodes
        session = load_default_session()
        nodes = session.get("nodes", [])
        ssh_user = session.get("ssh_user", "ec2-user")
        ssh_key = session.get("ssh_key", "")
        
        if not nodes:
            return jsonify({"status": "error", "message": "No nodes configured"}), 400
        
        if not ssh_key:
            return jsonify({"status": "error", "message": "SSH key not configured"}), 400
        
        emit_log(f"🔌 Connecting to {len(nodes)} node(s) for cleanup...")
        
        # Connect to all nodes
        connections = {}
        for node in nodes:
            try:
                ssh = connect_node(node, ssh_user, ssh_key)
                node["private_ip"] = get_private_ip(ssh)
                node["idx"] = nodes.index(node)
                connections[node["name"]] = ssh
                emit_log(f"✅ Connected to {node['name']}")
            except Exception as e:
                emit_log(f"❌ Failed to connect to {node['name']}: {str(e)}")
                return jsonify({"status": "error", "message": f"Failed to connect to {node['name']}: {str(e)}"}), 500
        
        if not connections:
            return jsonify({"status": "error", "message": "Failed to connect to any nodes"}), 500
        
        emit_log(f"🗑️ Destroying and recreating TestRegion on all nodes (fastest cleanup method)...")
        
        # Destroy and recreate region on all nodes in parallel
        def cleanup_region_worker(node):
            node_name = node["name"]
            ssh = connections[node_name]
            locator_port = 10336 + node["idx"]
            private_ip = node["private_ip"]
            
            # Build gateway sender IDs for this node (all other regions)
            sender_ids = [
                f"To{n['region'].replace(' ', '')}"
                for n in nodes
                if n["name"] != node_name
            ]
            sender_ids_str = ",".join(sender_ids) if sender_ids else ""
            
            emit_log(f"[{node_name}] Destroying and recreating TestRegion...")
            
            # Destroy and recreate the region
            cmd = (
                f"gfsh -e 'connect --locator={private_ip}[{locator_port}]' "
                f"-e 'destroy region --name=TestRegion --if-exists' "
                f"-e 'create region "
                f"--name=TestRegion "
                f"--type=PARTITION "
                f"--key-constraint=java.lang.String "
                f"--gateway-sender-id={sender_ids_str}'"
            )
            
            out, err = run_ssh_cmd(ssh, cmd, timeout=60)
            
            # Check if region was recreated successfully
            if "created on" in out.lower() or "already exists" in out.lower() or "created successfully" in out.lower():
                emit_log(f"[{node_name}] ✅ TestRegion destroyed and recreated with JSONFormatter constraint")
                return {"node": node_name, "status": "success"}
            else:
                emit_log(f"[{node_name}] ⚠️ Region recreation output: {out[:200]}")
                return {"node": node_name, "status": "warning", "output": out[:200]}
        
        # Run cleanup on all nodes in parallel
        import concurrent.futures
        max_workers = max(1, min(len(nodes), 8))
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(cleanup_region_worker, node) for node in nodes]
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    emit_log(f"❌ Error in cleanup worker: {str(e)}")
                    results.append({"status": "error", "error": str(e)})
        
        # Close all connections
        for ssh in connections.values():
            ssh.close()
        
        # Check results
        success_count = sum(1 for r in results if r.get("status") == "success")
        warning_count = sum(1 for r in results if r.get("status") == "warning")
        
        if success_count == len(nodes):
            emit_log(f"✅ Cleanup completed")
            return jsonify({
                "status": "success",
                "message": "Cleanup completed",
                "method": "destroy_and_recreate",
                "nodes_processed": len(nodes),
                "successful": success_count
            })
        elif success_count > 0:
            emit_log(f"✅ Cleanup completed")
            return jsonify({
                "status": "success",
                "message": "Cleanup completed",
                "nodes_processed": len(nodes),
                "successful": success_count,
                "warnings": warning_count
            })
        else:
            emit_log(f"❌ Cleanup failed")
            return jsonify({
                "status": "error",
                "message": "Cleanup failed",
                "results": results
            }), 500
            
    except Exception as e:
        # Close any open connections
        for ssh in connections.values():
            try:
                ssh.close()
            except:
                pass
        
        emit_log(f"❌ Cleanup failed: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/check_latency", methods=["POST"])
def check_latency():
    """Check latency by inserting 1 record into Postgres and GemFire, then measuring read times using WAN write check logic."""
    try:
        # Try psycopg2 first (more compatible with eventlet), fallback to psycopg3
        try:
            import psycopg2 as psycopg
            psycopg_connect = psycopg.connect
        except ImportError:
            try:
                import psycopg
                psycopg_connect = psycopg.connect
            except ImportError:
                return jsonify({"status": "error", "message": "psycopg2 or psycopg not installed. Install with: pip install psycopg2-binary"}), 500
        
        # Get Postgres connection details from environment
        pg_host = os.getenv("POSTGRES_HOST", "localhost")
        pg_port = int(os.getenv("POSTGRES_PORT", "5432"))
        pg_db = os.getenv("POSTGRES_DB", "postgres")
        pg_user = os.getenv("POSTGRES_USER", "postgres")
        pg_password = os.getenv("POSTGRES_PASSWORD", "")
        
        if not pg_password:
            return jsonify({"status": "error", "message": "POSTGRES_PASSWORD not set in .env file"}), 400
        
        emit_log("🔍 Starting latency check...")
        
        # Get node configuration
        session = load_default_session()
        nodes = session.get("nodes", [])
        
        if not nodes:
            return jsonify({"status": "error", "message": "No nodes configured"}), 400
        
        # Set idx for each node (same as WAN setup)
        for idx, node in enumerate(nodes):
            node["idx"] = idx
        
        # Generate test key and value (same format as WAN write check)
        test_key = f"latency_test_{int(time.time())}"
        test_value = f"test_data_{int(time.time())}"
        
        # Connect to Postgres
        try:
            pg_conn = psycopg_connect(
                host=pg_host,
                port=pg_port,
                dbname=pg_db,
                user=pg_user,
                password=pg_password
            )
            # For psycopg2, set autocommit
            if hasattr(pg_conn, 'autocommit'):
                pg_conn.autocommit = True
            else:
                pg_conn.set_session(autocommit=True)
            emit_log("✅ Connected to Postgres")
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to connect to Postgres: {str(e)}"}), 500
        
        # Create table if it doesn't exist
        try:
            with pg_conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS latency_test (
                        id SERIAL PRIMARY KEY,
                        key VARCHAR(255) UNIQUE NOT NULL,
                        value TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            emit_log("✅ Postgres table ready")
        except Exception as e:
            pg_conn.close()
            return jsonify({"status": "error", "message": f"Failed to create Postgres table: {str(e)}"}), 500
        
        # Insert into Postgres (same key/value as GemFire)
        try:
            with pg_conn.cursor() as cur:
                # Clear old test data
                cur.execute("DELETE FROM latency_test WHERE key LIKE 'latency_test_%'")
                # Insert new record
                cur.execute(
                    "INSERT INTO latency_test (key, value) VALUES (%s, %s)",
                    (test_key, test_value)
                )
            emit_log(f"✅ Inserted record into Postgres: {test_key}={test_value}")
        except Exception as e:
            pg_conn.close()
            return jsonify({"status": "error", "message": f"Failed to insert into Postgres: {str(e)}"}), 500
        
        # Get REST API URLs for all nodes (same logic as demo dashboard)
        # Build node config similar to demo_dashboard.get_node_config()
        REST_API_PORT_OFFSET = 8080
        REGION_TO_ROLE = {
            "US East": "C2",
            "US West": "Aircraft",
            "EU": "Submarine",
        }
        
        rest_api_working = {}
        for idx, node in enumerate(nodes):
            node["idx"] = idx  # Ensure idx is set
            region = node.get("region", "")
            role = REGION_TO_ROLE.get(region, "")
            if role:
                rest_port = REST_API_PORT_OFFSET + idx
                public_ip = node.get("public_ip", "")
                if public_ip:
                    rest_url = f"http://{public_ip}:{rest_port}/geode/v1"
                    rest_api_working[node["name"]] = rest_url
                    emit_log(f"✅ {node['name']} REST API: {rest_url}")
        
        if not rest_api_working:
            pg_conn.close()
            return jsonify({"status": "error", "message": "No REST API URLs available"}), 400
        
        # Write to GemFire using first node (same as WAN write check - POST method)
        first_node = nodes[0]
        first_rest_url = rest_api_working.get(first_node["name"])
        region_name = "TestRegion"
        
        if first_rest_url:
            try:
                post_response = requests.post(
                    f"{first_rest_url}/{region_name}",
                    json={test_key: test_value},
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
                
                if post_response.status_code in [200, 201]:
                    emit_log(f"✅ Inserted record into GemFire: {test_key}={test_value}")
                    socketio.sleep(2)  # Wait for replication (shorter than WAN check)
                else:
                    emit_log(f"⚠️ Warning: Failed to insert into GemFire: HTTP {post_response.status_code}")
            except Exception as e:
                emit_log(f"⚠️ Warning: Failed to insert into GemFire: {str(e)}")
        
        # Measure Postgres read time (includes connection overhead if remote)
        # Note: This measures full round-trip time including network if Postgres is remote
        pg_read_time = None
        try:
            # Close existing connection to measure full round-trip
            pg_conn.close()
            
            # Measure full round-trip: connection + query
            start_time = time.time()
            pg_conn = psycopg_connect(
                host=pg_host,
                port=pg_port,
                dbname=pg_db,
                user=pg_user,
                password=pg_password
            )
            if hasattr(pg_conn, 'autocommit'):
                pg_conn.autocommit = True
            else:
                pg_conn.set_session(autocommit=True)
            
            with pg_conn.cursor() as cur:
                cur.execute("SELECT value FROM latency_test WHERE key = %s", (test_key,))
                result = cur.fetchone()
            end_time = time.time()
            pg_read_time = (end_time - start_time) * 1000  # Convert to milliseconds
            emit_log(f"📊 Postgres read time (with connection): {pg_read_time:.2f}ms")
            pg_conn.close()
        except Exception as e:
            try:
                pg_conn.close()
            except:
                pass
            return jsonify({"status": "error", "message": f"Failed to read from Postgres: {str(e)}"}), 500
        
        # Measure GemFire read times for each node (using WAN write check read logic)
        gemfire_results = {}
        for node in nodes:
            node_name = node["name"]
            node_url = rest_api_working.get(node["name"])
            
            if not node_url:
                gemfire_results[node_name] = {
                    "read_ms": None,
                    "success": False,
                    "error": "REST API URL not available"
                }
                continue
            
            try:
                # Read using GET (same as WAN write check)
                start_time = time.time()
                get_response = requests.get(f"{node_url}/{region_name}", timeout=5)
                end_time = time.time()
                read_time = (end_time - start_time) * 1000  # Convert to milliseconds
                
                if get_response.status_code == 200:
                    try:
                        data_resp = get_response.json()
                        found = False
                        
                        # Search for the key in response (same logic as WAN write check)
                        if "TestRegion" in data_resp:
                            region_data = data_resp["TestRegion"]
                            
                            # Handle list format
                            if isinstance(region_data, list):
                                for item in region_data:
                                    if isinstance(item, dict) and test_key in item and item[test_key] == test_value:
                                        found = True
                                        break
                            # Handle dict format
                            elif isinstance(region_data, dict) and test_key in region_data and region_data[test_key] == test_value:
                                found = True
                        
                        if found:
                            gemfire_results[node_name] = {
                                "read_ms": round(read_time, 2),
                                "success": True
                            }
                            emit_log(f"📊 {node_name} read time: {read_time:.2f}ms (found)")
                        else:
                            gemfire_results[node_name] = {
                                "read_ms": round(read_time, 2),
                                "success": False,
                                "error": "Record not found in response"
                            }
                            emit_log(f"⚠️ {node_name} read time: {read_time:.2f}ms (not found)")
                    except Exception as json_err:
                        gemfire_results[node_name] = {
                            "read_ms": round(read_time, 2),
                            "success": False,
                            "error": f"Failed to parse JSON: {str(json_err)}"
                        }
                        emit_log(f"⚠️ {node_name} read time: {read_time:.2f}ms (JSON parse error)")
                elif get_response.status_code == 503:
                    gemfire_results[node_name] = {
                        "read_ms": None,
                        "success": False,
                        "error": "Service Unavailable (503) - REST API may not be running"
                    }
                    emit_log(f"❌ {node_name}: Service Unavailable (503) - REST API may not be running")
                elif get_response.status_code == 403:
                    gemfire_results[node_name] = {
                        "read_ms": None,
                        "success": False,
                        "error": "Forbidden (403) - Check REST API access"
                    }
                    emit_log(f"❌ {node_name}: Forbidden (403) - Check REST API access")
                else:
                    gemfire_results[node_name] = {
                        "read_ms": None,
                        "success": False,
                        "error": f"HTTP {get_response.status_code}"
                    }
                    emit_log(f"❌ {node_name}: HTTP {get_response.status_code}")
            except requests.exceptions.Timeout:
                gemfire_results[node_name] = {
                    "read_ms": None,
                    "success": False,
                    "error": "Request timeout"
                }
                emit_log(f"❌ {node_name}: Request timeout")
            except requests.exceptions.ConnectionError:
                gemfire_results[node_name] = {
                    "read_ms": None,
                    "success": False,
                    "error": "Connection error - REST API not reachable"
                }
                emit_log(f"❌ {node_name}: Connection error - REST API not reachable")
            except Exception as e:
                gemfire_results[node_name] = {
                    "read_ms": None,
                    "success": False,
                    "error": str(e)
                }
                emit_log(f"❌ {node_name}: Failed to read - {str(e)}")
        
        # Prepare results
        results = {
            "status": "success",
            "postgres": {
                "read_ms": round(pg_read_time, 2)
            },
            "gemfire": gemfire_results
        }
        
        emit_log("✅ Latency check complete")
        return jsonify(results)
        
    except Exception as e:
        import traceback
        error_msg = f"Latency check failed: {str(e)}"
        emit_log(f"❌ {error_msg}")
        traceback.print_exc()
        return jsonify({"status": "error", "message": error_msg}), 500


@app.route("/start_demo_dashboard", methods=["POST"])
def start_demo_dashboard():
    """Start the demo dashboard on demand."""
    try:
        global demo_dashboard_process, demo_dashboard_lock
        
        with demo_dashboard_lock:
            # Check if demo dashboard is already running
            if demo_dashboard_process and demo_dashboard_process.poll() is None:
                emit_log("🌍 Demo dashboard is already running")
                return jsonify({"status": "already_running", "url": DEMO_DASHBOARD_URL})
            
            # Check if port 5002 is accessible (demo dashboard might be running externally)
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', 5002))
                sock.close()
                if result == 0:
                    emit_log("🌍 Demo dashboard is already running on port 5002")
                    return jsonify({"status": "already_running", "url": DEMO_DASHBOARD_URL})
            except:
                pass
            
            # Start demo dashboard in background process
            emit_log("🌍 Starting demo dashboard...")
            env = os.environ.copy()
            env["PYTHONPATH"] = os.getcwd()
            
            # Redirect stderr to a log file to avoid blocking on pipe buffers
            log_file_path = os.path.join(os.getcwd(), "demo_dashboard_error.log")
            log_file = open(log_file_path, "w")
            
            demo_dashboard_process = subprocess.Popen(
                [sys.executable, "app/demo_dashboard.py"],
                env=env,
                cwd=os.getcwd(),
                stdout=subprocess.DEVNULL,  # Discard stdout
                stderr=log_file  # Write errors to log file
            )
            
            # Wait a moment for the process to start
            time.sleep(3)
            
            # Close log file so we can read it
            log_file.close()
            
            # Check if process is still running
            if demo_dashboard_process.poll() is not None:
                # Process exited immediately - read error log
                error_msg = "Demo dashboard failed to start"
                try:
                    if os.path.exists(log_file_path):
                        with open(log_file_path, "r") as f:
                            error_content = f.read()
                            if error_content:
                                # Filter out debugger messages
                                error_lines = [line for line in error_content.split('\n') 
                                              if line.strip() and 'Debugger' not in line and 'PIN' not in line]
                                if error_lines:
                                    error_msg = '\n'.join(error_lines[:10])
                except Exception:
                    pass
                
                # Check if port is accessible anyway
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', 5002))
                sock.close()
                if result != 0:
                    emit_log(f"❌ Demo dashboard process exited: {error_msg[:300]}")
                    return jsonify({"status": "error", "message": f"Failed to start: {error_msg[:200]}"}), 500
            
            # Verify port is accessible
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('localhost', 5002))
            sock.close()
            
            if result == 0:
                emit_log("✅ Demo dashboard started successfully")
                return jsonify({"status": "started", "url": DEMO_DASHBOARD_URL})
            else:
                emit_log(f"❌ Demo dashboard process running but port 5002 not accessible")
                return jsonify({"status": "error", "message": "Demo dashboard started but port 5002 not accessible"}), 500
            
    except Exception as e:
        emit_log(f"❌ Failed to start demo dashboard: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    print("\n" + "=" * 100)
    print("🚀 STARTING GEMFIRE WAN CONTROL DASHBOARD")
    print("=" * 100)
    print(f"Server will be available at: http://localhost:5004")
    print(f"Server will be available at: http://0.0.0.0:5004")
    print("=" * 100)
    print("\nWaiting for connections...")
    print("All SSH commands and outputs will be displayed below:\n")
    socketio.run(app, host="0.0.0.0", port=5004, debug=True)
