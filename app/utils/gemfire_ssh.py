import paramiko, time, threading, requests

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
CLEANUP_BEFORE_SETUP = False
BASE_PATH = "/home/ec2-user/data/ddl-demo"
LOCATOR_PATH = f"{BASE_PATH}/locator"
SERVER_PATH = f"{BASE_PATH}/server"

socketio = None

# Region to coordinates mapping for visualization
REGION_COORDS = {
    "US West": {"lat": 37.7749, "lng": -122.4194},  # San Francisco
    "US East": {"lat": 38.9072, "lng": -77.0369},  # Washington DC
    "EU": {"lat": 51.5074, "lng": -0.1278},  # London
}


# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def emit_status(msg, node_name=None, status_type="info"):
    """Emit progress updates to both console and dashboard."""
    print(msg)
    if socketio:
        socketio.emit(
            "progress", {"message": msg, "node": node_name, "type": status_type}
        )


def run_ssh_cmd(ssh, cmd, timeout=90):
    """Run a remote SSH command and return (stdout, stderr)."""
    try:
        emit_status(f"  💻 EXEC: {cmd}")
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        start = time.time()
        while not stdout.channel.exit_status_ready():
            if time.time() - start > timeout:
                raise TimeoutError(f"⚠️ Timeout: {cmd}")
            time.sleep(1)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        return out, err
    except Exception as e:
        return "", str(e)


def connect_node(node, user, keyfile):
    """Establish SSH connection."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(node["public_ip"], username=user, key_filename=keyfile, timeout=10)
    return ssh


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


def fix_hostname_resolution(ssh, node):
    """Fix hostname resolution by adding entry to /etc/hosts."""
    emit_status(f"[{node['name']}] 🔧 Fixing hostname resolution...", node["name"])

    out, err = run_ssh_cmd(ssh, "hostname")
    hostname = out.strip() if out else None

    if hostname and node.get("private_ip"):
        cmd = f"echo '{node['private_ip']} {hostname}' | sudo tee -a /etc/hosts"
        run_ssh_cmd(ssh, cmd)
        emit_status(
            f"[{node['name']}] ✅ Added {node['private_ip']} {hostname} to /etc/hosts",
            node["name"],
        )


def cleanup_gemfire(ssh, node, locator_port=None):
    """Clean up GemFire by killing processes and wiping directories."""
    emit_status(f"[{node['name']}] 🧹 Cleaning up GemFire...", node["name"], "cleanup")

    # Kill all GemFire processes
    emit_status(f"[{node['name']}] Killing GemFire processes...", node["name"])
    run_ssh_cmd(ssh, "pkill -9 -f 'gemfire' || true")
    run_ssh_cmd(ssh, "pkill -9 -f 'ServerLauncher' || true")
    run_ssh_cmd(ssh, "pkill -9 -f 'LocatorLauncher' || true")
    run_ssh_cmd(ssh, "pkill -9 -f 'gfsh' || true")
    time.sleep(1)

    # Free up only the ports used by this node
    emit_status(f"[{node['name']}] Freeing up ports...", node["name"])
    idx = node.get("idx", 0)
    ports_to_free = [
        40404,  # Common GemFire port
        10336 + idx,  # Locator port
        55221 + idx,  # Server port
        8080 + idx,  # REST API port
        10931 + idx,  # Gateway receiver port
    ]
    for port in ports_to_free:
        run_ssh_cmd(ssh, f"lsof -ti:{port} | xargs kill -9 2>/dev/null || true")

    # Clean all directories
    emit_status(f"[{node['name']}] Removing data directories...", node["name"])
    run_ssh_cmd(ssh, f"rm -rf {LOCATOR_PATH}/*")
    run_ssh_cmd(ssh, f"rm -rf {SERVER_PATH}/*")
    run_ssh_cmd(ssh, f"rm -rf {BASE_PATH}/*.log")
    run_ssh_cmd(ssh, f"rm -rf {BASE_PATH}/*.pid")

    emit_status(f"[{node['name']}] ✅ Cleanup complete", node["name"], "success")


# -----------------------------------------------------------------------------
# WAN Setup Core
# -----------------------------------------------------------------------------
def setup_wan_demo(nodes, user, keyfile):
    global socketio

    emit_status("🚀 Starting full GemFire WAN setup...")
    emit_status("--------------------------------------------------")

    # 1️⃣ Establish SSH and discover private IPs
    connections = {}
    for idx, node in enumerate(nodes):
        try:
            name = node["name"]
            emit_status(
                f"[{name}] 🔌 Connecting to {node['public_ip']}...", name, "connecting"
            )
            ssh = connect_node(node, user, keyfile)
            node["private_ip"] = get_private_ip(ssh)
            node["dsid"] = idx + 1
            node["idx"] = idx
            connections[name] = ssh
            emit_status(
                f"[{name}] ✅ Connected → Private IP: {node['private_ip']} DSID: {node['dsid']}",
                name,
                "connected",
            )
        except Exception as e:
            emit_status(f"[{name}] ❌ Connection failed: {e}", name, "error")
            raise

    # 2️⃣ Fix hostname resolution on all nodes
    for node in nodes:
        if node["name"] in connections:
            fix_hostname_resolution(connections[node["name"]], node)

    # 3️⃣ Start locators on all nodes
    emit_status("\n📍 STEP 1: Starting locators...")
    for node in nodes:
        if node["name"] in connections:
            locator_port = 10336 + node["idx"]
            emit_status(
                f"[{node['name']}] Starting locator on port {locator_port}...",
                node["name"],
                "locator_starting",
            )

            ssh = connections[node["name"]]

            # Build remote-locators string
            remote_locators = []
            for n in nodes:
                if n["name"] != node["name"]:
                    remote_port = 10336 + n["idx"]
                    remote_locators.append(f"{n['private_ip']}[{remote_port}]")
            remote_locators_str = ",".join(remote_locators)

            cmd = (
                f"gfsh -e 'start locator "
                f"--name={node['name']}_locator "
                f"--port={locator_port} "
                f"--dir={LOCATOR_PATH} "
                f"--bind-address={node['private_ip']} "
                f"--J=-Dgemfire.distributed-system-id={node['dsid']} "
                f"--J=-Dgemfire.remote-locators={remote_locators_str}'"
            )
            out, err = run_ssh_cmd(ssh, cmd, timeout=120)

            if (
                "successfully started" in out.lower()
                or "is currently online" in out.lower()
            ):
                emit_status(
                    f"[{node['name']}] ✅ Locator started successfully",
                    node["name"],
                    "locator_running",
                )
            else:
                emit_status(
                    f"[{node['name']}] ⚠️ Locator output: {out[:200]}", node["name"]
                )

    time.sleep(5)

    # 4️⃣ Start servers on all nodes
    emit_status("\n🖥️  STEP 2: Starting servers...")
    for node in nodes:
        if node["name"] in connections:
            locator_port = 10336 + node["idx"]
            server_port = 55221 + node["idx"]
            rest_port = 8080 + node["idx"]

            emit_status(
                f"[{node['name']}] Starting server...", node["name"], "server_starting"
            )

            ssh = connections[node["name"]]
            cmd = (
                f"gfsh -e 'start server "
                f"--name={node['name']}_server "
                f"--dir={SERVER_PATH} "
                f"--bind-address={node['private_ip']} "
                f"--server-port={server_port} "
                f"--locators={node['private_ip']}[{locator_port}] "
                f"--J=-Dgemfire.start-dev-rest-api=true "
                f"--J=-Dgemfire.http-service-bind-address={node['private_ip']} "
                f"--J=-Dgemfire.http-service-port={rest_port}'"
            )
            out, err = run_ssh_cmd(ssh, cmd, timeout=120)

            if (
                "successfully started" in out.lower()
                or "is currently online" in out.lower()
            ):
                emit_status(
                    f"[{node['name']}] ✅ Server started successfully",
                    node["name"],
                    "server_running",
                )
            else:
                emit_status(
                    f"[{node['name']}] ⚠️ Server output: {out[:200]}", node["name"]
                )

    time.sleep(5)

    # 5️⃣ Create gateway senders (bidirectional)
    emit_status("\n🔀 STEP 3: Creating gateway senders...")

    # Get all node names for generating sender IDs
    all_node_names = [n["name"] for n in nodes]

    for node in nodes:
        if node["name"] in connections:
            ssh = connections[node["name"]]
            locator_port = 10336 + node["idx"]

            # Create senders to all OTHER nodes
            for target_node in nodes:
                if target_node["name"] != node["name"]:
                    # Create sender ID based on region (cleaner for UI)
                    sender_region = target_node["region"].replace(" ", "")
                    sender_id = f"To{sender_region}"

                    emit_status(
                        f"[{node['name']}] Creating sender {sender_id} → {target_node['name']} (DSID {target_node['dsid']})...",
                        node["name"],
                    )

                    cmd = (
                        f"gfsh -e 'connect --locator={node['private_ip']}[{locator_port}]' "
                        f"-e 'create gateway-sender --id={sender_id} "
                        f"--parallel=true "
                        f"--remote-distributed-system-id={target_node['dsid']}'"
                    )
                    out, err = run_ssh_cmd(ssh, cmd, timeout=60)

                    if "created successfully" in out.lower() or sender_id in out:
                        emit_status(
                            f"[{node['name']}] ✅ Sender {sender_id} created",
                            node["name"],
                        )
                    else:
                        emit_status(
                            f"[{node['name']}] ⚠️ Sender output: {out[:150]}",
                            node["name"],
                        )

    time.sleep(3)

    # 6️⃣ Create gateway receivers
    emit_status("\n📥 STEP 4: Creating gateway receivers...")
    for node in nodes:
        if node["name"] in connections:
            ssh = connections[node["name"]]
            locator_port = 10336 + node["idx"]
            receiver_start_port = 10931 + node["idx"]
            receiver_end_port = receiver_start_port

            emit_status(f"[{node['name']}] Creating gateway receiver...", node["name"])

            cmd = (
                f"gfsh -e 'connect --locator={node['private_ip']}[{locator_port}]' "
                f"-e 'create gateway-receiver "
                f"--start-port={receiver_start_port} "
                f"--end-port={receiver_end_port} "
                f"--bind-address={node['private_ip']}'"
            )
            out, err = run_ssh_cmd(ssh, cmd, timeout=60)

            if "created successfully" in out.lower() or "receiver" in out.lower():
                emit_status(
                    f"[{node['name']}] ✅ Gateway receiver created", node["name"]
                )
            else:
                emit_status(
                    f"[{node['name']}] ⚠️ Receiver output: {out[:150]}", node["name"]
                )

    time.sleep(3)

    # 7️⃣ Create region with gateway senders attached
    emit_status("\n📦 STEP 5: Creating TestRegion with gateway senders...")
    for node in nodes:
        if node["name"] in connections:
            ssh = connections[node["name"]]
            locator_port = 10336 + node["idx"]

            # Build sender IDs list for this node (all other regions)
            sender_ids = []
            for target_node in nodes:
                if target_node["name"] != node["name"]:
                    sender_region = target_node["region"].replace(" ", "")
                    sender_ids.append(f"To{sender_region}")

            sender_str = ",".join(sender_ids)

            emit_status(
                f"[{node['name']}] Creating region with senders: {sender_str}",
                node["name"],
            )

            cmd = (
                f"gfsh -e 'connect --locator={node['private_ip']}[{locator_port}]' "
                f"-e 'create region --name=TestRegion --type=PARTITION "
                f"--gateway-sender-id={sender_str}'"
            )
            out, err = run_ssh_cmd(ssh, cmd, timeout=60)

            if "created successfully" in out.lower() or "TestRegion" in out:
                emit_status(
                    f"[{node['name']}] ✅ Region created with WAN senders",
                    node["name"],
                    "region_ready",
                )
            else:
                emit_status(
                    f"[{node['name']}] ⚠️ Region output: {out[:150]}", node["name"]
                )

    # Close all SSH connections
    for ssh in connections.values():
        ssh.close()

    emit_status("\n" + "=" * 50)
    emit_status("✅ WAN SETUP COMPLETE!", None, "complete")
    emit_status("=" * 50)

    # Emit completion with node coordinates for drawing connections
    if socketio:
        node_data = []
        for node in nodes:
            coords = REGION_COORDS.get(node.get("region", ""), {"lat": 0, "lng": 0})
            node_data.append(
                {
                    "name": node["name"],
                    "region": node.get("region", ""),
                    "lat": coords["lat"],
                    "lng": coords["lng"],
                }
            )
        socketio.emit("wan_complete", {"nodes": node_data})


# -----------------------------------------------------------------------------
# Node Verification
# -----------------------------------------------------------------------------
def verify_nodes(nodes, user, keyfile, sio=None):
    global socketio
    socketio = sio

    emit_status("🔍 Verifying node connections...")
    results = []

    for node in nodes:
        try:
            emit_status(
                f"[{node['name']}] Testing SSH connection to {node['public_ip']}...",
                node["name"],
                "checking",
            )
            ssh = connect_node(node, user, keyfile)
            priv_ip = get_private_ip(ssh)
            ssh.close()

            if priv_ip:
                emit_status(
                    f"[{node['name']}] ✅ Connection successful (Private IP: {priv_ip})",
                    node["name"],
                    "verified",
                )
                results.append(
                    {"node": node["name"], "status": "success", "private_ip": priv_ip}
                )
            else:
                emit_status(
                    f"[{node['name']}] ⚠️ Connected but could not detect private IP",
                    node["name"],
                    "warning",
                )
                results.append(
                    {
                        "node": node["name"],
                        "status": "warning",
                        "message": "Could not detect private IP",
                    }
                )

        except Exception as e:
            emit_status(
                f"[{node['name']}] ❌ Connection failed: {e}", node["name"], "error"
            )
            results.append({"node": node["name"], "status": "error", "message": str(e)})

    return results


# -----------------------------------------------------------------------------
# WAN Verification
# -----------------------------------------------------------------------------
def verify_wan_setup(nodes, user, keyfile):
    global socketio

    emit_status("\n🔍 Starting WAN Verification...")
    emit_status("=" * 50)

    verification_results = {"overall": True, "tests": []}

    connections = {}
    rest_api_working = {}

    # 1️⃣ Test SSH connectivity
    emit_status("\n📡 TEST 1: SSH Connectivity")
    for idx, node in enumerate(nodes):
        try:
            emit_status(f"[{node['name']}] Testing SSH connection...", node["name"])
            ssh = connect_node(node, user, keyfile)
            priv_ip = get_private_ip(ssh)

            if priv_ip:
                node["private_ip"] = priv_ip
                node["idx"] = idx
                node["dsid"] = idx + 1
                connections[node["name"]] = ssh
                emit_status(
                    f"[{node['name']}] ✅ SSH connection successful", node["name"]
                )
                verification_results["tests"].append(
                    {"test": f"SSH Connection - {node['name']}", "status": "PASS"}
                )
            else:
                emit_status(
                    f"[{node['name']}] ❌ Could not determine private IP", node["name"]
                )
                verification_results["overall"] = False
                verification_results["tests"].append(
                    {
                        "test": f"SSH Connection - {node['name']}",
                        "status": "FAIL",
                        "error": "Could not determine private IP",
                    }
                )
        except Exception as e:
            emit_status(f"[{node['name']}] ❌ SSH connection failed: {e}", node["name"])
            verification_results["overall"] = False
            verification_results["tests"].append(
                {
                    "test": f"SSH Connection - {node['name']}",
                    "status": "FAIL",
                    "error": str(e),
                }
            )

    # 2️⃣ Check GemFire processes
    emit_status("\n🖥️  TEST 2: GemFire Process Status")
    for node in nodes:
        if node["name"] in connections:
            ssh = connections[node["name"]]

            # Check for locator
            out, _ = run_ssh_cmd(ssh, "ps aux | grep LocatorLauncher | grep -v grep")
            if out:
                emit_status(f"[{node['name']}] ✅ Locator is running", node["name"])
            else:
                emit_status(f"[{node['name']}] ⚠️ Locator not detected", node["name"])
                verification_results["overall"] = False

            # Check for server
            out, _ = run_ssh_cmd(ssh, "ps aux | grep ServerLauncher | grep -v grep")
            if out:
                emit_status(f"[{node['name']}] ✅ Server is running", node["name"])
            else:
                emit_status(f"[{node['name']}] ⚠️ Server not detected", node["name"])
                verification_results["overall"] = False

    # 3️⃣ Test REST API
    emit_status("\n🌐 TEST 3: REST API Connectivity")
    for idx, node in enumerate(nodes):
        rest_port = 8080 + idx
        rest_url = f"http://{node['public_ip']}:{rest_port}/geode/v1"

        try:
            emit_status(
                f"[{node['name']}] Testing REST API at {rest_url}...", node["name"]
            )
            response = requests.get(f"{rest_url}/TestRegion", timeout=5)

            if response.status_code == 200:
                emit_status(f"[{node['name']}] ✅ REST API is responding", node["name"])
                rest_api_working[node["name"]] = rest_url
                verification_results["tests"].append(
                    {"test": f"REST API - {node['name']}", "status": "PASS"}
                )
            else:
                emit_status(
                    f"[{node['name']}] ⚠️ REST API returned HTTP {response.status_code}",
                    node["name"],
                )
                verification_results["overall"] = False
        except Exception as e:
            emit_status(f"[{node['name']}] ❌ REST API test failed: {e}", node["name"])
            verification_results["overall"] = False

    # 4️⃣ Test WAN replication
    emit_status("\n🔄 TEST 4: WAN Replication")
    if len(rest_api_working) >= 2:
        try:
            # Write data to first node
            first_node = nodes[0]
            first_rest_url = rest_api_working.get(first_node["name"])

            if first_rest_url:
                test_key = f"wan_test_{int(time.time())}"
                test_value = f"test_data_{int(time.time())}"

                emit_status(
                    f"   Writing test data to {first_node['name']}: {test_key}={test_value}"
                )

                put_response = requests.post(
                    f"{first_rest_url}/TestRegion",
                    json={test_key: test_value},
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )

                if put_response.status_code in [200, 201]:
                    emit_status(f"   ✅ Test data written successfully")

                    # Wait for replication
                    emit_status("   ⏳ Waiting 10 seconds for WAN replication...")
                    time.sleep(10)

                    # Check all other nodes
                    replication_success = True
                    for node in nodes[1:]:
                        node_url = rest_api_working.get(node["name"])
                        if node_url:
                            try:
                                get_response = requests.get(
                                    f"{node_url}/TestRegion", timeout=5
                                )

                                if get_response.status_code == 200:
                                    data = get_response.json()
                                    found = False

                                    if "TestRegion" in data and isinstance(
                                        data["TestRegion"], list
                                    ):
                                        for item in data["TestRegion"]:
                                            if (
                                                test_key in item
                                                and item[test_key] == test_value
                                            ):
                                                found = True
                                                break

                                    if found:
                                        emit_status(
                                            f"   ✅ [{node['name']}] Data replicated successfully!",
                                            node["name"],
                                        )
                                        verification_results["tests"].append(
                                            {
                                                "test": f"WAN Replication to {node['name']}",
                                                "status": "PASS",
                                            }
                                        )
                                    else:
                                        emit_status(
                                            f"   ❌ [{node['name']}] Data not found",
                                            node["name"],
                                        )
                                        replication_success = False
                                        verification_results["overall"] = False
                            except Exception as e:
                                emit_status(
                                    f"   ❌ [{node['name']}] Error: {e}", node["name"]
                                )
                                replication_success = False
                                verification_results["overall"] = False

                    # Cleanup test data
                    emit_status(f"   🧹 Cleaning up test data...")
                    for node in nodes:
                        node_url = rest_api_working.get(node["name"])
                        if node_url:
                            try:
                                requests.delete(
                                    f"{node_url}/TestRegion/{test_key}", timeout=5
                                )
                            except:
                                pass

        except Exception as e:
            emit_status(f"   ❌ Replication test failed: {e}")
            verification_results["overall"] = False

    # Close connections
    for ssh in connections.values():
        ssh.close()

    # Final summary
    emit_status("\n" + "=" * 50)
    if verification_results["overall"]:
        emit_status("🎉 WAN VERIFICATION PASSED!", None, "complete")
    else:
        emit_status("⚠️ WAN VERIFICATION FAILED", None, "error")
    emit_status("=" * 50)

    return verification_results


# -----------------------------------------------------------------------------
# Standalone Cleanup Function
# -----------------------------------------------------------------------------
def destroy_gemfire_objects(nodes, user, keyfile):
    global socketio

    emit_status("🧹 Starting comprehensive GemFire cleanup...")
    emit_status("--------------------------------------------------")

    connections = {}

    for idx, node in enumerate(nodes):
        try:
            ssh = connect_node(node, user, keyfile)
            priv_ip = get_private_ip(ssh)
            if priv_ip:
                node["private_ip"] = priv_ip
            node["idx"] = idx
            connections[node["name"]] = ssh
            emit_status(f"[{node['name']}] ✅ Connected", node["name"])
        except Exception as e:
            emit_status(f"[{node['name']}] ❌ Connection failed: {e}", node["name"])
            continue

    for node in nodes:
        if node["name"] in connections:
            ssh = connections[node["name"]]
            locator_port = 10336 + node.get("idx", 0)
            cleanup_gemfire(ssh, node, locator_port)

    emit_status("✅ Cleanup complete across all nodes", None, "complete")

    for ssh in connections.values():
        ssh.close()


# -----------------------------------------------------------------------------
# Entrypoints
# -----------------------------------------------------------------------------
def start_wan_setup(nodes, user, keyfile, sio=None):
    global socketio
    socketio = sio
    thread = threading.Thread(target=setup_wan_demo, args=(nodes, user, keyfile))
    thread.start()
    return "WAN setup started..."


def start_cleanup(nodes, user, keyfile, sio=None):
    global socketio
    socketio = sio
    thread = threading.Thread(
        target=destroy_gemfire_objects, args=(nodes, user, keyfile)
    )
    thread.start()
    return "Cleanup started..."


def start_verification(nodes, user, keyfile, sio=None):
    global socketio
    socketio = sio
    thread = threading.Thread(target=verify_wan_setup, args=(nodes, user, keyfile))
    thread.start()
    return "Verification started..."
