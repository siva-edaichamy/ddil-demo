"""
Utility script for managing a GemFire WAN cluster.

This module provides convenience functions (and an optional CLI) to:
  * Gracefully shut down all locators and servers in the WAN cluster
  * Forcefully terminate any lingering GemFire processes (optional)
  * Restart the cluster, including WAN gateway configuration and region creation

It reuses the SSH helpers defined in ``app.utils.gemfire_ssh`` so the
shutdown/restart workflow stays consistent with the Flask dashboards.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

# Ensure project root is on sys.path when invoked directly (e.g. python app/utils/wan_cluster_control.py)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

try:
    from app.config import REGION_NAME as DEFAULT_REGION_NAME  # type: ignore
except Exception:  # pragma: no cover - fallback for direct execution
    DEFAULT_REGION_NAME = "TestRegion"

from app.utils.gemfire_ssh import (  # noqa: E402
    cleanup_gemfire,
    connect_node,
    fix_hostname_resolution,
    get_private_ip,
    run_ssh_cmd,
)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

BASE_PATH = "/home/ec2-user/data/ddl-demo"
LOCATOR_PATH = f"{BASE_PATH}/locator"
SERVER_PATH = f"{BASE_PATH}/server"

LOCATOR_BASE_PORT = 10336
SERVER_BASE_PORT = 40404
REST_BASE_PORT = 8080
RECEIVER_BASE_PORT = 55221
JMX_BASE_PORT = 10931

DEFAULT_SESSION_PATH = PROJECT_ROOT / "config" / "last_session.json"


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _log(message: str) -> None:
    """Emit a timestamped log line."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


def _sanitize_name(name: str) -> str:
    """Convert a node name to a safe identifier for gfsh."""
    return name.replace(" ", "_").replace("-", "_")


def _load_session(
    session_source: str | Path | Dict,
    ssh_user: str | None = None,
    ssh_key: str | None = None,
) -> Dict:
    """
    Load a session definition from a JSON file or dict.

    The session format matches ``DEFAULT_SESSION`` in ``control_dashboard.py``:
    {
        "ssh_user": "...",
        "ssh_key": "...",
        "nodes": [
            {"name": "...", "public_ip": "...", "region": "..."},
            ...
        ]
    }
    """

    if isinstance(session_source, (str, Path)):
        session_path = Path(session_source).expanduser().resolve()
        if not session_path.exists():
            raise FileNotFoundError(f"Session file not found: {session_path}")
        with session_path.open("r", encoding="utf-8") as fh:
            session = json.load(fh)
    elif isinstance(session_source, Dict):
        session = dict(session_source)
    else:
        raise TypeError("session_source must be a path or a dict")

    if ssh_user:
        session["ssh_user"] = ssh_user
    if ssh_key:
        session["ssh_key"] = ssh_key

    required_keys = {"ssh_user", "ssh_key", "nodes"}
    if not required_keys.issubset(session):
        missing = ", ".join(sorted(required_keys - set(session)))
        raise KeyError(f"Session missing required keys: {missing}")

    if not session["nodes"]:
        raise ValueError("Session does not contain any nodes")

    return session


def _prepare_nodes(
    session: Dict,
    require_private_ip: bool,
    strict: bool,
) -> Tuple[List[Dict], Dict[str, object], Dict[str, str]]:
    """
    Connect to nodes, enrich metadata, and optionally enforce private IP discovery.

    Returns (nodes, connections, failures):
      * nodes: list of node dicts (mutated copies) with idx/dsid/private_ip
      * connections: mapping node_name -> SSHClient
      * failures: mapping node_name -> error message
    """

    nodes: List[Dict] = []
    for idx, node_cfg in enumerate(session["nodes"]):
        node = dict(node_cfg)
        node["idx"] = idx
        node["dsid"] = idx + 1
        nodes.append(node)

    user, keyfile = session["ssh_user"], session["ssh_key"]
    connections: Dict[str, object] = {}
    failures: Dict[str, str] = {}

    for node in nodes:
        try:
            _log(f"[{node['name']}] Connecting via SSH ({node['public_ip']})...")
            ssh = connect_node(node, user, keyfile)
            priv_ip = get_private_ip(ssh)

            if require_private_ip and not priv_ip:
                raise RuntimeError("Unable to determine private IP address")

            node["private_ip"] = priv_ip or node["public_ip"]
            node["private_ip_detected"] = bool(priv_ip)
            connections[node["name"]] = ssh

            label = "private" if priv_ip else "public"
            _log(
                f"[{node['name']}] Connected (using {label} IP: {node['private_ip']})"
            )
        except Exception as exc:
            failures[node["name"]] = str(exc)
            _log(f"[{node['name']}] ❌ Connection failed: {exc}")

    if strict and failures:
        for ssh in connections.values():
            try:
                ssh.close()
            except Exception:
                pass
        error_nodes = ", ".join(failures.keys())
        raise RuntimeError(f"Unable to connect to required nodes: {error_nodes}")

    return nodes, connections, failures


def _close_connections(connections: Iterable[object]) -> None:
    for ssh in connections:
        try:
            ssh.close()
        except Exception:
            pass


def _force_kill_gemfire(ssh) -> None:
    """Forcefully terminate lingering GemFire processes."""
    commands = [
        "pkill -9 -f 'LocatorLauncher' || true",
        "pkill -9 -f 'ServerLauncher' || true",
        "pkill -9 -f 'gemfire' || true",
        "pkill -9 -f 'gfsh' || true",
    ]
    for cmd in commands:
        run_ssh_cmd(ssh, cmd, timeout=30)


def _stop_server(ssh, node: Dict) -> None:
    locator_port = LOCATOR_BASE_PORT + node["idx"]
    safe_name = _sanitize_name(node["name"])
    cmd = (
        f"gfsh -e \"connect --locator={node['private_ip']}[{locator_port}]\" "
        f"-e \"stop server --name={safe_name}_server\""
    )
    out, err = run_ssh_cmd(ssh, cmd, timeout=90)
    if err:
        _log(f"[{node['name']}] stop server stderr: {err}")
    _log(f"[{node['name']}] stop server output: {out}")


def _stop_locator(ssh, node: Dict) -> None:
    locator_port = LOCATOR_BASE_PORT + node["idx"]
    safe_name = _sanitize_name(node["name"])
    cmd = (
        f"gfsh -e \"connect --locator={node['private_ip']}[{locator_port}]\" "
        f"-e \"stop locator --name={safe_name}_locator\""
    )
    out, err = run_ssh_cmd(ssh, cmd, timeout=90)
    if err:
        _log(f"[{node['name']}] stop locator stderr: {err}")
    _log(f"[{node['name']}] stop locator output: {out}")


def _start_locator(ssh, node: Dict, all_nodes: List[Dict]) -> None:
    safe_name = _sanitize_name(node["name"])
    locator_port = LOCATOR_BASE_PORT + node["idx"]
    http_port = REST_BASE_PORT + node["idx"]
    jmx_port = JMX_BASE_PORT + node["idx"]

    remote_locators = [
        f"{other['private_ip']}[{LOCATOR_BASE_PORT + other['idx']}]"
        for other in all_nodes
        if other["name"] != node["name"]
    ]

    remote_flag = (
        f"--J=-Dgemfire.remote-locators={','.join(remote_locators)} " if remote_locators else ""
    )

    cmd = (
        "gfsh -e \"start locator "
        f"--name={safe_name}_locator "
        f"--port={locator_port} "
        f"--dir={LOCATOR_PATH} "
        f"--bind-address={node['private_ip']} "
        f"--http-service-port={http_port} "
        f"--J=-Dgemfire.distributed-system-id={node['dsid']} "
        f"{remote_flag}"
        f"--J=-Dgemfire.jmx-manager-port={jmx_port}\""
    )
    out, err = run_ssh_cmd(ssh, cmd.strip(), timeout=120)
    if err:
        _log(f"[{node['name']}] start locator stderr: {err}")
    _log(f"[{node['name']}] start locator output: {out}")


def _start_server(ssh, node: Dict, all_nodes: List[Dict]) -> None:
    safe_name = _sanitize_name(node["name"])
    locator_port = LOCATOR_BASE_PORT + node["idx"]
    server_port = SERVER_BASE_PORT + node["idx"]
    rest_port = REST_BASE_PORT + node["idx"]

    remote_locators = [
        f"{other['private_ip']}[{LOCATOR_BASE_PORT + other['idx']}]"
        for other in all_nodes
        if other["name"] != node["name"]
    ]
    remote_flag = (
        f"--J=-Dgemfire.remote-locators={','.join(remote_locators)} " if remote_locators else ""
    )

    cmd = (
        "gfsh -e \"start server "
        f"--name={safe_name}_server "
        f"--dir={SERVER_PATH} "
        f"--bind-address={node['private_ip']} "
        f"--server-port={server_port} "
        f"--locators={node['private_ip']}[{locator_port}] "
        f"--J=-Dgemfire.distributed-system-id={node['dsid']} "
        f"{remote_flag}"
        f"--start-rest-api=true "
        f"--http-service-port={rest_port} "
        f"--http-service-bind-address={node['private_ip']}\""
    )
    out, err = run_ssh_cmd(ssh, cmd.strip(), timeout=150)
    if err:
        _log(f"[{node['name']}] start server stderr: {err}")
    _log(f"[{node['name']}] start server output: {out}")


def _create_gateway_senders(ssh, node: Dict, all_nodes: List[Dict]) -> None:
    locator_port = LOCATOR_BASE_PORT + node["idx"]

    for target in all_nodes:
        if target["name"] == node["name"]:
            continue

        sender_region = target["region"].replace(" ", "")
        sender_id = f"To{sender_region}"
        cmd = (
            f"gfsh -e \"connect --locator={node['private_ip']}[{locator_port}]\" "
            f"-e \"create gateway-sender --id={sender_id} "
            f"--parallel=true "
            f"--remote-distributed-system-id={target['dsid']}\""
        )
        out, err = run_ssh_cmd(ssh, cmd, timeout=90)
        if err:
            _log(f"[{node['name']}] create gateway-sender ({sender_id}) stderr: {err}")
        _log(
            f"[{node['name']}] create gateway-sender ({sender_id}) output: {out}"
        )


def _create_gateway_receiver(ssh, node: Dict) -> None:
    locator_port = LOCATOR_BASE_PORT + node["idx"]
    start_port = RECEIVER_BASE_PORT + node["idx"]
    end_port = start_port + 1
    cmd = (
        f"gfsh -e \"connect --locator={node['private_ip']}[{locator_port}]\" "
        f"-e \"create gateway-receiver "
        f"--start-port={start_port} "
        f"--end-port={end_port} "
        f"--bind-address={node['private_ip']}\""
    )
    out, err = run_ssh_cmd(ssh, cmd, timeout=90)
    if err:
        _log(f"[{node['name']}] create gateway-receiver stderr: {err}")
    _log(f"[{node['name']}] create gateway-receiver output: {out}")


def _create_region(ssh, node: Dict, all_nodes: List[Dict], region_name: str) -> None:
    locator_port = LOCATOR_BASE_PORT + node["idx"]
    sender_ids = [
        f"To{other['region'].replace(' ', '')}"
        for other in all_nodes
        if other["name"] != node["name"]
    ]
    sender_flag = (
        f"--gateway-sender-id={','.join(sender_ids)} " if sender_ids else ""
    )

    cmd = (
        f"gfsh -e \"connect --locator={node['private_ip']}[{locator_port}]\" "
        f"-e \"create region "
        f"--name={region_name} "
        f"--type=PARTITION "
        f"{sender_flag}\""
    )
    out, err = run_ssh_cmd(ssh, cmd.strip(), timeout=90)
    if err:
        _log(f"[{node['name']}] create region stderr: {err}")
    _log(f"[{node['name']}] create region output: {out}")


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

def shutdown_cluster(
    session_source: str | Path | Dict = DEFAULT_SESSION_PATH,
    *,
    ssh_user: str | None = None,
    ssh_key: str | None = None,
    cleanup: bool = False,
    force_kill: bool = True,
) -> Dict:
    """
    Shut down the GemFire WAN cluster.

    Returns a dict summarizing the outcome per node.
    """

    session = _load_session(session_source, ssh_user, ssh_key)
    nodes, connections, failures = _prepare_nodes(
        session, require_private_ip=False, strict=False
    )

    report = {"nodes": {}, "failures": failures}

    try:
        for node in nodes:
            ssh = connections.get(node["name"])
            node_report = {"stopped": False, "error": None}

            if not ssh:
                node_report["error"] = failures.get(node["name"], "Connection failed")
                report["nodes"][node["name"]] = node_report
                continue

            try:
                _log(f"[{node['name']}] Stopping GemFire server...")
                _stop_server(ssh, node)

                _log(f"[{node['name']}] Stopping GemFire locator...")
                _stop_locator(ssh, node)

                if cleanup:
                    _log(f"[{node['name']}] Running cleanup_gemfire...")
                    cleanup_gemfire(ssh, node)
                elif force_kill:
                    _log(f"[{node['name']}] Force killing lingering GemFire processes...")
                    _force_kill_gemfire(ssh)

                node_report["stopped"] = True
            except Exception as exc:
                node_report["error"] = str(exc)
                _log(f"[{node['name']}] ❌ Shutdown error: {exc}")

            report["nodes"][node["name"]] = node_report
    finally:
        _close_connections(connections.values())

    return report


def start_cluster(
    session_source: str | Path | Dict = DEFAULT_SESSION_PATH,
    *,
    ssh_user: str | None = None,
    ssh_key: str | None = None,
    region_name: str = DEFAULT_REGION_NAME,
    setup_wan_components: bool = True,
    wait_between_steps: int = 5,
) -> Dict:
    """
    Start GemFire locators, servers, and WAN components.

    Returns a dict summarizing start results per node.
    """

    session = _load_session(session_source, ssh_user, ssh_key)
    nodes, connections, _ = _prepare_nodes(
        session, require_private_ip=True, strict=True
    )

    report: Dict[str, Dict[str, bool | str | None]] = {}

    try:
        _log("Fixing hostname resolution on all nodes...")
        for node in nodes:
            ssh = connections[node["name"]]
            try:
                fix_hostname_resolution(ssh, node)
            except Exception as exc:
                _log(f"[{node['name']}] ⚠️ Unable to update /etc/hosts: {exc}")

        _log("Starting locators across all nodes...")
        for node in nodes:
            ssh = connections[node["name"]]
            _start_locator(ssh, node, nodes)
        _log(f"Waiting {wait_between_steps}s for locators to stabilize...")
        time.sleep(wait_between_steps)

        _log("Starting servers across all nodes...")
        for node in nodes:
            ssh = connections[node["name"]]
            _start_server(ssh, node, nodes)
        _log(f"Waiting {wait_between_steps}s for servers to stabilize...")
        time.sleep(wait_between_steps)

        if setup_wan_components and len(nodes) > 1:
            _log("Creating gateway senders on all nodes...")
            for node in nodes:
                ssh = connections[node["name"]]
                _create_gateway_senders(ssh, node, nodes)
            _log("Creating gateway receivers on all nodes...")
            for node in nodes:
                ssh = connections[node["name"]]
                _create_gateway_receiver(ssh, node)
            _log("Creating regions with WAN senders...")
            for node in nodes:
                ssh = connections[node["name"]]
                _create_region(ssh, node, nodes, region_name)
        elif setup_wan_components:
            _log("Only one node detected; skipping WAN sender/receiver creation.")

        for node in nodes:
            report[node["name"]] = {"started": True, "error": None}
    except Exception as exc:
        _log(f"❌ Cluster startup failed: {exc}")
        for node in nodes:
            if node["name"] not in report:
                report[node["name"]] = {"started": False, "error": str(exc)}
        raise
    finally:
        _close_connections(connections.values())

    return report


def restart_cluster(
    session_source: str | Path | Dict = DEFAULT_SESSION_PATH,
    *,
    ssh_user: str | None = None,
    ssh_key: str | None = None,
    region_name: str = DEFAULT_REGION_NAME,
    cleanup: bool = False,
    force_kill: bool = True,
    setup_wan_components: bool = True,
    wait_between_steps: int = 5,
) -> Dict:
    """Convenience helper that performs a shutdown followed by a start."""

    _log("=== GemFire WAN cluster restart ===")
    shutdown_report = shutdown_cluster(
        session_source,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        cleanup=cleanup,
        force_kill=force_kill,
    )

    _log("Shutdown complete. Waiting before restart...")
    time.sleep(wait_between_steps)

    start_report = start_cluster(
        session_source,
        ssh_user=ssh_user,
        ssh_key=ssh_key,
        region_name=region_name,
        setup_wan_components=setup_wan_components,
        wait_between_steps=wait_between_steps,
    )

    return {"shutdown": shutdown_report, "start": start_report}


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage a GemFire WAN cluster (shutdown/start/restart)."
    )
    parser.add_argument(
        "action", choices=["shutdown", "start", "restart"], help="Operation to perform"
    )
    parser.add_argument(
        "--session-file",
        default=str(DEFAULT_SESSION_PATH),
        help="Path to a JSON session definition (default: config/last_session.json)",
    )
    parser.add_argument("--ssh-user", help="Override SSH user from the session file")
    parser.add_argument("--ssh-key", help="Override SSH key path from the session file")
    parser.add_argument(
        "--region",
        default=DEFAULT_REGION_NAME,
        help=f"Region name to create on restart (default: {DEFAULT_REGION_NAME})",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove GemFire directories/logs during shutdown (data destructive).",
    )
    parser.add_argument(
        "--no-force-kill",
        action="store_true",
        help="Disable forceful pkill of GemFire processes during shutdown.",
    )
    parser.add_argument(
        "--minimal-start",
        action="store_true",
        help="Skip WAN sender/receiver/region creation during start.",
    )
    parser.add_argument(
        "--wait-seconds",
        type=int,
        default=5,
        help="Delay (seconds) between major steps.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])

    try:
        if args.action == "shutdown":
            shutdown_cluster(
                args.session_file,
                ssh_user=args.ssh_user,
                ssh_key=args.ssh_key,
                cleanup=args.cleanup,
                force_kill=not args.no_force_kill,
            )
        elif args.action == "start":
            start_cluster(
                args.session_file,
                ssh_user=args.ssh_user,
                ssh_key=args.ssh_key,
                region_name=args.region,
                setup_wan_components=not args.minimal_start,
                wait_between_steps=args.wait_seconds,
            )
        else:  # restart
            restart_cluster(
                args.session_file,
                ssh_user=args.ssh_user,
                ssh_key=args.ssh_key,
                region_name=args.region,
                cleanup=args.cleanup,
                force_kill=not args.no_force_kill,
                setup_wan_components=not args.minimal_start,
                wait_between_steps=args.wait_seconds,
            )
    except Exception as exc:
        _log(f"Operation failed: {exc}")
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


