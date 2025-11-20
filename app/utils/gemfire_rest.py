"""
app/utils/gemfire_rest.py
-------------------------
REST API wrappers for interacting with GemFire.
All requests assume that REST API is running on port 7070.
"""

import requests
from app import config


def check_health(node_ip):
    """Check if the REST API is reachable."""
    url = f"http://{node_ip}:{config.REST_PORT}/gemfire/v1/members"
    try:
        resp = requests.get(url, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def list_regions(node_ip):
    """Return a list of available regions on this node."""
    url = f"http://{node_ip}:{config.REST_PORT}/gemfire/v1/regions"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("regions", [])
    except Exception:
        pass
    return []


def create_region(node_ip, region_name):
    """Create a replicate region if it doesn't exist."""
    url = f"http://{node_ip}:{config.REST_PORT}/gemfire/v1/regions"
    payload = {"name": region_name, "type": "REPLICATE"}
    try:
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code in (200, 201, 409)  # 409 = already exists
    except Exception:
        return False


def put_entry(node_ip, region, key, value):
    """Insert or update a key/value pair."""
    url = (
        f"http://{node_ip}:{config.REST_PORT}/gemfire/v1/regions/{region}/entries/{key}"
    )
    try:
        resp = requests.post(url, json=value, timeout=5)
        return resp.status_code in (200, 201)
    except Exception:
        return False


def get_entry(node_ip, region, key):
    """Retrieve a key from the region."""
    url = (
        f"http://{node_ip}:{config.REST_PORT}/gemfire/v1/regions/{region}/entries/{key}"
    )
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None
