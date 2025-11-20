"""
app/utils/settings_manager.py
-----------------------------
Handles reading and writing of user settings.
"""

import json
import os

SETTINGS_FILE = "user_settings.json"


def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(data):
    try:
        with open(SETTINGS_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"[WARN] Failed to save settings: {e}")
