"""
startup.py
-----------
Entrypoint for the GemFire DDIL demo environment.

Usage:
    python startup.py                    # Launch control dashboard only (port 5004)
                                         # Then use "Open Dashboard" button to start demo dashboard
    
    python startup.py --mode prepare    # Same as above (control dashboard only)
    
    python startup.py --mode all        # Launch both dashboards (demo dashboard won't be manageable via UI)
                                         # Note: If using --mode all, Stop Demo button won't work
"""

import argparse
import subprocess
import threading
import time
import sys
import os


def run_control_dashboard():
    """Runs the control dashboard on port 5004."""
    print("🚀 Starting GemFire Control Dashboard on http://localhost:5004")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    subprocess.run(
        [sys.executable, "app/control_dashboard.py"], env=env, cwd=os.getcwd()
    )


def run_demo_dashboard():
    """Runs the demo dashboard on port 5002."""
    print("🌍 Starting GemFire Demo Dashboard on http://localhost:5002")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    subprocess.run([sys.executable, "app/demo_dashboard.py"], env=env, cwd=os.getcwd())


def main():
    parser = argparse.ArgumentParser(description="GemFire DDIL Demo Launcher")
    parser.add_argument(
        "--mode",
        choices=["prepare", "all"],
        default="prepare",
        help="Run control dashboard only or both control and demo dashboards",
    )
    args = parser.parse_args()

    if args.mode == "prepare":
        # Only start control dashboard - use "Open Dashboard" button to start demo dashboard
        print("\n" + "=" * 60)
        print("📋 Control Dashboard Only Mode")
        print("=" * 60)
        print("Use the 'Open Dashboard' button in the UI to start the demo dashboard.")
        print("This allows the control dashboard to manage the demo dashboard lifecycle.")
        print("=" * 60 + "\n")
        run_control_dashboard()
    elif args.mode == "all":
        # Start both dashboards (demo dashboard won't be manageable via UI buttons)
        print("\n" + "=" * 60)
        print("⚠️  Both Dashboards Mode")
        print("=" * 60)
        print("Note: Demo dashboard started via startup.py cannot be stopped")
        print("      using the 'Stop Demo' button. Use Ctrl+C to stop both.")
        print("=" * 60 + "\n")
        # Start control dashboard in background thread
        t1 = threading.Thread(target=run_control_dashboard, daemon=True)
        t1.start()

        # Wait a bit for control dashboard to start
        time.sleep(3)

        # Start demo dashboard in main thread
        run_demo_dashboard()


if __name__ == "__main__":
    main()
