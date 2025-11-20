# GemFire WAN Demo Dashboard

A web-based orchestration tool for managing Apache Geode/GemFire WAN (Wide Area Network) replication across multiple clusters.

## Overview

This project provides two dashboards:

1. **Control Dashboard** (Port 5004): Cluster lifecycle management
   - Automated cluster setup and configuration
   - WAN replication setup and verification
   - Real-time status monitoring
   - Data cleanup operations

2. **Demo Dashboard** (Port 5002): Interactive data visualization
   - Real-time data visualization across nodes
   - Add/view data via REST API
   - Visual representation of WAN replication
   - Network simulation features

## Prerequisites

- Python 3.9+
- SSH access to GemFire nodes with key-based authentication
- Apache Geode/GemFire installed on target nodes (version 10.1.2+)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ddil-demo
```

2. Create virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure session:
```bash
cp config/last_session.json.example config/last_session.json
# Edit config/last_session.json with your node details
```

## Configuration

Edit `config/last_session.json`:

```json
{
  "ssh_user": "ec2-user",
  "ssh_key": "/path/to/your/key.pem",
  "nodes": [
    {
      "name": "C2",
      "public_ip": "your-node-ip-1",
      "region": "US East"
    },
    {
      "name": "Aircraft",
      "public_ip": "your-node-ip-2",
      "region": "US West"
    },
    {
      "name": "Submarine",
      "public_ip": "your-node-ip-3",
      "region": "EU"
    }
  ]
}
```

Ensure SSH key has proper permissions:
```bash
chmod 400 /path/to/your/key.pem
```

## Usage

### Start Both Dashboards

```bash
python startup.py --mode all
```

This starts:
- Control Dashboard at http://localhost:5004
- Demo Dashboard at http://localhost:5002

### Start Dashboards Separately

**Control Dashboard:**
```bash
python app/control_dashboard.py
```
Access at: http://localhost:5004

**Demo Dashboard:**
```bash
python app/demo_dashboard.py
```
Access at: http://localhost:5002

### Control Dashboard Workflow

1. Configure nodes in the web UI (or use `config/last_session.json`)
2. Click "Verify Nodes" to test SSH connectivity
3. Click "Setup Cluster (WAN)" to begin automated setup
4. Monitor real-time progress updates
5. Use "Cleanup Data" to remove all data when needed

### Demo Dashboard Workflow

1. View data across nodes in real-time
2. Add data using input fields
3. Observe WAN replication in action
4. Simulate network issues using "Dive" and "Network Issues" buttons

## Project Structure

```
ddil-demo/
├── app/
│   ├── control_dashboard.py      # Control dashboard (port 5004)
│   ├── demo_dashboard.py         # Demo visualization (port 5002)
│   ├── templates/                # HTML templates
│   └── utils/                    # Utility modules
├── config/
│   ├── last_session.json         # Session config (gitignored)
│   └── last_session.json.example # Example config
├── startup.py                     # Unified launcher
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

## Security

⚠️ **Important:**
- Never commit `config/last_session.json` or `user_settings.json` - these contain sensitive information
- SSH keys and credentials are excluded via `.gitignore`
- Restrict access to dashboard ports in production
- Use HTTPS in production environments
