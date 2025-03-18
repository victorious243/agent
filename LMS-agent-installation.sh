#!/bin/bash

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Define variables
SCRIPT_DIR=$(dirname "$0")
PYTHON_SCRIPT="$SCRIPT_DIR/lms_agent.py"
INSTALL_DIR="/opt/lms-agent"
DATA_DIR="/var/lib/lms-agent"
SERVICE_FILE="/etc/systemd/system/LMS-agent.service"

# Check if the Python script exists in the current directory
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Error: lms_agent.py not found in the current directory."
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt-get install -y python3 python3-pip iptables
pip3 install requests pandas scikit-learn joblib
apt install python3.12-venv -y
python3 -m venv .venv
source .venv/bin/activate
pip install requests
pip install scikit-learn


# Stop the service if it's already running
echo "Stopping LMS-agent service if running..."
systemctl stop LMS-agent || true

# Set up directories
echo "Setting up directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"
chown root:root "$DATA_DIR"

# Copy the Python script to the installation directory
echo "Copying the Python script..."
cp "$PYTHON_SCRIPT" "$INSTALL_DIR/lms_agent.py"

# Update the Python script with absolute paths and remove sudo from block_ip
# echo "Configuring the Python script..."
# sed -i 's|MACHINE_ID_FILE = "./machine_id.txt"|MACHINE_ID_FILE = "'"$DATA_DIR"'/machine_id.txt"|' "$INSTALL_DIR/lms_agent.py"
# sed -i 's|MODEL_FILE = "./threat_detection_model.pkl"|MODEL_FILE = "'"$DATA_DIR"'/threat_detection_model.pkl"|' "$INSTALL_DIR/lms_agent.py"
# sed -i 's|subprocess.run(\["sudo", "iptables"|subprocess.run(\["iptables"|' "$INSTALL_DIR/lms_agent.py"

# Insert signal handler after "import joblib"
echo "Adding signal handler for graceful shutdown..."
sed -i '/import joblib/a import signal\nimport sys\n\ndef signal_handler(sig, frame):\n    print("Received SIGTERM, shutting down...")\n    send_status("offline")\n    sys.exit(0)\n\nsignal.signal(signal.SIGTERM, signal_handler)' "$INSTALL_DIR/lms_agent.py"

# Create the systemd service file
echo "Creating systemd service file..."
cat << EOF > "$SERVICE_FILE"
[Unit]
Description=LMS Agent Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/lms_agent.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd daemon
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Enable the service to start at boot
echo "Enabling the service..."
systemctl enable LMS-agent

# Start the service
echo "Starting the service..."
systemctl start LMS-agent

# Provide feedback
echo "Service setup complete."
echo "You can check the status with: sudo systemctl status LMS-agent"
echo "View logs with: sudo journalctl -u LMS-agent -f"