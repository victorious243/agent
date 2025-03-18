import re
import time
import socket
import requests
import uuid
import os
import subprocess
import threading
from collections import Counter
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import json
import joblib
from datetime import datetime

# ====================
# CONSTANTS & SETTINGS
# ====================
LOG_FILES = [
    {"path": "/var/log/auth.log", "type": "auth"},
    {"path": "/var/log/syslog", "type": "syslog"},
    {"path": "/var/log/kern.log", "type": "kern"},
    {"path": "/var/log/ufw.log", "type": "ufw"},
]
MACHINE_ID_FILE = "./machine_id.txt"
SERVER_URL = "http://172.20.10.4:3000/api/status"
LOG_SERVER_URL = "http://172.20.10.4:3000/api/logs"
THRESHOLD = 5
TIME_WINDOW = 60
MODEL_FILE = "./threat_detection_model.pkl"
FEATURES = [
    'ssh_failed_1min', 'ssh_failed_5min', 'ssh_failed_10min',
    'sudo_failed_1min', 'sudo_failed_5min', 'sudo_failed_10min',
    'root_logins_1hr', 'root_logins_24hr',
    'port_attempts_1min', 'port_attempts_5min', 'port_diversity',
    'time_of_day'
]

# ====================
# HELPER FUNCTIONS
# ====================

def get_machine_id():
    if os.path.exists(MACHINE_ID_FILE):
        with open(MACHINE_ID_FILE, "r") as file:
            return file.read().strip()
    machine_id = str(uuid.uuid4())
    with open(MACHINE_ID_FILE, "w") as file:
        file.write(machine_id)
    return machine_id

MACHINE_ID = get_machine_id()

def get_agent_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def send_status(status, alert_message=None):
    payload = {
        "machine_id": MACHINE_ID,
        "status": status,
        "hostname": socket.gethostname(),
        "ip_address": get_agent_ip(),
        "alert": alert_message
    }
    try:
        response = requests.post(SERVER_URL, json=payload, timeout=45)
        print(f"✅ Status sent: {status} | Response: {response.status_code}")
    except requests.RequestException as e:
        print(f"❌ Failed to send status update: {e}")

def parse_log_line(line, log_type):
    pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+[0-9:]+)\s+(\S+)\s+(.*?)$'
    match = re.match(pattern, line)
    if match:
        timestamp, hostname, message = match.groups()
        process_pid_match = re.match(r'(\S+?)(?:\[(\d+)\])?:\s+(.*)', message)
        if process_pid_match:
            process, pid, message_content = process_pid_match.groups()
        else:
            process, pid, message_content = None, None, message
        return {
            "log_type": log_type,
            "timestamp": timestamp,
            "hostname": hostname,
            "process": process,
            "pid": pid,
            "message": message_content,
            "ip_address": get_agent_ip(),
            "source_ip": parse_source_ip(line)
        }
    return {
        "log_type": log_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00", time.gmtime()),
        "hostname": socket.gethostname(),
        "process": None,
        "pid": None,
        "message": line.strip(),
        "ip_address": get_agent_ip(),
        "source_ip": parse_source_ip(line)
    }

def parse_source_ip(line):
    patterns = [
        r'from (\d+\.\d+\.\d+\.\d+)',              # "from 172.16.232.150"
        r'SRC=(\d+\.\d+\.\d+\.\d+)',              # "SRC=172.16.232.150"
        r'rhost=(\d+\.\d+\.\d+\.\d+)',            # "rhost=172.16.232.150"
        r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',  # "Failed password ... from 172.16.232.150"
        r'(\d+\.\d+\.\d+\.\d+)\s+port\s+\d+'      # "172.16.232.150 port 47838"
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)
    return None

def parse_port(line):
    match = re.search(r'DPT=(\d+)', line) or re.search(r'port\s+(\d+)', line)
    return int(match.group(1)) if match else None

def parse_timestamp(timestamp_str):
    try:
        dt = datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%dT%H:%M:%S")
        return dt.timestamp()
    except (ValueError, TypeError):
        return time.time()

def log_alert(message, alert_type="threat", severity="info", details={}):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_entry = {
        "log_type": "threat_detected",  # Changed to distinguish threat logs
        "timestamp": timestamp,
        "hostname": socket.gethostname(),
        "ip_address": get_agent_ip(),
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
        "details": details
    }
    send_log_entries("threat_detected", [log_entry])
    print(f"⚠️ ALERT: {message}")
def block_ip(ip):
    print(f"🔒 Blocking IP {ip}...")
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)
        print(f"✅ IP {ip} blocked successfully.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to block IP {ip}: {e}")

def extract_features(ip, data):
    current_time = time.time()
    features = {}
    ssh_attempts = data.get('ssh_attempts', {1: [], 5: [], 10: []})
    for window in [1, 5, 10]:
        count = sum(1 for t in ssh_attempts.get(window, []) if current_time - t <= window * 60)
        features[f'ssh_failed_{window}min'] = count
        print(f"DEBUG: {ip} ssh_failed_{window}min = {count}")
    sudo_attempts = data.get('sudo_attempts', {1: [], 5: [], 10: []})
    for window in [1, 5, 10]:
        features[f'sudo_failed_{window}min'] = sum(1 for t in sudo_attempts.get(window, []) if current_time - t <= window * 60)
    root_logins = data.get('root_logins', [])
    features['root_logins_1hr'] = sum(1 for t in root_logins if current_time - t <= 3600)
    features['root_logins_24hr'] = sum(1 for t in root_logins if current_time - t <= 86400)
    port_attempts = data.get('port_attempts', {1: [], 5: []})
    for window in [1, 5]:
        features[f'port_attempts_{window}min'] = sum(1 for t in port_attempts.get(window, []) if current_time - t <= window * 60)
    ports = set(data.get('ports', []))
    features['port_diversity'] = len(ports) if ports else 0
    local_time = time.localtime(current_time)
    features['time_of_day'] = local_time.tm_hour * 60 + local_time.tm_min
    return features

def train_model():
    data = []
    labels = {0: "normal", 1: "brute_force", 2: "sudo_failure", 3: "root_anomaly", 4: "port_scan"}

    for log_file in LOG_FILES:
        try:
            with open(log_file["path"], "r") as f:
                lines = f.readlines()
                ssh_attempts = {}
                sudo_attempts = {}
                root_logins = []
                port_attempts = {}
                ports = set()
                for line in lines:
                    log_entry = parse_log_line(line, log_file["type"])
                    ip = log_entry.get("source_ip")
                    if not ip:
                        continue
                    log_time = parse_timestamp(log_entry["timestamp"])
                    if log_file["type"] == "auth":
                        if "Failed password" in line or "Invalid user" in line:
                            if ip not in ssh_attempts:
                                ssh_attempts[ip] = {1: [], 5: [], 10: []}
                            for window in [1, 5, 10]:
                                ssh_attempts[ip][window].append(log_time)
                        elif "sudo:" in line and ("incorrect password" in line or "authentication failure" in line):
                            if ip not in sudo_attempts:
                                sudo_attempts[ip] = {1: [], 5: [], 10: []}
                            for window in [1, 5, 10]:
                                sudo_attempts[ip][window].append(log_time)
                        elif "session opened for user root" in line:
                            root_logins.append(log_time)
                    elif log_file["type"] == "ufw":
                        if ip not in port_attempts:
                            port_attempts[ip] = {1: [], 5: []}
                        for window in [1, 5]:
                            port_attempts[ip][window].append(log_time)
                        port = parse_port(line)
                        if port:
                            ports.add(port)

                for ip in set(list(ssh_attempts.keys()) + list(sudo_attempts.keys()) + list(port_attempts.keys())):
                    features = extract_features(ip, {
                        'ssh_attempts': ssh_attempts.get(ip, {}),
                        'sudo_attempts': sudo_attempts.get(ip, {}),
                        'root_logins': root_logins,
                        'port_attempts': port_attempts.get(ip, {}),
                        'ports': ports
                    })
                    if features['ssh_failed_10min'] > THRESHOLD:
                        label = 1
                    elif features['sudo_failed_10min'] > 3:
                        label = 2
                    elif features['root_logins_1hr'] > 2 and features['time_of_day'] < 360:
                        label = 3
                    elif features['port_attempts_5min'] > 10 and features['port_diversity'] > 5:
                        label = 4
                    else:
                        label = 0
                    data.append(list(features.values()) + [label])

        except FileNotFoundError:
            print(f"❌ Log file not found: {log_file['path']}")
            continue

    if len(data) < 50:
        print("Insufficient real data. Adding simulated data.")
        current_time = time.time()
        for i in range(50):
            ip = f"192.168.1.{i}"
            ssh_attempts = {1: [current_time - j for j in range(i % 10)], 5: [current_time - j for j in range(i % 5)], 10: [current_time - j for j in range(i % 3)]}
            sudo_attempts = {1: [current_time - j for j in range(i % 5)], 5: [], 10: []}
            root_logins = [current_time - j * 3600 for j in range(i % 3)]
            port_attempts = {1: [current_time - j for j in range(i % 15)], 5: [current_time - j for j in range(i % 10)]}
            ports = set(range(i % 10))
            features = extract_features(ip, {
                'ssh_attempts': ssh_attempts,
                'sudo_attempts': sudo_attempts,
                'root_logins': root_logins,
                'port_attempts': port_attempts,
                'ports': ports
            })
            label = i % 5
            data.append(list(features.values()) + [label])

    df = pd.DataFrame(data, columns=FEATURES + ['threat_type'])
    X = df[FEATURES]
    y = df['threat_type']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy}")
    joblib.dump(model, MODEL_FILE)
    print(f"Model saved to {MODEL_FILE}")
    return model

def tail_log_file(log_path, log_type):
    entries = []
    last_send_time = time.time()
    try:
        with open(log_path, "r") as file:
            file.seek(0, 2)
            while True:
                line = file.readline()
                if line:
                    log_entry = parse_log_line(line, log_type)
                    entries.append(log_entry)
                else:
                    time.sleep(0.1)
                current_time = time.time()
                if current_time - last_send_time >= 1.0 and entries:
                    send_log_entries(log_type, entries)
                    entries = []
                    last_send_time = current_time
    except FileNotFoundError:
        print(f"❌ Log file not found: {log_path}")
    except PermissionError:
        print(f"❌ Permission denied for log file: {log_path}")
    except Exception as e:
        print(f"❌ Error tailing log file {log_path}: {e}")

def send_log_entries(log_type, entries):
    payload = {
        "machine_id": MACHINE_ID,
        "log_entries": entries
    }
    try:
        response = requests.post(LOG_SERVER_URL, json=payload, timeout=45)
        print(f"✅ {len(entries)} log entries sent: {response.status_code}")
    except requests.RequestException as e:
        print(f"❌ Failed to send log entries: {e}")

def get_os_info(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return f"Hostname: {hostname}"
    except socket.herror:
        return "OS detection unavailable"

# ====================
# MAIN MONITORING LOOP
# ====================

def monitor_log():
    send_status("online")
    try:
        model = joblib.load(MODEL_FILE)
        print("ML model loaded.")
    except FileNotFoundError:
        print("No trained model found. Training...")
        model = train_model()
        if model is None:
            print("❌ Failed to train model. Running without ML detection.")
            return

    threat_data = {}
    labels = {0: "normal", 1: "brute_force", 2: "sudo_failure", 3: "root_anomaly", 4: "port_scan"}

    for log_file in LOG_FILES:
        try:
            with open(log_file["path"], "r") as file:
                file.seek(0, 2)
                while True:
                    line = file.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    log_entry = parse_log_line(line, log_file["type"])
                    ip = log_entry.get("source_ip")
                    if not ip:
                        print(f"DEBUG: No source_ip found in line: {line.strip()}")
                        continue

                    if ip not in threat_data:
                        threat_data[ip] = {
                            'ssh_attempts': {1: [], 5: [], 10: []},
                            'sudo_attempts': {1: [], 5: [], 10: []},
                            'root_logins': [],
                            'port_attempts': {1: [], 5: []},
                            'ports': set()
                        }

                    log_time = parse_timestamp(log_entry["timestamp"])
                    current_time = time.time()

                    if log_file["type"] == "auth":
                        if "Failed password" in line or "Invalid user" in line:
                            for window in [1, 5, 10]:
                                threat_data[ip]['ssh_attempts'][window].append(log_time)
                        elif "sudo:" in line and ("incorrect password" in line or "authentication failure" in line):
                            for window in [1, 5, 10]:
                                threat_data[ip]['sudo_attempts'][window].append(log_time)
                        elif "session opened for user root" in line:
                            threat_data[ip]['root_logins'].append(log_time)
                    elif log_file["type"] == "ufw":
                        for window in [1, 5]:
                            threat_data[ip]['port_attempts'][window].append(log_time)
                        port = parse_port(line)
                        if port:
                            threat_data[ip]['ports'].add(port)

                    # Clean old entries
                    for window in [1, 5, 10]:
                        threat_data[ip]['ssh_attempts'][window] = [t for t in threat_data[ip]['ssh_attempts'][window] if current_time - t <= window * 60]
                        threat_data[ip]['sudo_attempts'][window] = [t for t in threat_data[ip]['sudo_attempts'][window] if current_time - t <= window * 60]
                    for window in [1, 5]:
                        threat_data[ip]['port_attempts'][window] = [t for t in threat_data[ip]['port_attempts'][window] if current_time - t <= window * 60]
                    threat_data[ip]['root_logins'] = [t for t in threat_data[ip]['root_logins'] if current_time - t <= 86400]

                    features = extract_features(ip, threat_data[ip])
                    df_features = pd.DataFrame([features], columns=FEATURES)
                    prediction = model.predict(df_features)[0]
                    print(f"DEBUG: Prediction for {ip}: {labels[prediction]}")

                    # ML-based detection
                    if prediction != 0:
                        threat_type = labels[prediction]
                        os_info = get_os_info(ip)
                        details = {
                            "ip": ip,
                            "os_info": os_info,
                            "features": features  # Include all extracted features for context
                        }
                        alert_message = f"{threat_type.replace('_', ' ').title()} detected from IP: {ip}, OS: {os_info} (ML)"
                        severity = "dangerous" if threat_type in ["brute_force", "port_scan"] else "warning"
                        log_alert(alert_message, alert_type=threat_type, severity=severity, details=details)
                        send_status("online", alert_message)
                        block_ip(ip)
                        del threat_data[ip]
                    # Rule-based detection
                    elif features['ssh_failed_1min'] > THRESHOLD or len(threat_data[ip]['ssh_attempts'][1]) > THRESHOLD:
                        os_info = get_os_info(ip)
                        details = {
                            "ip": ip,
                            "os_info": os_info,
                            "attempts": len(threat_data[ip]['ssh_attempts'][1])
                        }
                        alert_message = f"Brute Force detected from IP: {ip}, OS: {os_info} (Rule-based: {details['attempts']} attempts in 1 min)"
                        log_alert(alert_message, alert_type="brute_force", severity="dangerous", details=details)
                        send_status("online", alert_message)
                        block_ip(ip)
                        del threat_data[ip]

        except KeyboardInterrupt:
            print("🛑 Stopping monitoring...")
            send_status("offline")
            break
        except Exception as e:
            print(f"❌ Error in {log_file['path']}: {e}")

# ====================
# MAIN ENTRY POINT
# ====================

if __name__ == "__main__":
    print("🔍 Monitoring logs...")
    monitor_threads = []
    for log_file in LOG_FILES:
        thread = threading.Thread(target=tail_log_file, args=(log_file["path"], log_file["type"]))
        thread.daemon = True
        thread.start()
        monitor_threads.append(thread)
    monitor_log()