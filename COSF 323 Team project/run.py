from flask import Flask, render_template, jsonify, request
import threading
from scapy.all import sniff, IP, TCP, UDP
import time
import psutil
import socket
import joblib
import pandas as pd
from collections import defaultdict

app = Flask(__name__)

# Load the trained model
model = joblib.load('trained_model.pkl')

# Global list to store packet logs and notifications
packet_logs = []
notifications = []
capture_thread = None
capture_running = False

# Limit for the number of packet logs
PACKET_LOGS_LIMIT = 100  # Adjust this value as needed

# Global dictionaries to store counts for feature extraction
src_ip_count = defaultdict(int)
dst_ip_count = defaultdict(int)
src_port_count = defaultdict(int)
dst_port_count = defaultdict(int)

def process_packet(packet):
    """Callback function to process each captured packet."""
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        transport_layer = "Unknown"
        if packet.haslayer(TCP):
            transport_layer = "TCP"
        elif packet.haslayer(UDP):
            transport_layer = "UDP"
        
        # Extract features from the packet
        features = extract_features(packet)
        print(f"Extracted features: {features}")  # Debugging statement
        
        # Predict if the packet is malicious or benign
        prediction = model.predict([features])[0]
        print(f"Prediction: {prediction}")  # Debugging statement
        
        log = f"Packet: {ip_layer.src} -> {ip_layer.dst} ({transport_layer}) at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        if prediction == 0:  # 0 indicates a malicious packet
            log += " [WARNING: Malicious Packet Detected]"
            # Inform the user about the detected malicious packet
            inform_user(log)
        else:  # 1 indicates a benign packet
            log += " [INFO: Benign Packet]"
        
        # Add the log to the packet logs list
        packet_logs.append(log)
        # Ensure the packet logs list does not exceed the limit
        if len(packet_logs) > PACKET_LOGS_LIMIT:
            packet_logs.pop(0)
        
        print(log)  # Print to console for debugging

def extract_features(packet):
    """Extract features from the packet for the machine learning model."""
    # Convert the flag to an integer
    flag_value = int(packet[IP].flags)

    # Extract IP addresses and ports
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
    dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport

    # Update global counts
    src_ip_count[src_ip] += 1
    dst_ip_count[dst_ip] += 1
    src_port_count[src_port] += 1
    dst_port_count[dst_port] += 1

    # Calculate additional features
    count = src_ip_count[src_ip]
    same_srv_rate = src_port_count[src_port] / count if count > 0 else 0
    dst_host_srv_count = dst_ip_count[dst_ip]
    dst_host_same_srv_rate = dst_port_count[dst_port] / dst_host_srv_count if dst_host_srv_count > 0 else 0
    dst_host_same_src_port_rate = src_port_count[src_port] / dst_host_srv_count if dst_host_srv_count > 0 else 0

    # Feature extraction based on the model)
    features = {
        'protocol_type': packet[IP].proto,
        'service': src_port,
        'flag': flag_value,
        'src_bytes': len(packet[IP].payload),
        'dst_bytes': len(packet[IP].payload),
        'count': count,
        'same_srv_rate': same_srv_rate,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_same_src_port_rate': dst_host_same_src_port_rate
    }
    return pd.Series(features).values

def inform_user(message):
    """Inform the user about detected malicious packets."""
    # This function can be customized to send notifications, emails, etc.
    notifications.append(message)
    print(f"ALERT: {message}")  # Debugging statement

@app.route('/start_capture')
def start_capture():
    """Start packet capture on the selected network interface."""
    global capture_thread, capture_running
    interface = request.args.get('interface')
    if interface:
        capture_running = True
        capture_thread = threading.Thread(target=packet_capture, args=(interface,), daemon=True)
        capture_thread.start()
        return jsonify({"status": "Capture started on interface " + interface})
    else:
        return jsonify({"error": "No interface specified"}), 400

@app.route('/stop_capture')
def stop_capture():
    """Stop packet capture."""
    global capture_running
    capture_running = False
    return jsonify({"status": "Capture stopped"})

@app.route('/clear_logs')
def clear_logs():
    """Clear the packet logs."""
    global packet_logs
    packet_logs = []
    return jsonify({"status": "Packet logs cleared"})

def packet_capture(interface):
    """Start sniffing packets using Scapy."""
    while capture_running:
        sniff(filter="ip", iface=interface, prn=process_packet, store=False, timeout=1)

@app.route('/interfaces')
def interfaces():
    """Provide a list of available network interfaces with names."""
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces.append({
                    'name': name,
                    'ip': addr.address
                })
    return jsonify(interfaces)

@app.route('/')
def index():
    """Serve the main page with packet logs."""
    return render_template('index.html', logs=packet_logs)

@app.route('/logs')
def logs():
    """Provide packet logs in JSON format."""
    return jsonify(packet_logs)

@app.route('/notifications')
def get_notifications():
    """Provide notifications in JSON format."""
    print(f"Notifications: {notifications}")  # Debugging statement
    return jsonify(notifications)

if __name__ == "__main__":
    # Run the Flask web application
    app.run(debug=True, host='0.0.0.0', port=5000)
