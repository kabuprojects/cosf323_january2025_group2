from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
import threading
from scapy.all import sniff, IP, TCP, UDP
import time
import psutil
import socket
import joblib
import pandas as pd
from collections import defaultdict
import os

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb+srv://mwainaina:admin123@cluster0.jv0jw.mongodb.net/mydatabase"
app.config["SECRET_KEY"] = "your_secret_key"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Load the trained model
model_path = os.path.join(os.path.dirname(__file__), 'trained_model.pkl')
model = joblib.load(model_path)

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
        
        log = {
            'message': f"Packet: {ip_layer.src} -> {ip_layer.dst} ({transport_layer}) at {time.strftime('%Y-%m-%d %H:%M:%S')}",
            'type': 'benign' if prediction == 1 else 'malicious',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': ip_layer.src,
            'dst_ip': ip_layer.dst,
            'protocol': transport_layer
        }
        
        # Check if the packet already exists in the logs
        if not any(
            existing_log['src_ip'] == log['src_ip'] and
            existing_log['dst_ip'] == log['dst_ip'] and
            existing_log['protocol'] == log['protocol'] and
            existing_log['timestamp'] == log['timestamp']
            for existing_log in packet_logs
        ):
            if prediction == 0:  # 0 indicates a malicious packet
                log['message'] += " [WARNING: Malicious Packet Detected]"
                # Inform the user about the detected malicious packet
                inform_user(log['message'])
            else:  # 1 indicates a benign packet
                log['message'] += " [INFO: Benign Packet]"
            
            # Add the log to the packet logs list
            packet_logs.append(log)
            # Ensure the packet logs list does not exceed the limit
            if len(packet_logs) > PACKET_LOGS_LIMIT:
                packet_logs.pop(0)
            
            print(log['message'])  # Print to console for debugging

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

    # Feature extraction based on the model
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
        sniff(filter="ip", iface=interface, prn=process_packet, store=False, timeout=10)

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
    if 'username' in session:
        return render_template('index.html', logs=packet_logs)
    return redirect(url_for('login'))

@app.route('/logs')
def logs():
    """Provide packet logs in JSON format."""
    if 'username' in session:
        return jsonify(packet_logs)
    return redirect(url_for('login'))

@app.route('/notifications')
def get_notifications():
    """Provide notifications in JSON format."""
    if 'username' in session:
        return jsonify(notifications)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        users = mongo.db.users
        login_user = users.find_one({'username': request.form['username']})

        if login_user and bcrypt.check_password_hash(login_user['password'], request.form['password']):
            session['username'] = request.form['username']
            return redirect(url_for('index'))

        flash('Invalid username/password combination')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page."""
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'username': request.form['username']})

        if existing_user is None:
            hashpass = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
            users.insert_one({
                'username': request.form['username'],
                'email': request.form['email'],
                'password': hashpass
            })
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))

        flash('Username already exists')
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout the current user."""
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == "__main__":
    # Run the Flask web application
    app.run(debug=True, host='0.0.0.0', port=5000)
