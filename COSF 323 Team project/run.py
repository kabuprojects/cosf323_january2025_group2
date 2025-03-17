from flask import Flask, render_template, jsonify, request
import threading
from scapy.all import sniff, IP, TCP, UDP
import time
import psutil
import socket

app = Flask(__name__)

# Global list to store packet logs
packet_logs = []
capture_thread = None
capture_running = False

def process_packet(packet):
    """Callback function to process each captured packet."""
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        transport_layer = "Unknown"
        if packet.haslayer(TCP):
            transport_layer = "TCP"
        elif packet.haslayer(UDP):
            transport_layer = "UDP"
        
        log = f"Packet: {ip_layer.src} -> {ip_layer.dst} ({transport_layer}) at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        packet_logs.append(log)
        print(log)  # Print to console for debugging

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

def packet_capture(interface):
    """Start sniffing packets using Scapy."""
    while capture_running:
        sniff(filter="ip", iface=interface, prn=process_packet, store=False)

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

if __name__ == "__main__":
    # Run the Flask web application
    app.run(debug=True, host='0.0.0.0', port=5000)
