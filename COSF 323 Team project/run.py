from flask import Flask, render_template, jsonify
import threading
from scapy.all import sniff, IP
import time

app = Flask(__name__)

# Global list to store packet logs
packet_logs = []

def process_packet(packet):
    """Callback function to process each captured packet."""
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        log = f"Packet: {ip_layer.src} -> {ip_layer.dst} at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        packet_logs.append(log)
        print(log)  # Print to console for debugging

def packet_capture():
    """Start sniffing packets using Scapy."""
    sniff(filter="ip", prn=process_packet, store=False)

@app.route('/')
def index():
    """Serve the main page with packet logs."""
    return render_template('index.html', logs=packet_logs)

@app.route('/logs')
def logs():
    """Provide packet logs in JSON format."""
    return jsonify(packet_logs)

if __name__ == "__main__":
    # Start packet capture in a background thread
    capture_thread = threading.Thread(target=packet_capture, daemon=True)
    capture_thread.start()
    
    # Run the Flask web application
    app.run(debug=True, host='0.0.0.0', port=5000)
