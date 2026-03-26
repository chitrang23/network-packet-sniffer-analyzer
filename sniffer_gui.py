import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import threading
import csv
import requests
import folium
from sklearn.ensemble import IsolationForest

# ==============================
# GLOBAL VARIABLES
# ==============================
running = False
packet_count = 0
tcp_count = 0
udp_count = 0
selected_protocol = "ALL"
log_data = []

model = IsolationForest(contamination=0.1)
data_points = []

# ==============================
# AUTO DETECT WORKING INTERFACE
# ==============================
def get_working_interface():
    interfaces = get_if_list()
    print("Available Interfaces:\n", interfaces)

    for iface in interfaces:
        print(f"\nTesting interface: {iface}")
        try:
            packets = sniff(iface=iface, count=3, timeout=2)
            if packets:
                print(f"✅ Working Interface Found: {iface}")
                return iface
        except:
            continue

    print("❌ No working interface found, using default")
    return interfaces[0]

INTERFACE = get_working_interface()

# ==============================
# GEO LOCATION
# ==============================
def show_map(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if res['status'] != 'success':
            return

        lat = res['lat']
        lon = res['lon']
        city = res['city']

        m = folium.Map(location=[lat, lon], zoom_start=4)
        folium.Marker([lat, lon], popup=f"{ip} - {city}").add_to(m)
        m.save("map.html")

    except:
        pass

# ==============================
# GUI SAFE UPDATE
# ==============================
def update_gui(output):
    text_area.insert(tk.END, output)
    text_area.yview(tk.END)

# ==============================
# PACKET ANALYSIS
# ==============================
def analyze_packet(packet):
    global packet_count, tcp_count, udp_count

    if not running:
        return

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "OTHER"
        proto_num = 0

        if packet.haslayer(TCP):
            protocol = "TCP"
            proto_num = 1
            tcp_count += 1
        elif packet.haslayer(UDP):
            protocol = "UDP"
            proto_num = 2
            udp_count += 1

        # Filter
        if selected_protocol != "ALL" and protocol != selected_protocol:
            return

        # Convert IP to numeric
        src_num = sum(map(int, src.split('.')))
        dst_num = sum(map(int, dst.split('.')))

        data_points.append([src_num, dst_num, proto_num])

        # AI detection (fast)
        if len(data_points) > 5:
            model.fit(data_points)
            prediction = model.predict([data_points[-1]])[0]
        else:
            prediction = 1

        alert = "⚠ Anomaly" if prediction == -1 else "✅ Normal"

        packet_count += 1

        output = f"{packet_count} | {src} -> {dst} | {protocol} {alert}\n"

        log_data.append([packet_count, src, dst, protocol, alert])

        # Safe GUI update
        root.after(0, update_gui, output)

        # Update stats
        root.after(0, lambda: stats_label.config(
            text=f"TCP: {tcp_count} | UDP: {udp_count}"
        ))

        # Map for anomaly
        if prediction == -1:
            show_map(src)

# ==============================
# SNIFFING
# ==============================
def sniff_packets():
    print("🚀 Using interface:", INTERFACE)
    sniff(prn=analyze_packet, store=False, iface=INTERFACE)

# ==============================
# CONTROLS
# ==============================
def start_sniffing():
    global running
    running = True
    status_label.config(text="Status: Running", fg="green")
    threading.Thread(target=sniff_packets, daemon=True).start()

def stop_sniffing():
    global running
    running = False
    status_label.config(text="Status: Stopped", fg="red")

def set_protocol(value):
    global selected_protocol
    selected_protocol = value

def export_logs():
    with open("packet_logs.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["No", "Source", "Destination", "Protocol", "Status"])
        
        # Remove emojis for CSV compatibility
        clean_data = []
        for row in log_data:
            clean_row = [
                row[0],
                row[1],
                row[2],
                row[3],
                row[4].replace("✅", "Normal").replace("⚠", "Anomaly")
            ]
            clean_data.append(clean_row)

        writer.writerows(clean_data)

# ==============================
# GUI
# ==============================
root = tk.Tk()
root.title("AI Network Packet Sniffer & Analyzer")
root.geometry("750x550")

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Button(frame, text="Start Capture", bg="green", fg="white",
          command=start_sniffing).grid(row=0, column=0, padx=5)

tk.Button(frame, text="Stop Capture", bg="red", fg="white",
          command=stop_sniffing).grid(row=0, column=1, padx=5)

tk.Button(frame, text="Export Logs",
          command=export_logs).grid(row=0, column=2, padx=5)

dropdown = ttk.Combobox(root, values=["ALL", "TCP", "UDP"])
dropdown.set("ALL")
dropdown.bind("<<ComboboxSelected>>", lambda e: set_protocol(dropdown.get()))
dropdown.pack()

status_label = tk.Label(root, text="Status: Stopped", fg="red")
status_label.pack()

stats_label = tk.Label(root, text="TCP: 0 | UDP: 0")
stats_label.pack()

text_area = tk.Text(root, height=25, width=90)
text_area.pack()

root.mainloop()