# 🛡️ AI Network Packet Sniffer & Analyzer

## 📌 Overview

This project is an advanced cybersecurity tool that captures live network traffic and analyzes it using AI (Machine Learning) to detect suspicious or anomalous activity.

It also provides real-time visualization and maps suspicious IP addresses using geolocation.

---

## 🚀 Features

✅ Live packet capture using Scapy
✅ AI-based anomaly detection (Isolation Forest)
✅ TCP / UDP traffic monitoring
✅ Real-time GUI using Tkinter
✅ Geo-location mapping of suspicious IPs
✅ CSV log export
✅ Protocol filtering (ALL / TCP / UDP)
✅ Thread-safe real-time updates

---

## 🧠 How It Works

1. Captures packets from your network interface
2. Extracts features (source IP, destination IP, protocol)
3. Converts data into numeric format
4. Uses **Isolation Forest (AI Model)** to detect anomalies
5. Displays results in GUI:

   * ✅ Normal Traffic
   * ⚠ Suspicious / Anomalous Traffic
6. Suspicious IPs are mapped using geolocation API

---

## 🛠️ Technologies Used

* Python
* Scapy (Packet Sniffing)
* Tkinter (GUI)
* Scikit-learn (AI Model)
* Folium (Map Visualization)
* Requests (API calls)

---

## 📦 Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-username/ai-packet-sniffer.git
cd ai-packet-sniffer
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Npcap (IMPORTANT for Windows)

Download and install:
👉 https://npcap.com/

✔ Enable:

* WinPcap API-compatible mode

---

## ▶️ Run the Project

```bash
python sniffer_gui.py
```

---

## 🖥️ Usage

1. Click **Start Capture**
2. Select protocol (ALL / TCP / UDP)
3. View live packet logs
4. Detect anomalies in real-time
5. Click **Export Logs** to save results
6. Open `map.html` to view suspicious IP locations

---

## 📊 Output Example

```
1 | 192.168.1.5 -> 8.8.8.8 | TCP ✅ Normal
2 | 45.33.32.156 -> 192.168.1.5 | TCP ⚠ Anomaly
```

---

## ⚠️ Important Notes

* Run as **Administrator** (required for packet sniffing)
* Ensure **Npcap** is installed on Windows
* Works best on active networks (WiFi / Ethernet)

---

## 🔐 Use Cases

* Network monitoring
* Intrusion detection (basic IDS)
* Cybersecurity learning project
* Traffic analysis

---

## 🚀 Future Improvements

* Real-time graphs & dashboards
* Deep learning-based detection
* Integration with threat intelligence APIs
* Live map inside GUI
* Web-based dashboard

---

## 👨‍💻 Author

Developed by **Chitrang**

---

## ⭐ If you like this project

Give it a star ⭐ on GitHub!
