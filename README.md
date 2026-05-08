# Python-Based Intrusion Detection System (IDS)

This is a custom IDS project I made using Python to better understand how intrusion detection systems and network monitoring work.

The system monitors live network traffic, detects suspicious activity, sends Discord alerts, tracks IP locations, and logs alerts for analysis.

I mainly built this project to learn more about packet inspection, network behavior, and how SOC-style monitoring systems work.

# Features

Live packet monitoring using Scapy
Detection of:

* Port scanning behavior
* High connection attempts
* ICMP flood activity
* Suspicious port access

Real-time Discord alerts
IP geolocation tracking
JSON alert logging
Security analytics dashboard using Matplotlib
Threshold-based anomaly detection logic


# How It Works

The IDS captures live packets and analyzes traffic patterns in real time.

It checks things like:

* source IP addresses
* destination ports
* packet frequency
* TCP and ICMP traffic

If suspicious behavior passes certain thresholds, the system:

* generates an alert
* sends a Discord notification
* logs the event into a JSON file

# Detection Capabilities

## High Connection Detection

Detects when a single IP sends too many packets within a short amount of time.

## Port Scan Detection

Detects when an IP attempts connections to many different ports, which may indicate scanning behavior.

## ICMP Flood Detection

Detects excessive ICMP ping activity.

## Suspicious Port Monitoring

Monitors traffic involving commonly targeted ports.

# IP Geolocation Tracking

The IDS performs IP lookups to identify:

* country
* city
* ISP / organization

This helps provide more context about where suspicious traffic is coming from.

# Analytics Dashboard

The dashboard shows:

* top IPs generating alerts
* alert type distribution
* traffic origin countries

This makes it easier to analyze suspicious traffic activity.


# Screenshots

## IDS Terminal
<img width="2831" height="1199" alt="Screenshot 2026-05-08 002231" src="https://github.com/user-attachments/assets/28ad00cc-9383-4cc7-aa27-cb5f4482932a" />



## Discord Alerts
<img width="1968" height="987" alt="Screenshot 2026-05-08 002348" src="https://github.com/user-attachments/assets/d9eaa0a3-856d-4d19-ba62-db8b27bae53b" />

<img width="1978" height="1123" alt="Screenshot 2026-05-08 002321" src="https://github.com/user-attachments/assets/e48b601d-53ea-4e80-8b4d-83d1b8745cea" />


## Analytics Dashboard
<img width="1985" height="1109" alt="Screenshot 2026-05-08 002424" src="https://github.com/user-attachments/assets/b46d0c29-e768-4a39-8261-feabb3985d71" />
<img width="1590" height="1096" alt="Screenshot 2026-05-08 002436" src="https://github.com/user-attachments/assets/8f4e1f83-81d0-4b1d-bd79-7487befa4ed0" />
<img width="1572" height="1112" alt="Screenshot 2026-05-08 002446" src="https://github.com/user-attachments/assets/586a4b5f-4a33-4e0a-b7ea-d4d7890fa4fd" />

# Technologies Used

* Python
* Scapy
* Requests
* Matplotlib
* Discord Webhooks




# Installation

## Clone Repository

```bash
git clone https://github.com/izzatikram-web/Intrusion-Detection-System.git
cd Intrusion-Detection-System
```

---

## Create Virtual Environment

```bash
python -m venv venv
```

Activate environment:

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running the IDS

```bash
python ids.py
```

The system will begin monitoring live network traffic.

---

# Running the Dashboard

```bash
python dashboard.py
```

---

# Testing the IDS

## ICMP Flood Test

```bash
ping x.x.x.x -n 100
```

## Port Scan Test

```bash
nmap x.x.x.x (ip address)
```

---

# Future Improvements

Possible future improvements include:

* Live web dashboard
* Threat severity scoring
* Machine learning anomaly detection
* World map visualization of attacker IPs
* Email notifications
* Threat intelligence integration

