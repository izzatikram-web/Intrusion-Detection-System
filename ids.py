from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress
import requests
import json

DISCORD_WEBHOOK_URL = ""

LOG_FILE = "ids_alerts.json"

geo_cache = {}

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_multicast or
            ip_obj.is_reserved
        )
    except ValueError:
        return False


def get_ip_location(ip):
    if ip in geo_cache:
        return geo_cache[ip]

    if not is_public_ip(ip):
        location = {
            "country": "Private/Local",
            "city": "N/A",
            "isp": "N/A"
        }
        geo_cache[ip] = location
        return location

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,query"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") == "success":
            location = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", data.get("org", "Unknown"))
            }
        else:
            location = {
                "country": "Unknown",
                "city": "Unknown",
                "isp": "Unknown"
            }

    except Exception:
        location = {
            "country": "Lookup failed",
            "city": "Lookup failed",
            "isp": "Lookup failed"
        }

    geo_cache[ip] = location
    return location

connection_attempts = defaultdict(list)
port_scan_tracker = defaultdict(set)
icmp_tracker = defaultdict(list)
last_alert_time = {}

SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    445: "SMB"
}

TIME_WINDOW = timedelta(seconds=60)
CONNECTION_THRESHOLD = 25
PORT_SCAN_THRESHOLD = 10
ICMP_THRESHOLD = 20


def send_discord_alert(alert_type, src_ip, details, location):
    if DISCORD_WEBHOOK_URL == "":
        return

    message = {
        "content": (
            f" 🚨**IDS Alert**\n"
            f"**Type:** {alert_type}\n"
            f"**IP:** {src_ip}\n"
            f"**Location:** {location['city']}, {location['country']}\n"
            f"**ISP/Org:** {location['isp']}\n"
            f"**Details:** {details}\n"
            f"**Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    }

    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except Exception as e:
        print(f"Discord alert failed: {e}")


def log_alert(alert_type, src_ip, details):
    key = f"{alert_type}-{src_ip}"
    now = datetime.now()

    if key in last_alert_time:
        if now - last_alert_time[key] < timedelta(seconds=60):
            return

    last_alert_time[key] = now

    location = get_ip_location(src_ip)

    alert = {
        "timestamp": now.isoformat(),
        "alert_type": alert_type,
        "source_ip": src_ip,
        "country": location["country"],
        "city": location["city"],
        "isp": location["isp"],
        "details": details
    }

    with open(LOG_FILE, "a") as file:
        file.write(json.dumps(alert) + "\n")

    print(
        f"[ALERT] {alert_type} from {src_ip} "
        f"({location['city']}, {location['country']}) - {details}"
    )

    send_discord_alert(alert_type, src_ip, details, location)


def clean_old(events, now):
    return [t for t in events if now - t <= TIME_WINDOW]


def analyze_packet(packet):
    now = datetime.now()

    if packet.haslayer(IP):
        src_ip = packet[IP].src

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            connection_attempts[src_ip].append(now)
            connection_attempts[src_ip] = clean_old(connection_attempts[src_ip], now)

            if len(connection_attempts[src_ip]) > CONNECTION_THRESHOLD:
                log_alert("High Connections", src_ip, f"{len(connection_attempts[src_ip])} packets in 60s")
                connection_attempts[src_ip].clear()

            if flags & 0x02:
                port_scan_tracker[src_ip].add(dst_port)

                if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                    log_alert("Port Scan", src_ip, f"Ports: {list(port_scan_tracker[src_ip])}")
                    port_scan_tracker[src_ip].clear()

            if dst_port in SUSPICIOUS_PORTS:
                log_alert("Suspicious Port", src_ip, f"{SUSPICIOUS_PORTS[dst_port]} ({dst_port})")

        if packet.haslayer(ICMP):
            icmp_tracker[src_ip].append(now)
            icmp_tracker[src_ip] = clean_old(icmp_tracker[src_ip], now)

            if len(icmp_tracker[src_ip]) > ICMP_THRESHOLD:
                log_alert("ICMP Flood", src_ip, f"{len(icmp_tracker[src_ip])} pings")
                icmp_tracker[src_ip].clear()


print("IDS is running...")
log_alert("TEST ALERT", "127.0.0.1", "Testing Discord webhook")
sniff(prn=analyze_packet, store=False)