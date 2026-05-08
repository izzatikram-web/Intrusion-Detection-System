import json
from collections import Counter
import matplotlib.pyplot as plt

LOG_FILE = "ids_alerts.json"

ips = []
alert_types = []
countries = []

with open(LOG_FILE, "r") as file:
    for line in file:
        try:
            alert = json.loads(line)

            ips.append(alert.get("source_ip", "Unknown"))
            alert_types.append(alert.get("alert_type", "Unknown"))
            countries.append(alert.get("country", "Unknown"))

        except:
            pass

# Count occurrences
ip_counts = Counter(ips)
top_ips = dict(ip_counts.most_common(10))
alert_counts = Counter(alert_types)
country_counts = Counter(countries)

# -------- TOP IPs --------
plt.figure(figsize=(10,5))
plt.bar(top_ips.keys(), top_ips.values())
plt.title("Top IPs Generating Alerts")
plt.xlabel("IP Address")
plt.ylabel("Alert Count")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# -------- ALERT TYPES --------
plt.figure(figsize=(8,5))
plt.bar(alert_counts.keys(), alert_counts.values())
plt.title("Alert Types")
plt.xlabel("Alert Type")
plt.ylabel("Count")
plt.xticks(rotation=20)
plt.tight_layout()
plt.show()

# -------- COUNTRIES --------
plt.figure(figsize=(8,5))
plt.bar(country_counts.keys(), country_counts.values())
plt.title("Traffic Origin Countries")
plt.xlabel("Country")
plt.ylabel("Alert Count")
plt.xticks(rotation=20)
plt.tight_layout()
plt.show()