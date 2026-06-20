from scapy.all import *

# Load capture file
packets = rdpcap("my_capture.pcapng")

# Protocol counters
tcp_count = 0
udp_count = 0
icmp_count = 0

# IP counters
src_count = {}
dst_count = {}

# Port counters
tcp_ports = {}
udp_ports = {}

# Analyze packets
for packet in packets:

    # Protocol counting
    if TCP in packet:
        tcp_count += 1

        port = packet[TCP].dport
        if port in tcp_ports:
            tcp_ports[port] += 1
        else:
            tcp_ports[port] = 1

    elif UDP in packet:
        udp_count += 1

        port = packet[UDP].dport
        if port in udp_ports:
            udp_ports[port] += 1
        else:
            udp_ports[port] = 1

    elif ICMP in packet:
        icmp_count += 1

    # IP analysis
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in src_count:
            src_count[src_ip] += 1
        else:
            src_count[src_ip] = 1

        if dst_ip in dst_count:
            dst_count[dst_ip] += 1
        else:
            dst_count[dst_ip] = 1

# Statistics
most_active = max(src_count, key=src_count.get)
most_targeted = max(dst_count, key=dst_count.get)

sorted_ips = sorted(
    src_count.items(),
    key=lambda x: x[1],
    reverse=True
)

protocols = {
    "TCP": tcp_count,
    "UDP": udp_count,
    "ICMP": icmp_count
}

most_used = max(protocols, key=protocols.get)

unique_ips = len(src_count)

# Generate report
report = ""

report += "NETWORK ANALYSIS REPORT\n"
report += "=======================\n\n"

report += f"Total Packets: {len(packets)}\n\n"

report += f"Most Active IP: {most_active}\n"
report += f"Packets: {src_count[most_active]}\n\n"

report += f"Most Targeted Destination: {most_targeted}\n"
report += f"Packets Received: {dst_count[most_targeted]}\n\n"

report += "TOP 5 SOURCE IPS\n"
report += "================\n"

for ip, count in sorted_ips[:5]:
    report += f"{ip} -> {count}\n"

report += "\nTRAFFIC STATISTICS\n"
report += "==================\n"
report += f"Unique Source IPs: {unique_ips}\n"

report += "\nPROTOCOL REPORT\n"
report += "===============\n"
report += f"TCP: {tcp_count}\n"
report += f"UDP: {udp_count}\n"
report += f"ICMP: {icmp_count}\n\n"

report += f"Most Used Protocol: {most_used}\n"

report += "\nSECURITY ALERTS\n"
report += "===============\n"

for ip, count in sorted_ips:

    if count >= 400:
        report += f"[HIGH] {ip} generated {count} packets\n"

    elif count >= 200:
        report += f"[MEDIUM] {ip} generated {count} packets\n"

    elif count >= 100:
        report += f"[LOW] {ip} generated {count} packets\n"

report += "\nSCAN DETECTION\n"
report += "==============\n"

for ip, count in src_count.items():
    if count > 300:
        report += f"{ip} -> Possible scanning activity\n"

port_services = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP"
}

report += "\nPORT ANALYSIS\n"
report += "=============\n"

sorted_tcp = sorted(
    tcp_ports.items(),
    key=lambda x: x[1],
    reverse=True
)

for port, count in sorted_tcp[:5]:

    service = port_services.get(port, "Unknown Service")

    report += f"{service} ({port}) -> {count} packets\n"

# Save report
with open("network_report.txt", "w") as file:
    file.write(report)

print("Report Generated Successfully!")
import matplotlib.pyplot as plt

# Top 5 IPs
top_ips = sorted_ips[:5]

ip_addresses = []
packet_counts = []

for ip, count in top_ips:
    ip_addresses.append(ip)
    packet_counts.append(count)

plt.figure(figsize=(10, 5))
plt.bar(ip_addresses, packet_counts)

plt.title("Top 5 Source IPs")
plt.xlabel("IP Address")
plt.ylabel("Packet Count")

plt.xticks(rotation=20)

plt.tight_layout()

plt.savefig("traffic_graph.png")

plt.show()
# Protocol Pie Chart

protocol_labels = ["TCP", "UDP", "ICMP"]
protocol_values = [tcp_count, udp_count, icmp_count]

plt.figure(figsize=(6, 6))

plt.pie(
    protocol_values,
    labels=protocol_labels,
    autopct="%1.1f%%"
)

plt.title("Protocol Distribution")

plt.savefig("protocol_pie_chart.png")

plt.show()