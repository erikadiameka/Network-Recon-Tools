import socket
from datetime import datetime

# =========================

target = input("Masukkan target (contoh: scanme.nmap.org): ")

print(f"\n🔍 Scanning {target}...\n")

start_time = datetime.now()

# daftar port umum + service
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

for port in range(1, 1001):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)

    result = s.connect_ex((target, port))

    if result == 0:
        service = common_ports.get(port, "UNKNOWN")
        print(f"🟢 Port {port} TERBUKA → {service}")

    s.close()

end_time = datetime.now()
total = end_time - start_time

print(f"\n⏱️ Waktu scan: {total}")