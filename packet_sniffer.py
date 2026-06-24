"""
Packet Sniffer Tool
====================
Menangkap dan menganalisis paket data di jaringan.

Informasi yang ditangkap:
  - IP sumber & tujuan
  - Port sumber & tujuan
  - Protokol (TCP, UDP, ICMP)
  - Ukuran paket
  - Data payload (jika tidak terenkripsi)

LEGAL NOTICE:
  - Gunakan HANYA pada jaringan milik sendiri
  - Menyadap jaringan orang lain tanpa izin = melanggar hukum
  - Butuh akses Administrator/Root

Penggunaan:
  # Jalankan sebagai Administrator di Windows!
  python packet_sniffer.py
  python packet_sniffer.py --count 50
  python packet_sniffer.py --filter tcp
  python packet_sniffer.py --output hasil.txt
"""

import socket
import struct
import argparse
import sys
import os
from datetime import datetime

# ─────────────────────────────────────────────
# KONSTANTA PROTOKOL
# ─────────────────────────────────────────────

PROTOCOLS = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
}

# Port umum untuk identifikasi layanan
COMMON_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# ─────────────────────────────────────────────
# PARSER PAKET
# ─────────────────────────────────────────────

def parse_ip_header(data: bytes) -> dict:
    """Parse IP header dari raw bytes."""
    if len(data) < 20:
        return {}

    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = iph[0]
    ihl = (version_ihl & 0xF) * 4  # IP header length
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    total_length = iph[2]

    return {
        "version": version_ihl >> 4,
        "ihl": ihl,
        "protocol_num": protocol,
        "protocol": PROTOCOLS.get(protocol, f"OTHER({protocol})"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "total_length": total_length,
        "payload": data[ihl:],
    }


def parse_tcp_header(data: bytes) -> dict:
    """Parse TCP header."""
    if len(data) < 20:
        return {}

    tcph = struct.unpack("!HHLLBBHHH", data[:20])
    src_port = tcph[0]
    dst_port = tcph[1]
    sequence = tcph[2]
    flags_byte = tcph[5]

    # Parse TCP flags
    flags = {
        "FIN": bool(flags_byte & 0x01),
        "SYN": bool(flags_byte & 0x02),
        "RST": bool(flags_byte & 0x04),
        "PSH": bool(flags_byte & 0x08),
        "ACK": bool(flags_byte & 0x10),
        "URG": bool(flags_byte & 0x20),
    }
    active_flags = [f for f, v in flags.items() if v]

    data_offset = (tcph[4] >> 4) * 4
    payload = data[data_offset:]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "sequence": sequence,
        "flags": active_flags,
        "payload": payload,
    }


def parse_udp_header(data: bytes) -> dict:
    """Parse UDP header."""
    if len(data) < 8:
        return {}

    udph = struct.unpack("!HHHH", data[:8])
    return {
        "src_port": udph[0],
        "dst_port": udph[1],
        "length": udph[2],
        "payload": data[8:],
    }


def parse_icmp_header(data: bytes) -> dict:
    """Parse ICMP header."""
    if len(data) < 4:
        return {}

    icmph = struct.unpack("!BBH", data[:4])
    icmp_types = {
        0: "Echo Reply (Ping Reply)",
        3: "Destination Unreachable",
        8: "Echo Request (Ping)",
        11: "Time Exceeded",
    }
    return {
        "type": icmph[0],
        "type_name": icmp_types.get(icmph[0], f"Type {icmph[0]}"),
        "code": icmph[1],
    }


def get_service(port: int) -> str:
    """Identifikasi layanan dari nomor port."""
    return COMMON_PORTS.get(port, "")


def extract_http_info(payload: bytes) -> str:
    """Ekstrak info HTTP dari payload jika ada."""
    try:
        text = payload.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        if lines and any(
            lines[0].startswith(m) for m in ["GET", "POST", "PUT", "DELETE", "HTTP/"]
        ):
            return lines[0][:100]
    except Exception:
        pass
    return ""


def extract_dns_info(payload: bytes) -> str:
    """Ekstrak nama domain dari query DNS jika ada."""
    try:
        if len(payload) < 12:
            return ""
        # Skip DNS header (12 bytes), parse query name
        i = 12
        domain_parts = []
        while i < len(payload):
            length = payload[i]
            if length == 0:
                break
            i += 1
            part = payload[i:i+length].decode("ascii", errors="ignore")
            domain_parts.append(part)
            i += length
        if domain_parts:
            return ".".join(domain_parts)
    except Exception:
        pass
    return ""


# ─────────────────────────────────────────────
# DISPLAY PAKET
# ─────────────────────────────────────────────

packet_count = 0

def display_packet(ip: dict, transport: dict, filter_proto: str, output_file=None):
    """Tampilkan informasi paket."""
    global packet_count
    protocol = ip["protocol"]

    # Filter protokol
    if filter_proto and filter_proto.upper() != protocol:
        return

    packet_count += 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    src_port = transport.get("src_port", "")
    dst_port = transport.get("dst_port", "")
    src_service = get_service(src_port) if src_port else ""
    dst_service = get_service(dst_port) if dst_port else ""

    # Format port dengan nama layanan
    src_str = f"{ip['src_ip']}:{src_port}" if src_port else ip["src_ip"]
    dst_str = f"{ip['dst_ip']}:{dst_port}" if dst_port else ip["dst_ip"]
    if src_service:
        src_str += f"({src_service})"
    if dst_service:
        dst_str += f"({dst_service})"

    # Flags TCP
    flags_str = ""
    if "flags" in transport and transport["flags"]:
        flags_str = f" [{','.join(transport['flags'])}]"

    # Info tambahan
    extra = ""
    payload = transport.get("payload", b"")

    if protocol == "TCP":
        http = extract_http_info(payload)
        if http:
            extra = f"\n    📄 HTTP: {http}"
    elif protocol == "UDP":
        if dst_port == 53 or src_port == 53:
            dns = extract_dns_info(payload)
            if dns:
                extra = f"\n    🌐 DNS Query: {dns}"
    elif protocol == "ICMP":
        icmp_name = transport.get("type_name", "")
        extra = f" | {icmp_name}"

    line = (
        f"  #{packet_count:04d} [{timestamp}] {protocol:<5}{flags_str}"
        f"\n    {src_str} → {dst_str}"
        f" | {ip['total_length']} bytes{extra}"
    )

    print(line)
    print()

    if output_file:
        output_file.write(line + "\n\n")


# ─────────────────────────────────────────────
# MAIN SNIFFER
# ─────────────────────────────────────────────

def run_sniffer(count: int, filter_proto: str, output_path: str):
    print("=" * 55)
    print("  PACKET SNIFFER TOOL")
    print("  Untuk keperluan edukasi dan analisis jaringan.")
    print("=" * 55)

    if filter_proto:
        print(f"  Filter  : {filter_proto.upper()} only")
    else:
        print(f"  Filter  : Semua protokol (TCP, UDP, ICMP)")

    print(f"  Limit   : {count if count else 'Tidak terbatas (Ctrl+C untuk stop)'}")
    print(f"  Waktu   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n  Menangkap paket... (tekan Ctrl+C untuk berhenti)\n")
    print("─" * 55)

    # Buat raw socket
    try:
        if sys.platform == "win32":
            # Windows: gunakan socket biasa dengan AF_INET
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((socket.gethostbyname(socket.gethostname()), 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Windows perlu SIO_RCVALL untuk menangkap semua paket
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # Linux/Mac: gunakan AF_PACKET
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except PermissionError:
        print("\n  [!] ERROR: Butuh akses Administrator/Root!")
        print("  Di Windows: klik kanan PowerShell → 'Run as Administrator'")
        print("  Di Linux  : jalankan dengan 'sudo python packet_sniffer.py'\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n  [!] Error membuat socket: {e}\n")
        sys.exit(1)

    output_file = None
    if output_path:
        output_file = open(output_path, "w", encoding="utf-8")
        print(f"  📄 Menyimpan ke: {output_path}\n")

    captured = 0

    try:
        while True:
            if count and captured >= count:
                break

            raw_data, addr = s.recvfrom(65535)

            # Windows sudah include IP header, Linux perlu skip ethernet header
            if sys.platform != "win32":
                raw_data = raw_data[14:]  # Skip ethernet frame (14 bytes)

            ip = parse_ip_header(raw_data)
            if not ip:
                continue

            transport = {}
            protocol = ip["protocol"]
            payload = ip["payload"]

            if protocol == "TCP":
                transport = parse_tcp_header(payload)
            elif protocol == "UDP":
                transport = parse_udp_header(payload)
            elif protocol == "ICMP":
                transport = parse_icmp_header(payload)
            else:
                continue  # Skip protokol lain

            display_packet(ip, transport, filter_proto, output_file)
            captured += 1

    except KeyboardInterrupt:
        print(f"\n\n  Dihentikan oleh user.")
    finally:
        if sys.platform == "win32":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        s.close()
        if output_file:
            output_file.close()

    print(f"\n{'=' * 55}")
    print(f"  Total paket tertangkap: {packet_count}")
    print(f"  Selesai: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'=' * 55}\n")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="📡 Packet Sniffer — Educational Use Only",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Contoh:
  # Tangkap semua paket (jalankan sebagai Admin!)
  python packet_sniffer.py

  # Tangkap 50 paket saja
  python packet_sniffer.py --count 50

  # Filter hanya TCP
  python packet_sniffer.py --filter tcp

  # Filter DNS (UDP port 53)
  python packet_sniffer.py --filter udp

  # Simpan hasil ke file
  python packet_sniffer.py --count 100 --output paket.txt

PENTING: Jalankan PowerShell sebagai Administrator!
        """
    )

    parser.add_argument("--count",  type=int, default=0,    help="Jumlah paket yang ditangkap (0 = unlimited)")
    parser.add_argument("--filter", type=str, default=None, help="Filter protokol: tcp / udp / icmp")
    parser.add_argument("--output", type=str, default=None, help="Simpan hasil ke file .txt")

    args = parser.parse_args()

    if args.filter and args.filter.upper() not in ["TCP", "UDP", "ICMP"]:
        print(f"[!] Filter tidak valid. Gunakan: tcp, udp, atau icmp")
        sys.exit(1)

    run_sniffer(args.count, args.filter, args.output)


if __name__ == "__main__":
    main()