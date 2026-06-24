"""
Network Scanner Tool
=====================
Scan semua perangkat yang terhubung ke jaringan WiFi.

Informasi yang ditampilkan:
  - IP Address setiap perangkat
  - MAC Address
  - Hostname (nama perangkat)
  - Vendor/Produsen perangkat
  - Status (aktif/tidak)
  - Waktu respon (ping)

LEGAL NOTICE:
  - Gunakan HANYA pada jaringan milik sendiri
  - Scanning jaringan orang lain tanpa izin = melanggar hukum
  - Butuh akses Administrator untuk fitur ARP

Penggunaan:
  python network_scanner.py
  python network_scanner.py --range 192.168.1.0/24
  python network_scanner.py --threads 50
  python network_scanner.py --output hasil.txt
"""

import socket
import struct
import subprocess
import concurrent.futures
import argparse
import sys
import os
import re
from datetime import datetime

# ─────────────────────────────────────────────
# MAC VENDOR DATABASE (sebagian)
# ─────────────────────────────────────────────

MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:11": "Google",
    "00:17:F2": "Apple",
    "00:1C:B3": "Apple",
    "00:23:12": "Apple",
    "00:26:B9": "Dell",
    "00:14:22": "Dell",
    "00:21:70": "Dell",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:E0:4C": "Realtek",
    "00:1B:21": "Intel",
    "8C:8D:28": "Intel",
    "00:16:EA": "Intel",
    "18:CF:5E": "Qualcomm",
    "00:25:D3": "Samsung",
    "F4:7B:5E": "Samsung",
    "50:01:BB": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi",
    "00:90:4C": "Epson",
    "00:1D:0F": "ASUS",
    "04:92:26": "ASUS",
    "AC:22:0B": "ASUS",
    "00:08:22": "InPro",
    "E8:48:B8": "TP-Link",
    "54:AF:97": "TP-Link",
    "00:1D:7E": "Cisco",
    "00:1E:BE": "Cisco",
    "CC:46:D6": "Cisco",
    "00:50:BA": "D-Link",
    "00:19:5B": "D-Link",
    "1C:7E:E5": "D-Link",
    "00:90:A9": "Western Digital",
    "00:14:A5": "Gemtek (Router)",
    "00:26:5A": "Huawei",
    "00:E0:FC": "Huawei",
    "04:BD:88": "Huawei",
    "00:08:9F": "Netgear",
    "00:14:6C": "Netgear",
    "30:46:9A": "Netgear",
}

def get_vendor(mac: str) -> str:
    """Cari vendor dari 3 oktet pertama MAC address."""
    prefix = mac.upper()[:8]
    return MAC_VENDORS.get(prefix, "Unknown")


# ─────────────────────────────────────────────
# DETEKSI JARINGAN LOKAL
# ─────────────────────────────────────────────

def get_local_ip() -> str:
    """Dapatkan IP lokal perangkat ini."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"


def get_network_range(local_ip: str) -> str:
    """Generate range jaringan dari IP lokal (asumsi /24)."""
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def ip_range(network: str) -> list:
    """Generate list IP dari CIDR notation (hanya /24 didukung)."""
    base = network.split("/")[0]
    parts = base.split(".")
    prefix = ".".join(parts[:3])
    return [f"{prefix}.{i}" for i in range(1, 255)]


# ─────────────────────────────────────────────
# PING & ARP
# ─────────────────────────────────────────────

def ping(ip: str) -> tuple:
    """
    Ping sebuah IP.
    Return: (is_alive, response_time_ms)
    """
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", "500", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        start = datetime.now()
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2
        )
        elapsed = (datetime.now() - start).total_seconds() * 1000

        if result.returncode == 0:
            return True, round(elapsed, 1)
        return False, 0
    except Exception:
        return False, 0


def get_hostname(ip: str) -> str:
    """Resolve hostname dari IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_mac_from_arp(ip: str) -> str:
    """Ambil MAC address dari ARP table."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["arp", "-a", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3
            )
            output = result.stdout.decode("utf-8", errors="ignore")
            # Cari pola MAC address
            mac_pattern = re.compile(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}")
            match = mac_pattern.search(output)
            if match:
                mac = match.group().replace("-", ":")
                return mac.upper()
        else:
            result = subprocess.run(
                ["arp", "-n", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3
            )
            output = result.stdout.decode("utf-8", errors="ignore")
            mac_pattern = re.compile(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
            match = mac_pattern.search(output)
            if match:
                return match.group().upper()
    except Exception:
        pass
    return ""


# ─────────────────────────────────────────────
# SCAN SATU HOST
# ─────────────────────────────────────────────

def scan_host(ip: str) -> dict | None:
    """Scan satu IP address lengkap."""
    alive, rtt = ping(ip)
    if not alive:
        return None

    hostname = get_hostname(ip)
    mac = get_mac_from_arp(ip)
    vendor = get_vendor(mac) if mac else "Unknown"

    return {
        "ip": ip,
        "hostname": hostname or "(unknown)",
        "mac": mac or "(unknown)",
        "vendor": vendor,
        "rtt": rtt,
    }


# ─────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────

def print_device(device: dict, index: int):
    """Tampilkan info satu perangkat."""
    print(f"  ┌─ [{index:03d}] {device['ip']}")
    print(f"  │   Hostname : {device['hostname']}")
    print(f"  │   MAC      : {device['mac']}")
    print(f"  │   Vendor   : {device['vendor']}")
    print(f"  └─  Ping     : {device['rtt']} ms")
    print()


# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────

def run_scan(network: str, threads: int, output_path: str):
    print("=" * 55)
    print("  NETWORK SCANNER TOOL")
    print("  Untuk keperluan edukasi dan analisis jaringan.")
    print("=" * 55)

    local_ip = get_local_ip()
    if not network:
        network = get_network_range(local_ip)

    targets = ip_range(network)

    print(f"\n  IP Kamu    : {local_ip}")
    print(f"  Network    : {network}")
    print(f"  Target     : {len(targets)} host")
    print(f"  Threads    : {threads}")
    print(f"  Waktu      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n  Scanning...\n")
    print("─" * 55)

    found_devices = []
    scanned = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_host, ip): ip for ip in targets}

        for future in concurrent.futures.as_completed(futures):
            scanned += 1

            # Progress bar
            pct = int((scanned / len(targets)) * 40)
            bar = f"[{'█' * pct}{'░' * (40 - pct)}] {scanned}/{len(targets)}"
            print(f"\r  {bar}", end="", flush=True)

            result = future.result()
            if result:
                print()
                print_device(result, len(found_devices) + 1)
                found_devices.append(result)

    # Simpan ke file
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(f"Network Scanner Result\n")
            f.write(f"Network : {network}\n")
            f.write(f"Waktu   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total   : {len(found_devices)} perangkat\n\n")
            for i, d in enumerate(found_devices, 1):
                f.write(f"[{i:03d}] {d['ip']}\n")
                f.write(f"      Hostname : {d['hostname']}\n")
                f.write(f"      MAC      : {d['mac']}\n")
                f.write(f"      Vendor   : {d['vendor']}\n")
                f.write(f"      Ping     : {d['rtt']} ms\n\n")
        print(f"\n  📄 Hasil disimpan di: {output_path}")

    print(f"\n{'=' * 55}")
    print(f"  ✅ Selesai! Ditemukan {len(found_devices)} perangkat aktif.")
    print(f"  Selesai: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'=' * 55}\n")

    return found_devices


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="📡 Network Scanner — Educational Use Only",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Contoh:
  # Scan otomatis jaringan kamu
  python network_scanner.py

  # Scan range tertentu
  python network_scanner.py --range 192.168.0.0/24

  # Lebih cepat dengan banyak thread
  python network_scanner.py --threads 100

  # Simpan hasil
  python network_scanner.py --output perangkat.txt

PERINGATAN: Gunakan hanya pada jaringan milik sendiri!
        """
    )

    parser.add_argument("--range",   type=str, default=None, help="Range IP (contoh: 192.168.1.0/24)")
    parser.add_argument("--threads", type=int, default=50,   help="Jumlah thread (default: 50)")
    parser.add_argument("--output",  type=str, default=None, help="Simpan hasil ke file .txt")

    args = parser.parse_args()
    run_scan(args.range, args.threads, args.output)


if __name__ == "__main__":
    main()