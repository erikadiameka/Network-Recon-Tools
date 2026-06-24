"""
WiFi Analyzer Tool
===================
Menganalisis semua jaringan WiFi yang terdeteksi di sekitar.

Informasi yang ditampilkan:
  - SSID (nama WiFi)
  - BSSID (MAC address router)
  - Signal strength (dBm)
  - Channel
  - Frekuensi (2.4GHz / 5GHz)
  - Keamanan (WPA2, WPA3, Open)
  - Vendor router

KONSEP YANG DIPELAJARI:
  - subprocess    : jalankan command Windows dari Python
  - regex         : parsing teks mentah jadi data terstruktur
  - dBm           : satuan kekuatan sinyal WiFi
  - 2.4GHz vs 5GHz: perbedaan frekuensi WiFi

LEGAL NOTICE:
  - Tools ini hanya membaca sinyal WiFi yang sudah tersebar di udara
  - Tidak melakukan koneksi atau intrusi ke jaringan manapun
  - Legal digunakan di mana saja

Penggunaan:
  python wifi_analyzer.py
  python wifi_analyzer.py --output wifi.txt
  python wifi_analyzer.py --watch     (refresh otomatis tiap 5 detik)
"""

import subprocess
import re
import argparse
import sys
import time
import os
from datetime import datetime

# ─────────────────────────────────────────────
# MAC VENDOR DATABASE
# ─────────────────────────────────────────────

MAC_VENDORS = {
    "E8:48:B8": "TP-Link",
    "54:AF:97": "TP-Link",
    "00:50:BA": "D-Link",
    "1C:7E:E5": "D-Link",
    "00:26:5A": "Huawei",
    "04:BD:88": "Huawei",
    "00:08:9F": "Netgear",
    "30:46:9A": "Netgear",
    "AC:22:0B": "ASUS",
    "04:92:26": "ASUS",
    "50:01:BB": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi",
    "58:D9:D5": "Tenda",
    "C8:3A:35": "Tenda",
    "00:1D:7E": "Cisco",
    "CC:46:D6": "Cisco",
    "00:17:F2": "Apple",
    "00:1C:B3": "Apple",
    "00:25:D3": "Samsung",
    "F4:7B:5E": "Samsung",
    "B8:27:EB": "Raspberry Pi",
    "00:1A:11": "Google",
    "00:1B:21": "Intel",
}

def get_vendor(bssid: str) -> str:
    """Cari vendor dari 3 oktet pertama MAC address."""
    prefix = bssid.upper()[:8]
    return MAC_VENDORS.get(prefix, "Unknown")


# ─────────────────────────────────────────────
# SIGNAL STRENGTH HELPER
# ─────────────────────────────────────────────

def signal_bar(signal: int) -> str:
    """
    Konversi nilai dBm ke bar visual.
    
    Skala dBm WiFi:
    -30 dBm = luar biasa kuat (jarang terjadi)
    -50 dBm = sangat kuat
    -60 dBm = kuat
    -70 dBm = sedang
    -80 dBm = lemah
    -90 dBm = sangat lemah
    """
    if signal >= -50:
        return "████████ Sangat Kuat"
    elif signal >= -60:
        return "██████░░ Kuat"
    elif signal >= -70:
        return "████░░░░ Sedang"
    elif signal >= -80:
        return "██░░░░░░ Lemah"
    else:
        return "█░░░░░░░ Sangat Lemah"


def signal_quality(signal: int) -> int:
    """Konversi dBm ke persentase kualitas (0-100%)."""
    if signal <= -100:
        return 0
    elif signal >= -50:
        return 100
    else:
        return 2 * (signal + 100)


def frequency_band(channel: int) -> str:
    """
    Tentukan band frekuensi dari channel number.
    
    Channel 1-14  = 2.4 GHz (jangkauan luas, lebih lambat)
    Channel 36+   = 5 GHz   (jangkauan sempit, lebih cepat)
    """
    if channel <= 14:
        return "2.4 GHz"
    else:
        return "5 GHz"


def security_level(auth: str, cipher: str) -> str:
    """
    Evaluasi tingkat keamanan WiFi.
    
    WPA3     = paling aman (terbaru)
    WPA2     = aman (standar saat ini)
    WPA      = kurang aman (lama)
    WEP      = sangat tidak aman (mudah di-crack)
    Open     = berbahaya (tidak ada enkripsi!)
    """
    auth_upper = auth.upper()
    if "WPA3" in auth_upper:
        return "🟢 WPA3 (Sangat Aman)"
    elif "WPA2" in auth_upper:
        return "🟡 WPA2 (Aman)"
    elif "WPA" in auth_upper:
        return "🟠 WPA (Kurang Aman)"
    elif "WEP" in auth_upper:
        return "🔴 WEP (Tidak Aman!)"
    elif "OPEN" in auth_upper or auth_upper == "":
        return "🔴 OPEN (Berbahaya!)"
    else:
        return f"⚪ {auth}"


# ─────────────────────────────────────────────
# SCAN WIFI — WINDOWS
# ─────────────────────────────────────────────

def scan_wifi_windows() -> list:
    """
    Scan WiFi menggunakan command 'netsh' bawaan Windows.
    
    Command yang dijalankan:
      netsh wlan show networks mode=bssid
    
    Output mentah diparse dengan regex untuk
    mengekstrak info setiap jaringan WiFi.
    """
    try:
        # Jalankan command Windows untuk scan WiFi
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15
        )

        # Decode output dari bytes ke string
        output = result.stdout.decode("utf-8", errors="ignore")

        if not output or "There is no wireless interface" in output:
            return []

        networks = []
        # Split per jaringan (dipisah oleh "SSID")
        blocks = re.split(r"SSID \d+ :", output)[1:]

        for block in blocks:
            lines = block.strip().split("\n")

            # ── Parse setiap field dengan regex ──

            # SSID = nama WiFi
            ssid = lines[0].strip() if lines else "Hidden Network"

            # BSSID = MAC address router
            bssid_match = re.search(r"BSSID \d+\s*:\s*([\w:]+)", block)
            bssid = bssid_match.group(1).upper() if bssid_match else "Unknown"

            # Signal = kekuatan sinyal dalam persen (Windows pakai %)
            signal_match = re.search(r"Signal\s*:\s*(\d+)%", block)
            signal_pct = int(signal_match.group(1)) if signal_match else 0
            # Konversi % ke dBm (perkiraan)
            # Formula: dBm = (pct / 2) - 100
            signal_dbm = (signal_pct // 2) - 100

            # Radio type = 802.11n, 802.11ac, dll
            radio_match = re.search(r"Radio type\s*:\s*(.+)", block)
            radio = radio_match.group(1).strip() if radio_match else "Unknown"

            # Channel = nomor channel WiFi
            channel_match = re.search(r"Channel\s*:\s*(\d+)", block)
            channel = int(channel_match.group(1)) if channel_match else 0

            # Authentication = jenis keamanan
            auth_match = re.search(r"Authentication\s*:\s*(.+)", block)
            auth = auth_match.group(1).strip() if auth_match else "Unknown"

            # Cipher = jenis enkripsi
            cipher_match = re.search(r"Cipher\s*:\s*(.+)", block)
            cipher = cipher_match.group(1).strip() if cipher_match else "Unknown"

            networks.append({
                "ssid": ssid or "Hidden Network",
                "bssid": bssid,
                "signal_pct": signal_pct,
                "signal_dbm": signal_dbm,
                "radio": radio,
                "channel": channel,
                "auth": auth,
                "cipher": cipher,
                "vendor": get_vendor(bssid),
                "band": frequency_band(channel),
                "security": security_level(auth, cipher),
                "quality": signal_quality(signal_dbm),
            })

        # Urutkan dari sinyal terkuat ke terlemah
        networks.sort(key=lambda x: x["signal_pct"], reverse=True)
        return networks

    except FileNotFoundError:
        print("\n  [!] Command 'netsh' tidak ditemukan.")
        print("  Tools ini hanya bisa di Windows.\n")
        return []
    except Exception as e:
        print(f"\n  [!] Error saat scan: {e}\n")
        return []


# ─────────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────────

def display_networks(networks: list, show_detail: bool = True):
    """Tampilkan semua jaringan WiFi yang ditemukan."""

    if not networks:
        print("\n  [!] Tidak ada jaringan WiFi ditemukan.")
        print("  Pastikan WiFi adapter aktif.\n")
        return

    print(f"\n  Ditemukan {len(networks)} jaringan WiFi:\n")

    open_networks = []
    weak_security = []

    for i, net in enumerate(networks, 1):
        print(f"  ┌─ [{i:02d}] {net['ssid']}")

        if show_detail:
            print(f"  │   BSSID    : {net['bssid']} ({net['vendor']})")
            print(f"  │   Sinyal   : {net['signal_pct']}% ({net['signal_dbm']} dBm)")
            print(f"  │   Kualitas : {signal_bar(net['signal_dbm'])}")
            print(f"  │   Channel  : {net['channel']} ({net['band']})")
            print(f"  │   Radio    : {net['radio']}")
            print(f"  └─  Keamanan : {net['security']}")
        else:
            # Mode ringkas
            print(f"  │   {net['signal_pct']}% | CH{net['channel']} | {net['band']}")
            print(f"  └─  {net['security']}")

        print()

        # Kumpulkan jaringan berbahaya untuk peringatan
        if "OPEN" in net["auth"].upper() or net["auth"] == "":
            open_networks.append(net["ssid"])
        elif "WEP" in net["auth"].upper():
            weak_security.append(net["ssid"])

    # ── Peringatan keamanan ──
    if open_networks:
        print(f"  ⚠️  PERINGATAN — {len(open_networks)} jaringan TANPA enkripsi:")
        for ssid in open_networks:
            print(f"     🔴 '{ssid}' — Jangan konek! Data bisa disadap!")
        print()

    if weak_security:
        print(f"  ⚠️  PERINGATAN — {len(weak_security)} jaringan pakai WEP (mudah di-crack):")
        for ssid in weak_security:
            print(f"     🟠 '{ssid}'")
        print()

    # ── Statistik channel ──
    print("─" * 55)
    print("  📊 Statistik Channel:")
    channel_count = {}
    for net in networks:
        ch = net["channel"]
        channel_count[ch] = channel_count.get(ch, 0) + 1

    for ch, count in sorted(channel_count.items()):
        bar = "█" * count
        band = frequency_band(ch)
        print(f"  CH{ch:2d} ({band}): {bar} {count} jaringan")
    print()


def save_results(networks: list, output_path: str):
    """Simpan hasil scan ke file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"WiFi Analyzer Result\n")
        f.write(f"Waktu  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total  : {len(networks)} jaringan\n\n")
        for i, net in enumerate(networks, 1):
            f.write(f"[{i:02d}] {net['ssid']}\n")
            f.write(f"     BSSID    : {net['bssid']} ({net['vendor']})\n")
            f.write(f"     Sinyal   : {net['signal_pct']}% ({net['signal_dbm']} dBm)\n")
            f.write(f"     Channel  : {net['channel']} ({net['band']})\n")
            f.write(f"     Keamanan : {net['security']}\n\n")
    print(f"  📄 Hasil disimpan di: {output_path}\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def run_scan(output_path: str, watch: bool, interval: int):
    print("=" * 55)
    print("  WIFI ANALYZER TOOL")
    print("  Untuk keperluan edukasi dan analisis jaringan.")
    print("=" * 55)

    if watch:
        print(f"\n  Mode Watch aktif — refresh setiap {interval} detik")
        print(f"  Tekan Ctrl+C untuk berhenti\n")

    try:
        while True:
            if watch:
                os.system("cls" if sys.platform == "win32" else "clear")
                print("=" * 55)
                print("  WIFI ANALYZER — LIVE MODE")
                print(f"  Update: {datetime.now().strftime('%H:%M:%S')}")
                print("=" * 55)

            print(f"\n  🔍 Scanning WiFi...\n")
            networks = scan_wifi_windows()
            display_networks(networks)

            if output_path:
                save_results(networks, output_path)

            if not watch:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n  Dihentikan.\n")

    print(f"{'=' * 55}")
    print(f"  Selesai: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'=' * 55}\n")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="📡 WiFi Analyzer — Educational Use Only",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Contoh:
  # Scan sekali
  python wifi_analyzer.py

  # Simpan hasil ke file
  python wifi_analyzer.py --output wifi.txt

  # Mode live — refresh otomatis tiap 5 detik
  python wifi_analyzer.py --watch

  # Mode live dengan interval custom
  python wifi_analyzer.py --watch --interval 10
        """
    )

    parser.add_argument("--output",   type=str, default=None, help="Simpan hasil ke file .txt")
    parser.add_argument("--watch",    action="store_true",    help="Mode live — refresh otomatis")
    parser.add_argument("--interval", type=int, default=5,    help="Interval refresh dalam detik (default: 5)")

    args = parser.parse_args()
    run_scan(args.output, args.watch, args.interval)


if __name__ == "__main__":
    main()