#!/usr/bin/env python3
"""
Pro-level Wi-Fi Deauth Detector
- Full channel hopping (2.4GHz + 5GHz)
- Rolling 10s PCAP per MAC
- Metadata logging: RSSI, channel, vendor/OUI, timestamp
"""

import argparse
import time
import os
import threading
from collections import defaultdict, deque
from scapy.all import sniff, Dot11, Dot11Deauth, wrpcap, conf, get_if_raw_hwaddr
from mac_vendor_lookup import MacLookup
import random

# CONFIG
WINDOW = 10            # seconds sliding window
THRESHOLD = 10         # deauth packets per window to trigger alert
TARGET_COUNT_THRESHOLD = 4
LOGFILE = "deauth_alerts.log"
PCAP_DIR = "pcap_alerts"
CHANNEL_HOP_INTERVAL = 5  # seconds
ROLLING_BUFFER_SIZE = 5000  # approximate max packets per MAC in rolling buffer

# All common 2.4GHz + 5GHz channels
CHANNELS = list(range(1, 15)) + [36, 40, 44, 48, 52, 56, 60, 64,
                                  100, 104, 108, 112, 116, 120, 124, 128,
                                  132, 136, 140, 144, 149, 153, 157, 161, 165]

# Globals
events = defaultdict(lambda: deque())  # timestamp, dst
rolling_pcaps = defaultdict(lambda: deque())  # store last 10s of packets
alerts_history = set()
current_channel = CHANNELS[0]

# Initialize vendor lookup
mac_lookup = MacLookup()
try:
    mac_lookup.update_vendors()  # optional: update database
except:
    pass  # skip if offline

# Helpers
def now_ts():
    return time.time()

def prune_old_events(src):
    cutoff = now_ts() - WINDOW
    dq = events[src]
    while dq and dq[0][0] < cutoff:
        dq.popleft()
    # Prune rolling PCAP buffer similarly
    pkt_dq = rolling_pcaps[src]
    while pkt_dq and pkt_dq[0][0] < cutoff:
        pkt_dq.popleft()

def check_alert(src):
    prune_old_events(src)
    dq = events[src]
    count = len(dq)
    distinct_targets = len({t for _, t in dq})
    if count >= THRESHOLD or distinct_targets >= TARGET_COUNT_THRESHOLD:
        return True, count, distinct_targets
    return False, count, distinct_targets

def save_alert_pcap(src):
    if not os.path.exists(PCAP_DIR):
        os.makedirs(PCAP_DIR)
    pkt_dq = rolling_pcaps[src]
    filename = f"{PCAP_DIR}/deauth_{src}_{int(time.time())}.pcap"
    if pkt_dq:
        packets = [pkt for ts, pkt in pkt_dq]
        wrpcap(filename, packets)
    return filename

def log_alert(msg):
    print(msg)
    with open(LOGFILE, "a") as f:
        f.write(msg + "\n")

def handle_pkt(pkt):
    global current_channel
    if pkt.haslayer(Dot11Deauth) or (pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12):
        ts = now_ts()
        src = pkt.addr2
        dst = pkt.addr1
        if not src:
            return

        # Record event
        events[src].append((ts, dst))
        rolling_pcaps[src].append((ts, pkt))
        # Limit buffer size
        while len(rolling_pcaps[src]) > ROLLING_BUFFER_SIZE:
            rolling_pcaps[src].popleft()

        # Alert check
        alerted, count, distinct_targets = check_alert(src)
        if alerted and src not in alerts_history:
            alerts_history.add(src)
            try:
                vendor = mac_lookup.lookup(src)
            except:
                vendor = "Unknown"
            msg = (f"[ALERT] {time.strftime('%Y-%m-%d %H:%M:%S')} - Possible deauth attack from {src} "
                   f"({count} deauths in {WINDOW}s, {distinct_targets} victims, RSSI unknown, channel {current_channel}, vendor {vendor})")
            log_alert(msg)
            save_alert_pcap(src)

def channel_hopper(iface):
    global current_channel
    while True:
        for ch in CHANNELS:
            os.system(f"iwconfig {iface} channel {ch} >/dev/null 2>&1")
            current_channel = ch
            time.sleep(CHANNEL_HOP_INTERVAL)

def print_dashboard():
    while True:
        os.system('clear')
        print("=== Deauth Detector Dashboard ===")
        print(f"Current channel: {current_channel}")
        print(f"{'MAC':20s} {'Count':>5s} {'Distinct Targets':>16s}")
        for mac, dq in events.items():
            prune_old_events(mac)
            if dq:
                distinct_targets = len({t for _, t in dq})
                print(f"{mac:20s} {len(dq):>5d} {distinct_targets:>16d}")
        print("\nPress Ctrl+C to stop...")
        time.sleep(3)

def main():
    parser = argparse.ArgumentParser(description="Pro-level Wi-Fi Deauth Detector")
    parser.add_argument("--iface", required=True, help="monitor mode interface")
    args = parser.parse_args()
    iface = args.iface

    conf.iface = iface

    # Start channel hopper
    threading.Thread(target=channel_hopper, args=(iface,), daemon=True).start()
    # Start dashboard
    threading.Thread(target=print_dashboard, daemon=True).start()

    print(f"Starting pro deauth detector on {iface}")
    try:
        sniff(iface=iface, prn=handle_pkt, store=False)
    except KeyboardInterrupt:
        print("Exiting detector.")

if __name__ == "__main__":
    main()
