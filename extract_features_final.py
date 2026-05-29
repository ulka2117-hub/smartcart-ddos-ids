# ============================================================
# Smart Cart Feature Extraction Script
# ============================================================

import dpkt
import pandas as pd
import numpy as np
from scipy.stats import entropy
from collections import defaultdict
import socket
import struct
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# Configuration
# ============================================================

PCAP_FILE    = "/home/ulka/ns-allinone-3.40/" \
               "ns-3.40/smartcart-ap-32-0.pcap"
OUTPUT_FILE  = "/home/ulka/ns-allinone-3.40/" \
               "ns-3.40/smartcart_dataset_final.csv"
WINDOW_SIZE  = 1.0  # seconds

# IP ranges
NORMAL_IPS   = {f"10.1.1.{i}" for i in range(2,22)}
ATTACKER_IPS = {f"10.1.1.{i}" for i in range(22,32)}
BG_IPS       = {"10.1.1.32","10.1.1.33"}
SERVER_IP    = "10.1.2.2"

# Attack phase time windows
ATTACK_PHASES = [
    (80.0,  120.0),
    (140.0, 180.0),
    (195.0, 235.0),
    (225.0, 265.0),
    (260.0, 290.0),
]

def is_attack_time(t):
    for start, end in ATTACK_PHASES:
        if start <= t <= end:
            return True
    return False

# ============================================================
# Helper Functions
# ============================================================

def ip_to_str(addr):
    try:
        return socket.inet_ntoa(addr)
    except:
        return ""

def calculate_entropy(values):
    if len(values) == 0:
        return 0.0
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    probs = np.array(
        list(counts.values()), dtype=float)
    probs /= probs.sum()
    if len(probs) == 1:
        return 0.0
    return float(entropy(probs, base=2))

def extract_ip_from_buf(buf, link_type):
    try:
        if link_type == 1:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                return eth.data
            return None
        elif link_type == 127:
            if len(buf) < 4:
                return None
            rt_len = struct.unpack_from(
                '<H', buf, 2)[0]
            buf = buf[rt_len:]
            if len(buf) < 24:
                return None
            frame_ctrl = struct.unpack_from(
                '<H', buf, 0)[0]
            ftype = (frame_ctrl >> 2) & 0x3
            fsub  = (frame_ctrl >> 4) & 0xF
            if ftype != 2:
                return None
            hdr_len = 26 if fsub in \
                [8,9,10,11] else 24
            to_ds   = (frame_ctrl >> 8) & 0x1
            from_ds = (frame_ctrl >> 9) & 0x1
            if to_ds and from_ds:
                hdr_len += 6
            buf = buf[hdr_len:]
            if len(buf) < 8:
                return None
            if buf[0]==0xAA and buf[1]==0xAA:
                proto = struct.unpack_from(
                    '>H', buf, 6)[0]
                buf = buf[8:]
                if proto != 0x0800:
                    return None
            else:
                return None
            if len(buf) < 20:
                return None
            return dpkt.ip.IP(buf)
    except:
        return None
    return None

def extract_features(pkts, src_ip, sim_start):
    if len(pkts) < 2:
        return None

    pkts = sorted(pkts, key=lambda x: x[0])
    timestamps = [p[0] for p in pkts]
    sizes      = [p[1] for p in pkts]
    protocols  = [p[2] for p in pkts]
    dst_ports  = [p[3] for p in pkts]
    dst_ips    = [p[4] for p in pkts]
    syn_flags  = [p[5] for p in pkts]
    ack_flags  = [p[6] for p in pkts]

    iats = np.diff(timestamps)
    flow_duration  = timestamps[-1] - \
                     timestamps[0]
    relative_start = timestamps[0] - sim_start

    if flow_duration <= 0:
        flow_duration = WINDOW_SIZE

    # Timing features
    iat_mean = float(np.mean(iats))
    iat_std  = float(np.std(iats))
    jitter   = float(np.mean(
        np.abs(np.diff(iats)))) \
        if len(iats) > 1 else 0.0

    # Volume features
    pps          = len(pkts) / WINDOW_SIZE
    byte_rate    = sum(sizes) / WINDOW_SIZE
    avg_pkt_size = float(np.mean(sizes))

    # Protocol features
    syn_count     = sum(syn_flags)
    ack_count     = sum(ack_flags)
    protocol_type = max(
        set(protocols),
        key=protocols.count)

    # Entropy features
    sidp_entropy = calculate_entropy(
        [f"{src_ip}-{p}"
         for p in dst_ports])
    dpdi_entropy = calculate_entropy(
        [f"{p}-{d}"
         for p, d in zip(dst_ports, dst_ips)])

    return {
        'iat_mean':      iat_mean,
        'iat_std':       iat_std,
        'jitter':        jitter,
        'pps':           pps,
        'byte_rate':     byte_rate,
        'avg_pkt_size':  avg_pkt_size,
        'flow_duration': flow_duration,
        'syn_count':     syn_count,
        'ack_count':     ack_count,
        'protocol_type': protocol_type,
        'sidp_entropy':  sidp_entropy,
        'dpdi_entropy':  dpdi_entropy,
        'relative_time': relative_start,
        'src_ip':        src_ip,
    }

# ============================================================
# Read pcap file
# ============================================================

print(f"\nReading: {PCAP_FILE}")

windows   = defaultdict(list)
sim_start = None
pkt_count = 0
seen      = set()

with open(PCAP_FILE, 'rb') as f:
    pcap      = dpkt.pcap.Reader(f)
    link_type = pcap.datalink()

    for ts, buf in pcap:
        pkt_count += 1

        ip = extract_ip_from_buf(
            buf, link_type)
        if ip is None:
            continue

        try:
            src = ip_to_str(ip.src)
            dst = ip_to_str(ip.dst)
        except:
            continue

        if src == SERVER_IP:
            continue
        if src not in NORMAL_IPS and \
           src not in ATTACKER_IPS and \
           src not in BG_IPS:
            continue

        if sim_start is None:
            sim_start = ts

        size = len(buf)
        key  = (round(ts,6), src, dst, size)
        if key in seen:
            continue
        seen.add(key)

        proto    = -1
        dst_port = 0
        syn_flag = 0
        ack_flag = 0

        if isinstance(ip.data, dpkt.tcp.TCP):
            proto    = 1
            dst_port = ip.data.dport
            flags    = ip.data.flags
            syn_flag = 1 \
                if (flags & 0x02) else 0
            ack_flag = 1 \
                if (flags & 0x10) else 0
        elif isinstance(ip.data, dpkt.udp.UDP):
            proto    = 0
            dst_port = ip.data.dport
        elif isinstance(
                ip.data, dpkt.icmp.ICMP):
            proto = 2

        rel = ts - sim_start
        wid = int(rel / WINDOW_SIZE)
        windows[(src, wid)].append((
            ts, size, proto,
            dst_port, dst,
            syn_flag, ack_flag
        ))

del seen

# ============================================================
# Extract features and label windows
# ============================================================

print("\nExtracting features...")

dataset = []
normal_count  = 0
attack_count  = 0
skipped_count = 0

for (src_ip, window_id), pkts \
        in windows.items():

    features = extract_features(
        pkts, src_ip, sim_start)

    if features is None:
        skipped_count += 1
        continue

    t = features['relative_time']

    # Assign label
    if src_ip in ATTACKER_IPS and \
       is_attack_time(t):
        label = 1
        attack_count += 1
    else:
        label = 0
        normal_count += 1

    features['label'] = label
    dataset.append(features)

# ============================================================
# Save dataset
# ============================================================

df = pd.DataFrame(dataset)

# Reorder columns
cols = [
    'src_ip',
    'relative_time',
    'iat_mean',
    'iat_std',
    'jitter',
    'pps',
    'byte_rate',
    'avg_pkt_size',
    'flow_duration',
    'syn_count',
    'ack_count',
    'protocol_type',
    'sidp_entropy',
    'dpdi_entropy',
    'label'
]
df = df[cols]

df.to_csv(OUTPUT_FILE, index=False)


