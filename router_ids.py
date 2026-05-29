# ============================================================
# Smart Cart Router IDS — Alert System
# ============================================================

import dpkt
import pandas as pd
import numpy as np
from scipy.stats import entropy
from collections import defaultdict
import socket
import struct
import pickle
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# Configuration
# ============================================================

PCAP_FILE  = "/home/ulka/ns-allinone-3.40/" \
             "ns-3.40/smartcart-ap-32-0.pcap"
MODEL_FILE = "/home/ulka/ns-allinone-3.40/" \
             "ns-3.40/smartcart_rf_model.pkl"
WINDOW_SIZE = 1.0
THRESHOLD   = 0.50

# IP ranges
NORMAL_IPS   = {f"10.1.1.{i}" for i in range(2,22)}
ATTACKER_IPS = {f"10.1.1.{i}" for i in range(22,32)}
BG_IPS       = {"10.1.1.32","10.1.1.33"}
SERVER_IP    = "10.1.2.2"

# Attack phase labels
ATTACK_PHASES = [
    (80.0,  120.0, "Phase1-UDP-Small-Flood"),
    (140.0, 180.0, "Phase2-UDP-Large-Flood"),
    (195.0, 235.0, "Phase3-ICMP-Flood"),
    (225.0, 265.0, "Phase4-TCP-SYN-Flood"),
    (260.0, 290.0, "Phase5-TCP-ACK-Flood"),
]

# Normal event labels
NORMAL_EVENTS = [
    (80.0,  110.0, "Lunch-Rush"),
    (140.0, 180.0, "Firmware-Update"),
    (200.0, 230.0, "Evening-Rush"),
    (230.0, 260.0, "Store-Closing"),
    (260.0, 300.0, "Late-Night"),
]

def get_attack_phase(t):
    for start, end, name in ATTACK_PHASES:
        if start <= t <= end:
            return name
    return None

def get_normal_event(t):
    for start, end, name in NORMAL_EVENTS:
        if start <= t <= end:
            return name
    return "Normal-Baseline"

def get_cart_name(ip):
    last = int(ip.split('.')[-1])
    if 2 <= last <= 21:
        idx = last - 2
        scenarios = {
            0:'Regular-0', 1:'Regular-1',
            2:'Regular-2', 3:'Regular-3',
            4:'Quick-4',   5:'Quick-5',
            6:'Quick-6',   7:'Slow-7',
            8:'Slow-8',    9:'Slow-9',
            10:'Bulk-10',  11:'Bulk-11',
            12:'Checkout-12',13:'Checkout-13',
            14:'Idle-14',  15:'Idle-15',
            16:'Mixed-16', 17:'Mixed-17',
            18:'Boot-18',  19:'Boot-19',
        }
        return f"Normal-{scenarios.get(idx,idx)}"
    elif 22 <= last <= 31:
        return f"ATTACKER-Cart-{last-22}"
    elif last in [32,33]:
        return f"Background-{last-32}"
    return f"Unknown-{ip}"

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
    flow_duration  = timestamps[-1]-timestamps[0]
    relative_start = timestamps[0] - sim_start

    if flow_duration <= 0:
        flow_duration = WINDOW_SIZE

    iat_mean = float(np.mean(iats))
    iat_std  = float(np.std(iats))
    jitter   = float(np.mean(
        np.abs(np.diff(iats)))) \
        if len(iats) > 1 else 0.0

    pps          = len(pkts) / WINDOW_SIZE
    byte_rate    = sum(sizes) / WINDOW_SIZE
    avg_pkt_size = float(np.mean(sizes))
    syn_count    = sum(syn_flags)
    ack_count    = sum(ack_flags)
    protocol_type = max(
        set(protocols), key=protocols.count)

    sidp_entropy = calculate_entropy(
        [f"{src_ip}-{p}" for p in dst_ports])
    dpdi_entropy = calculate_entropy(
        [f"{p}-{d}" for p,d
         in zip(dst_ports, dst_ips)])

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
# Load model
# ============================================================

print("="*60)
print("Smart Cart Router IDS — Alert System")
print("="*60)

print("\nLoading trained RF model...")
model = pickle.load(open(MODEL_FILE, 'rb'))
print("Model loaded successfully")

FEATURES = [
    'iat_mean','iat_std','jitter',
    'pps','byte_rate','avg_pkt_size',
    'flow_duration','syn_count','ack_count',
    'protocol_type','sidp_entropy','dpdi_entropy'
]

# ============================================================
# Read pcap file
# ============================================================

print(f"\nReading pcap: {PCAP_FILE}")
print("Processing 1-second windows...")
print("="*60)

windows   = defaultdict(list)
sim_start = None
pkt_count = 0
seen      = set()

with open(PCAP_FILE, 'rb') as f:
    pcap      = dpkt.pcap.Reader(f)
    link_type = pcap.datalink()

    for ts, buf in pcap:
        pkt_count += 1

        ip = extract_ip_from_buf(buf, link_type)
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
            syn_flag = 1 if (flags&0x02) else 0
            ack_flag = 1 if (flags&0x10) else 0
        elif isinstance(ip.data, dpkt.udp.UDP):
            proto    = 0
            dst_port = ip.data.dport
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            proto = 2

        rel = ts - sim_start
        wid = int(rel / WINDOW_SIZE)
        windows[(src, wid)].append((
            ts, size, proto,
            dst_port, dst,
            syn_flag, ack_flag
        ))

del seen
print(f"Packets processed: {pkt_count:,}")
print(f"Windows created:   {len(windows):,}")

# ============================================================
# Process windows and generate alerts
# ============================================================

print("\nRunning IDS — generating alerts...")
print("="*60)

alerts          = []
false_positives = []
phase_first     = {}

sorted_windows = sorted(
    windows.items(),
    key=lambda x: x[1][0][0]
    if x[1] else 0)

for (src_ip, window_id), pkts \
        in sorted_windows:

    features = extract_features(
        pkts, src_ip, sim_start)
    if features is None:
        continue

    t = features['relative_time']

    # Prepare feature vector
    X = pd.DataFrame([features])[FEATURES]
    X = X.fillna(0).replace(
        [np.inf, -np.inf], 0)

    # Run model prediction
    prediction = model.predict(X)[0]
    confidence = model.predict_proba(X)[0][1]

    # Generate alert if attack detected
    if prediction == 1 and \
       confidence >= THRESHOLD:

        attack_phase = get_attack_phase(t)
        normal_event = get_normal_event(t)
        cart_name    = get_cart_name(src_ip)
        true_attack  = src_ip in ATTACKER_IPS \
                       and attack_phase is not None

        alert = {
            'time':         round(t, 2),
            'src_ip':       src_ip,
            'cart_name':    cart_name,
            'confidence':   round(confidence, 4),
            'attack_phase': attack_phase \
                            or 'Unknown',
            'store_event':  normal_event,
            'correct':      true_attack,
        }
        alerts.append(alert)

        # Track first detection per phase
        if attack_phase and \
           attack_phase not in phase_first:
            phase_first[attack_phase] = t
            print(f"  ALERT t={t:.2f}s "
                  f"{src_ip} "
                  f"{attack_phase} "
                  f"conf={confidence:.4f}")

        # Track false positives
        if not true_attack:
            false_positives.append(alert)

# ============================================================
# Summary
# ============================================================

print("\n" + "="*60)
print("DETECTION SUMMARY")
print("="*60)

print("\nPhase first detection times:")
for phase in [p[2] for p in ATTACK_PHASES]:
    if phase in phase_first:
        print(f"  {phase:<30} "
              f"t={phase_first[phase]:.2f}s "
              f"DETECTED")
    else:
        print(f"  {phase:<30} "
              f"NOT DETECTED")

print(f"\nTotal alerts generated: {len(alerts)}")
print(f"False positives:        "
      f"{len(false_positives)}")

# ============================================================
# Alert Log — first 20
# ============================================================

print("\n" + "="*60)
print("ALERT LOG — First 20 Alerts")
print("="*60)
print(f"{'Time':>6} {'IP':<15} "
      f"{'Cart':<20} "
      f"{'Conf':>6} "
      f"{'Phase':<30}")
print("-"*80)

for alert in alerts[:20]:
    print(f"{alert['time']:>6.1f} "
          f"{alert['src_ip']:<15} "
          f"{alert['cart_name']:<20} "
          f"{alert['confidence']:>6.4f} "
          f"{alert['attack_phase']:<30}")

# ============================================================
# Save alerts
# ============================================================

if alerts:
    alerts_df = pd.DataFrame(alerts)
    alerts_df.to_csv(
        'router_ids_alerts.csv', index=False)
    print(f"\nAlerts saved: "
          f"router_ids_alerts.csv")

print("\n" + "="*60)
print("Router IDS Complete")
print("="*60)
