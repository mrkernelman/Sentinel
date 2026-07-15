"""
Live Network Flow Collector
Captures packets from a network interface, groups them into flows,
computes the same 20 CICIDS2017 features, and runs IsolationForest detection.

Requirements:
  - Windows: Npcap installed (https://npcap.com), run Flask as Administrator
  - Linux/Mac: run as root or with CAP_NET_RAW
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import threading
import ipaddress
import numpy as np

try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def _is_local(ip: str) -> bool:
    """True for a real RFC1918 LAN unicast address — i.e. an actual device on
    this network, not an internet destination. Scan scope is devices on this
    network.

    Deliberately narrower than ipaddress.is_private: that flag is also True
    for 0.0.0.0/8 ("no address yet", the source DHCP clients use before they
    have a lease) and 255.255.255.255 (broadcast) — both of which are IANA
    special-purpose ranges, not real hosts. Without excluding them, DHCP
    negotiation packets (src 0.0.0.0 -> dst 255.255.255.255) sneak through
    the LAN-scoping check and get analyzed as a device-to-device flow,
    fabricating a bogus "device" with no real identity."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_unspecified or addr.is_loopback or addr.is_multicast or addr.is_reserved or addr.is_link_local:
        return False
    return addr.is_private


# Sentinel's own dashboard/API ports. Traffic here is this tool being used
# (a browser polling its own REST API every few seconds), not a Shadow IT
# flow — its bursty, repetitive shape looks nothing like CICIDS "benign"
# traffic and gets flagged by the model. Excluded from flow analysis; the
# device is still discovered via any of its other LAN packets.
_SELF_PORTS = {5000, 8080, 3000}


# ── Service-name extraction (SNI / HTTP Host) ──────────────────────────────────
# Names the destination service ("drive.google.com") instead of a raw IP.
# ~95% of traffic is TLS, but the ClientHello's Server Name Indication is sent
# in cleartext before encryption starts — no decryption involved.

def extract_sni(payload: bytes):
    """Server Name Indication from a TLS ClientHello, or None."""
    try:
        # TLS record type 0x16 (handshake) + handshake type 0x01 (ClientHello)
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 43                                   # record(5)+hs hdr(4)+ver(2)+random(32)
        pos += 1 + payload[pos]                    # session id
        pos += 2 + int.from_bytes(payload[pos:pos + 2], "big")   # cipher suites
        pos += 1 + payload[pos]                    # compression methods
        ext_end = pos + 2 + int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= min(ext_end, len(payload)):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len  = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0:                      # server_name extension
                name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                name = payload[pos + 5:pos + 5 + name_len]
                return name.decode("ascii", "ignore") or None
            pos += ext_len
    except (IndexError, ValueError):
        pass
    return None


_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def extract_http_host(payload: bytes):
    """Host header from a plaintext HTTP request, or None."""
    if not payload.startswith(_HTTP_METHODS):
        return None
    head = payload[:2048]
    i = head.find(b"\r\nHost:")
    if i < 0:
        return None
    j = head.find(b"\r\n", i + 7)
    host = head[i + 7 : j if j > 0 else len(head)].strip()
    return host.decode("ascii", "ignore") or None


# ── Hardware vendor lookup (MAC OUI) ────────────────────────────────────────────
# Best-effort NIC vendor from the MAC address's first 3 octets (IEEE OUI
# assignment) — gives the Devices page a real "hardware name" instead of a
# hardcoded "unknown" for every row. Not a full IEEE OUI database (that's
# 40k+ entries and would need periodic updates); a small curated set covering
# common corporate/lab hardware (VMs, major PC/network vendors). Unmatched
# prefixes fall back to "Unknown Device" — still better than nothing, and
# never wrong, since it's only ever a lookup, no guessing.
_OUI_VENDORS = {
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware", "00:1C:14": "VMware",
    "08:00:27": "VirtualBox", "0A:00:27": "VirtualBox", "00:15:5D": "Hyper-V",
    "52:54:00": "QEMU/KVM", "00:16:3E": "Xen",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi", "28:CD:C1": "Raspberry Pi",
    "3C:07:54": "Apple", "F0:18:98": "Apple", "AC:DE:48": "Apple", "A4:5E:60": "Apple", "DC:A4:CA": "Apple",
    "00:1B:63": "Apple", "28:E0:2C": "Apple", "70:56:81": "Apple",
    "00:14:22": "Dell", "D4:BE:D9": "Dell", "B0:83:FE": "Dell", "F8:B1:56": "Dell",
    "00:1F:29": "HP", "3C:D9:2B": "HP", "B4:B5:2F": "HP", "94:57:A5": "HP",
    "00:21:CC": "Lenovo", "54:EE:75": "Lenovo", "E4:B3:18": "Lenovo",
    "00:1B:21": "Intel", "34:13:E8": "Intel", "A0:C5:89": "Intel",
    "00:1A:2F": "Cisco", "00:26:99": "Cisco", "58:97:1E": "Cisco",
    "50:C7:BF": "TP-Link", "AC:84:C6": "TP-Link", "C0:25:E9": "TP-Link",
    "20:E5:2A": "Netgear", "A0:40:A0": "Netgear",
    "00:12:FB": "Samsung", "5C:0A:5B": "Samsung", "8C:71:F8": "Samsung",
    "00:E0:FC": "Huawei", "48:7B:6B": "Huawei",
    "34:2E:B7": "Amazon", "F0:27:2D": "Amazon",
    "3C:5A:B4": "Google", "F4:F5:E8": "Google",
    "FC:FC:48": "Microsoft", "60:45:BD": "Microsoft",
}


def vendor_for_mac(mac: str) -> str:
    """OUI-based vendor name for a MAC address, or 'Unknown Device'."""
    if not mac or len(mac) < 8:
        return "Unknown Device"
    return _OUI_VENDORS.get(mac[:8].upper(), "Unknown Device")


# ── Flow record ────────────────────────────────────────────────────────────────

class FlowRecord:
    """Tracks per-flow statistics matching CICIDS2017 feature columns."""

    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "src_mac",
        "start_time", "last_time",
        "fwd_lengths", "bwd_lengths", "all_lengths", "all_timestamps",
        "fin", "syn", "rst", "psh", "ack",
        "init_win_fwd", "init_win_bwd", "_win_fwd_set", "_win_bwd_set",
        "sni", "_sni_tries",
    )

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, ts, src_mac=""):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.src_mac  = src_mac

        self.start_time     = ts
        self.last_time      = ts
        self.all_timestamps = [ts]

        self.fwd_lengths = []
        self.bwd_lengths = []
        self.all_lengths = []

        self.fin = self.syn = self.rst = self.psh = self.ack = 0
        self.init_win_fwd = self.init_win_bwd = 0
        self._win_fwd_set = self._win_bwd_set = False
        self.sni        = None
        self._sni_tries = 0

    def try_hostname(self, payload: bytes):
        """Best-effort service-name extraction; handshakes arrive early, so
        only the first few payload-bearing packets are worth parsing."""
        if self.sni or self._sni_tries >= 10 or not payload:
            return
        self._sni_tries += 1
        self.sni = extract_sni(payload) or extract_http_host(payload)

    def add_packet(self, pkt_src_ip, length, ts, tcp_flags=0, window=0):
        is_fwd = (pkt_src_ip == self.src_ip)
        self.last_time = ts
        self.all_timestamps.append(ts)
        self.all_lengths.append(length)

        if is_fwd:
            self.fwd_lengths.append(length)
            if not self._win_fwd_set and window:
                self.init_win_fwd  = window
                self._win_fwd_set  = True
        else:
            self.bwd_lengths.append(length)
            if not self._win_bwd_set and window:
                self.init_win_bwd  = window
                self._win_bwd_set  = True

        self.fin += bool(tcp_flags & 0x01)
        self.syn += bool(tcp_flags & 0x02)
        self.rst += bool(tcp_flags & 0x04)
        self.psh += bool(tcp_flags & 0x08)
        self.ack += bool(tcp_flags & 0x10)

    def to_feature_dict(self) -> dict:
        dur_us   = max(1.0, (self.last_time - self.start_time) * 1_000_000)
        dur_s    = dur_us / 1_000_000

        n_fwd    = len(self.fwd_lengths) or 1
        n_bwd    = len(self.bwd_lengths) or 1
        n_all    = len(self.all_lengths)  or 1

        fwd_b    = sum(self.fwd_lengths)
        bwd_b    = sum(self.bwd_lengths)
        total_b  = fwd_b + bwd_b
        total_p  = len(self.fwd_lengths) + len(self.bwd_lengths)

        iats = []
        ts_s = sorted(self.all_timestamps)
        for i in range(1, len(ts_s)):
            iats.append((ts_s[i] - ts_s[i - 1]) * 1_000_000)  # µs
        iat_mean = float(np.mean(iats)) if iats else 0.0

        all_arr  = np.array(self.all_lengths, dtype=float) if self.all_lengths else np.array([0.0])

        return {
            # ── CICIDS features ────────────────────────────────────────────
            "Flow Duration":                  dur_us,
            "Total Fwd Packets":              len(self.fwd_lengths),
            "Total Backward Packets":         len(self.bwd_lengths),
            "Total Length of Fwd Packets":    fwd_b,
            "Total Length of Bwd Packets":    bwd_b,
            "Flow Bytes/s":                   total_b / dur_s,
            "Flow Packets/s":                 total_p / dur_s,
            "Fwd Packet Length Mean":         float(np.mean(self.fwd_lengths)) if self.fwd_lengths else 0.0,
            "Bwd Packet Length Mean":         float(np.mean(self.bwd_lengths)) if self.bwd_lengths else 0.0,
            "Flow IAT Mean":                  iat_mean,
            "Packet Length Mean":             float(all_arr.mean()),
            "Packet Length Std":              float(all_arr.std()),
            "FIN Flag Count":                 self.fin,
            "SYN Flag Count":                 self.syn,
            "RST Flag Count":                 self.rst,
            "PSH Flag Count":                 self.psh,
            "ACK Flag Count":                 self.ack,
            "Average Packet Size":            float(all_arr.mean()),
            "Init_Win_bytes_forward":         self.init_win_fwd,
            "Init_Win_bytes_backward":        self.init_win_bwd,
            # ── Display fields (not used by model) ─────────────────────────
            "Source IP":                      self.src_ip,
            "Destination IP":                 self.dst_ip,
            "Protocol":                       self.protocol,
            "src_mac":                        self.src_mac or "Live",
            "device_type":                    vendor_for_mac(self.src_mac),
            "sni":                            self.sni,
        }


# ── Collector ──────────────────────────────────────────────────────────────────

class NetworkCollector:
    """
    Singleton live-capture engine.

    Lifecycle:
      collector.start(iface)  → starts sniff thread + flush thread
      collector.stop()        → signals both threads to exit
      collector.pop_detections() → returns and clears pending anomalies
    """

    def __init__(self, flow_timeout: int = 15, flush_interval: int = 5):
        self.flow_timeout   = flow_timeout
        self.flush_interval = flush_interval

        self._flows:   dict  = {}
        self._lock           = threading.Lock()
        self._running        = False
        self._sniff_thread   = None
        self._flush_thread   = None

        self.packets_seen    = 0
        self.flows_analysed  = 0
        self.started_at      = None
        self._detections     = []
        self._errors         = []
        # First-seen device tracking -- separate from anomaly detection, so a
        # device shows up the moment it's seen at all, not only once/if one
        # of its flows gets flagged. Keyed by (src_ip, src_mac).
        self._known_devices     = {}
        self._new_device_events = []

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _flow_key(src_ip, dst_ip, src_port, dst_port, proto):
        """Canonical bidirectional key so A→B and B→A share the same record."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, proto)
        return (dst_ip, src_ip, dst_port, src_port, proto)

    def _process_packet(self, pkt):
        if not self._running:
            return
        if not pkt.haslayer(IP):
            return

        ip     = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        # Scope to this network: device discovery and anomaly detection are
        # about LAN devices, not the internet destinations they talk to.
        if not (_is_local(src_ip) and _is_local(dst_ip)):
            return

        self.packets_seen += 1
        proto   = ip.proto
        src_port = dst_port = flags = window = 0
        src_mac = ""

        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src

        ts = time.time()
        new_device = None
        with self._lock:
            dev_key = (src_ip, src_mac)
            if dev_key not in self._known_devices:
                new_device = {"src_ip": src_ip, "src_mac": src_mac, "first_seen": ts}
                self._known_devices[dev_key] = new_device
                self._new_device_events.append(new_device)
        # Persisted immediately (outside the lock, so a slow DB write never
        # blocks packet processing) instead of waiting for a frontend poll of
        # /api/scan/devices -- a device sighting is logged the moment it's
        # seen, whether or not anyone has the Live Scan page open.
        if new_device is not None:
            self._persist_device(new_device)

        payload = b""
        if pkt.haslayer(TCP):
            t        = pkt[TCP]
            src_port = t.sport
            dst_port = t.dport
            flags    = int(t.flags)
            window   = t.window
            payload  = bytes(t.payload)
        elif pkt.haslayer(UDP):
            u        = pkt[UDP]
            src_port = u.sport
            dst_port = u.dport

        if src_port in _SELF_PORTS or dst_port in _SELF_PORTS:
            return

        length = len(pkt)
        key    = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowRecord(
                    src_ip, dst_ip, src_port, dst_port, proto, ts, src_mac
                )
            flow = self._flows[key]
            flow.add_packet(src_ip, length, ts, flags, window)
            if payload:
                flow.try_hostname(payload)

    def _persist_device(self, device: dict):
        """Write a first-seen device straight to device_sightings. Called
        the moment a new device is observed, independent of anyone polling
        /api/scan/devices."""
        from backend.models.db_models import execute
        try:
            execute(
                """INSERT INTO device_sightings (src_ip, src_mac, source)
                   VALUES (%s, %s, 'live')
                   ON CONFLICT (src_ip, src_mac) DO UPDATE
                     SET last_seen = NOW(), sightings_count = device_sightings.sightings_count + 1""",
                (device["src_ip"], device["src_mac"]),
            )
        except Exception as exc:
            self._errors.append(f"device persist failed: {exc}")

    def _persist_detections(self, results: list):
        """Save flagged flows straight to the detections table. Called from
        the flush loop / flush_all so scans are logged in the background
        regardless of whether the Live Scan page is open or polling."""
        if not results:
            return
        from backend.models.db_models import execute
        for r in results:
            try:
                execute(
                    """INSERT INTO detections
                       (src_ip, src_mac, dst_domain, protocol,
                        bytes_sent, bytes_received, duration, device_type,
                        shadow_it_type, risk_level, anomaly_score, source)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'live')""",
                    (
                        r["src_ip"],
                        r.get("src_mac", "Live"),
                        r.get("dst_domain", r.get("Destination IP", "Unknown")),
                        r.get("protocol", "TCP"),
                        r.get("bytes_sent", 0),
                        r.get("bytes_received", 0),
                        r.get("duration", 0),
                        r.get("device_type", "unknown"),
                        r["shadow_it_type"],
                        r["risk_level"],
                        r["anomaly_score"],
                    ),
                )
            except Exception as exc:
                self._errors.append(f"detection persist failed: {exc}")

    def _flush_loop(self):
        from ml.model import detect

        while self._running:
            time.sleep(self.flush_interval)
            now      = time.time()
            to_flush = []

            with self._lock:
                expired = [k for k, f in self._flows.items()
                           if (now - f.last_time) >= self.flow_timeout]
                for k in expired:
                    to_flush.append(self._flows.pop(k))

            if not to_flush:
                continue

            records = [f.to_feature_dict() for f in to_flush]
            self.flows_analysed += len(records)

            try:
                results, _ = detect(records)
                if results:
                    self._persist_detections(results)
                    with self._lock:
                        self._detections.extend(results)
            except Exception as exc:
                self._errors.append(str(exc))
                print(f"[collector] detect() error: {exc}")

    def _sniff_loop(self, iface):
        try:
            sniff(
                iface=iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as exc:
            self._errors.append(str(exc))
            self._running = False
            print(f"[collector] sniff error: {exc}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self, iface: str = None):
        if self._running:
            return False, "Already running"
        if not SCAPY_AVAILABLE:
            return False, "Scapy is not installed. Run: pip install scapy"

        self._running       = True
        self.started_at     = time.time()
        self.packets_seen   = 0
        self.flows_analysed = 0
        self._detections    = []
        self._errors        = []
        self._flows         = {}
        self._known_devices     = {}
        self._new_device_events = []

        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, args=(iface,), daemon=True
        )
        self._sniff_thread.start()

        return True, "Started"

    def stop(self):
        self._running = False

    def status(self) -> dict:
        uptime = round(time.time() - self.started_at, 1) if self.started_at and self._running else 0
        return {
            "running":            self._running,
            "packets_seen":       self.packets_seen,
            "flows_analysed":     self.flows_analysed,
            "active_flows":       len(self._flows),
            "detections_found":   len(self._detections),
            "known_devices_count": len(self._known_devices),
            "uptime_s":           uptime,
            "errors":             self._errors[-5:],
        }

    def flush_all(self):
        """Force-analyse every active flow immediately, ignoring the idle timeout."""
        from ml.model import detect
        with self._lock:
            to_flush = list(self._flows.values())
            self._flows = {}

        if not to_flush:
            return 0

        records = [f.to_feature_dict() for f in to_flush]
        self.flows_analysed += len(records)
        try:
            results, _ = detect(records)
            if results:
                self._persist_detections(results)
                with self._lock:
                    self._detections.extend(results)
        except Exception as exc:
            self._errors.append(str(exc))
        return len(records)

    def pop_detections(self) -> list:
        with self._lock:
            d = list(self._detections)
            self._detections = []
            return d

    def pop_new_devices(self) -> list:
        with self._lock:
            d = list(self._new_device_events)
            self._new_device_events = []
            return d


# ── Helpers ────────────────────────────────────────────────────────────────────

def _routing_ip():
    """Local IP of the adapter that actually routes internet traffic.
    'Connecting' a UDP socket picks the outbound interface without sending
    a single packet. None if offline."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def list_interfaces() -> list[dict]:
    """
    Returns interfaces with human-readable descriptions instead of raw
    `\\Device\\NPF_{GUID}` paths, sorted so the adapter that routes internet
    traffic comes first (virtual adapters like Hyper-V switches also carry an
    IP, so "has an IP" alone is not enough — an alphabetical sort put a
    Hyper-V adapter above the real Wi-Fi one). Adapters with any routable
    IPv4 come next; pseudo/TAP adapters without one go last.
    `device` is the raw path Scapy's sniff(iface=...) needs.
    """
    if not SCAPY_AVAILABLE:
        return []
    try:
        routing_ip = _routing_ip()
        result = []
        for device, iface in conf.ifaces.items():
            description = getattr(iface, "description", "") or device
            ips4 = list(getattr(iface, "ips", {}).get(4, []))
            ip = next((a for a in ips4 if a and not a.startswith("169.254.")), None)
            result.append({"device": device, "description": description, "ip": ip})
        result.sort(key=lambda r: (r["ip"] != routing_ip or routing_ip is None,
                                   r["ip"] is None, r["description"]))
        return result
    except Exception:
        return get_if_list()


# ── Module-level singleton ─────────────────────────────────────────────────────
_instance: NetworkCollector | None = None


def get_collector() -> NetworkCollector:
    global _instance
    if _instance is None:
        _instance = NetworkCollector()
    return _instance
