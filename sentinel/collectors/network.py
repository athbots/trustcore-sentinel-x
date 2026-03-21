"""
TrustCore Sentinel X — Network Traffic Collector

Uses scapy to sniff packets and aggregate them into per-flow statistics.
Falls back to psutil net_connections() if scapy/admin is unavailable.

Produces the standard 5-feature vector:
    [bytes_per_second, request_rate, payload_entropy, session_duration, port_risk_score]
"""
import asyncio
import math
import time
from collections import defaultdict

from sentinel.collectors.base import BaseCollector
from sentinel.config import NETWORK_POLL_INTERVAL

# High-risk destination ports (commonly targeted)
HIGH_RISK_PORTS = {
    20, 21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 1434,
    3306, 3389, 4444, 5900, 5985, 6379, 8080, 8443, 9200, 27017,
}


def _entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence, normalized to 0.0–1.0."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)
    return round(ent / 8.0, 4)  # normalize: max entropy of bytes = 8 bits


class _FlowKey:
    """Hashable 4-tuple identifying a network flow."""
    __slots__ = ("src", "dst", "dport", "proto")

    def __init__(self, src: str, dst: str, dport: int, proto: str):
        self.src = src
        self.dst = dst
        self.dport = dport
        self.proto = proto

    def __hash__(self):
        return hash((self.src, self.dst, self.dport, self.proto))

    def __eq__(self, other):
        return (self.src, self.dst, self.dport, self.proto) == (
            other.src, other.dst, other.dport, other.proto
        )


class _FlowStats:
    """Accumulates stats for a single flow within a polling window."""
    __slots__ = ("total_bytes", "packet_count", "payload_bytes", "start_time")

    def __init__(self):
        self.total_bytes = 0
        self.packet_count = 0
        self.payload_bytes = bytearray()
        self.start_time = time.time()


class NetworkCollector(BaseCollector):
    """
    Sniffs live network traffic with scapy, aggregates into per-flow
    feature vectors every `interval` seconds.

    If scapy is unavailable or admin rights are missing, falls back to
    psutil.net_connections() for connection-count-based monitoring.
    """

    def __init__(self, event_queue: asyncio.Queue, interval: float = NETWORK_POLL_INTERVAL):
        super().__init__(event_queue, interval)
        self._flows: dict[_FlowKey, _FlowStats] = {}
        self._sniffer = None
        self._scapy_available = False
        self._try_import_scapy()

    @property
    def collector_name(self) -> str:
        return "network"

    # ── scapy init ───────────────────────────────────────────────────────────

    def _try_import_scapy(self) -> None:
        try:
            from scapy.all import sniff, IP, TCP, UDP  # noqa: F401
            self._scapy_available = True
        except ImportError:
            self.logger.warning(
                "scapy not installed — falling back to psutil connection monitor. "
                "Install with: pip install scapy"
            )

    def start(self, loop) -> None:
        """Override to also start scapy sniffer thread if available."""
        super().start(loop)
        if self._scapy_available:
            self._start_sniffer()

    def _start_sniffer(self) -> None:
        """Start scapy async sniffer in background."""
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(
                prn=self._process_packet,
                store=False,
                filter="ip",
            )
            self._sniffer.start()
            self.logger.info("scapy packet sniffer started")
        except PermissionError:
            self.logger.warning(
                "Cannot start packet capture — admin/root privileges required. "
                "Falling back to psutil connection monitoring."
            )
            self._scapy_available = False
        except Exception as e:
            self.logger.warning(f"scapy sniffer failed: {e}. Falling back to psutil.")
            self._scapy_available = False

    def stop(self) -> None:
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        super().stop()

    # ── Packet processing (runs in sniffer callback) ─────────────────────────

    def _process_packet(self, pkt) -> None:
        """Called by scapy for each captured packet — accumulates flow stats."""
        try:
            from scapy.all import IP, TCP, UDP

            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")
            dport = 0
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                dport = pkt[UDP].dport

            key = _FlowKey(ip.src, ip.dst, dport, proto)

            if key not in self._flows:
                self._flows[key] = _FlowStats()

            stats = self._flows[key]
            stats.total_bytes += len(pkt)
            stats.packet_count += 1
            # Capture up to 2KB of payload for entropy calculation
            if hasattr(pkt, "load") and len(stats.payload_bytes) < 2048:
                stats.payload_bytes.extend(pkt.load[:512])

        except Exception:
            pass  # never crash the sniffer callback

    # ── collect_once (polling cycle) ─────────────────────────────────────────

    def collect_once(self) -> list[dict]:
        """
        Aggregate accumulated flow stats into feature vectors.
        Called every `interval` seconds by the base class loop.
        """
        if self._scapy_available:
            return self._collect_from_flows()
        else:
            return self._collect_from_psutil()

    def _collect_from_flows(self) -> list[dict]:
        """Convert accumulated scapy flows into event dicts."""
        events = []
        now = time.time()

        # Snapshot and reset flows
        flows = self._flows.copy()
        self._flows.clear()

        for key, stats in flows.items():
            duration = max(now - stats.start_time, 0.001)
            bytes_per_sec = stats.total_bytes / duration
            req_rate = stats.packet_count / duration
            entropy = _entropy(bytes(stats.payload_bytes))
            port_risk = 1.0 if key.dport in HIGH_RISK_PORTS else 0.0

            events.append({
                "source": "network",
                "event_type": "NETWORK_FLOW",
                "timestamp": now,
                "source_ip": key.src,
                "dest_ip": key.dst,
                "dest_port": key.dport,
                "protocol": key.proto,
                "features": [
                    round(bytes_per_sec, 2),
                    round(req_rate, 2),
                    entropy,
                    round(duration, 2),
                    port_risk,
                ],
                "metadata": {
                    "total_bytes": stats.total_bytes,
                    "packet_count": stats.packet_count,
                },
            })

        if events:
            self.logger.debug(f"Aggregated {len(events)} network flows")
        return events

    def _collect_from_psutil(self) -> list[dict]:
        """Fallback: monitor connections using psutil."""
        events = []
        now = time.time()

        try:
            import psutil
            connections = psutil.net_connections(kind="inet")

            # Group by remote address
            remote_counts: dict[str, int] = defaultdict(int)
            for conn in connections:
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_counts[remote_ip] += 1

            # Flag any remote IP with unusually many connections
            for remote_ip, count in remote_counts.items():
                if count >= 5:  # 5+ simultaneous connections = worth reporting
                    events.append({
                        "source": "network",
                        "event_type": "NETWORK_CONNECTIONS",
                        "timestamp": now,
                        "source_ip": "local",
                        "dest_ip": remote_ip,
                        "dest_port": 0,
                        "protocol": "TCP",
                        "features": [
                            0.0,          # bytes/s unknown in fallback
                            float(count), # use connection count as request_rate proxy
                            0.5,          # neutral entropy
                            0.0,          # duration unknown
                            0.0,          # port risk unknown
                        ],
                        "metadata": {
                            "connection_count": count,
                            "mode": "psutil_fallback",
                        },
                    })

        except Exception as e:
            self.logger.error(f"psutil fallback error: {e}")

        return events
