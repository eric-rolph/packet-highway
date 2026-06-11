"""Synthetic traffic model.

One generator feeds two things:
  * Demo live mode  — believable packet summaries streamed in real time
    (lets you see the visualization without Npcap/root).
  * Sample capture  — the same events rendered into REAL scapy packets and
    written to a pcap, then re-parsed through packets.py. This doubles as an
    end-to-end test of the parser.
"""
from __future__ import annotations

import os
import random
import tempfile
import threading
import time

from .packets import classify

HOME_IP = "192.168.1.50"
HOME_MAC = "aa:bb:cc:dd:ee:01"
GW_MAC = "aa:bb:cc:dd:ee:ff"

WEB_HOSTS = [
    "142.250.69.196", "104.16.132.229", "151.101.1.69", "13.107.42.14",
    "23.215.0.136", "172.217.14.99", "185.199.108.153", "52.84.151.39",
    "146.75.78.133", "34.117.41.85",
]
DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
SSH_HOST = "203.0.113.7"
NTP_HOST = "216.239.35.0"
ROUTER_IP = "192.168.1.1"
NAS_IP = "192.168.1.20"
RDP_HOST = "203.0.113.40"


def _ev(ts, src, dst, sport, dport, transport, size, flags="", ttl=None):
    out = src == HOME_IP
    return {
        "ts": ts,
        "src": src,
        "dst": dst,
        "smac": HOME_MAC if out else GW_MAC,
        "dmac": GW_MAC if out else HOME_MAC,
        "sport": sport,
        "dport": dport,
        "transport": transport,
        "proto": classify(transport, sport, dport),
        "size": size,
        "flags": flags,
        "ttl": ttl if ttl is not None else (64 if out else random.randint(48, 120)),
        "dir": "out" if out else "in",
    }


def gen_events(t0: float, duration: float, rng: random.Random) -> list[dict]:
    """Generate a sorted burst of correlated traffic events in [t0, t0+duration]."""
    ev: list[dict] = []

    def web_session(t: float):
        srv = rng.choice(WEB_HOSTS)
        cport = rng.randint(49152, 65000)
        port = 443 if rng.random() < 0.85 else 80
        # DNS lookup first
        dns = rng.choice(DNS_SERVERS)
        qp = rng.randint(49152, 65000)
        ev.append(_ev(t, HOME_IP, dns, qp, 53, "UDP", rng.randint(64, 96)))
        ev.append(_ev(t + rng.uniform(0.012, 0.07), dns, HOME_IP, 53, qp, "UDP", rng.randint(96, 280)))
        # TCP handshake
        t2 = t + rng.uniform(0.06, 0.16)
        rtt = rng.uniform(0.012, 0.06)
        ev.append(_ev(t2, HOME_IP, srv, cport, port, "TCP", 66, "S"))
        ev.append(_ev(t2 + rtt, srv, HOME_IP, port, cport, "TCP", 66, "SA"))
        ev.append(_ev(t2 + rtt * 1.5, HOME_IP, srv, cport, port, "TCP", 60, "A"))
        # Request out, response burst in
        t3 = t2 + rtt * 2
        ev.append(_ev(t3, HOME_IP, srv, cport, port, "TCP", rng.randint(250, 1100), "PA"))
        tr = t3 + rtt
        for _ in range(rng.randint(2, 9)):
            tr += rng.uniform(0.008, 0.05)
            ev.append(_ev(tr, srv, HOME_IP, port, cport, "TCP", rng.randint(620, 1514), "PA"))
            if rng.random() < 0.5:
                ev.append(_ev(tr + 0.004, HOME_IP, srv, cport, port, "TCP", 60, "A"))
        # Teardown
        if rng.random() < 0.6:
            ev.append(_ev(tr + rng.uniform(0.05, 0.4), HOME_IP, srv, cport, port, "TCP", 60, "FA"))
            ev.append(_ev(tr + rng.uniform(0.45, 0.6), srv, HOME_IP, port, cport, "TCP", 60, "FA"))
        elif rng.random() < 0.3:
            ev.append(_ev(tr + rng.uniform(0.05, 0.2), srv, HOME_IP, port, cport, "TCP", 60, "R"))

    def dns_only(t: float):
        dns = rng.choice(DNS_SERVERS)
        qp = rng.randint(49152, 65000)
        ev.append(_ev(t, HOME_IP, dns, qp, 53, "UDP", rng.randint(64, 110)))
        if rng.random() < 0.95:
            ev.append(_ev(t + rng.uniform(0.01, 0.09), dns, HOME_IP, 53, qp, "UDP", rng.randint(90, 420)))

    def ssh_chatter(t: float):
        cp = rng.randint(49152, 65000)
        tt = t
        for _ in range(rng.randint(2, 6)):
            tt += rng.uniform(0.02, 0.25)
            ev.append(_ev(tt, HOME_IP, SSH_HOST, cp, 22, "TCP", rng.randint(90, 220), "PA"))
            ev.append(_ev(tt + rng.uniform(0.02, 0.08), SSH_HOST, HOME_IP, 22, cp, "TCP", rng.randint(90, 360), "PA"))

    def ping(t: float):
        dst = rng.choice(WEB_HOSTS + DNS_SERVERS)
        ev.append(_ev(t, HOME_IP, dst, None, None, "ICMP", 74))
        ev.append(_ev(t + rng.uniform(0.01, 0.06), dst, HOME_IP, None, None, "ICMP", 74))

    def udp_noise(t: float):
        r = rng.random()
        if r < 0.3:  # NTP
            cp = rng.randint(49152, 65000)
            ev.append(_ev(t, HOME_IP, NTP_HOST, cp, 123, "UDP", 90))
            ev.append(_ev(t + rng.uniform(0.02, 0.08), NTP_HOST, HOME_IP, 123, cp, "UDP", 90))
        elif r < 0.7:  # QUIC-ish
            srv = rng.choice(WEB_HOSTS)
            cp = rng.randint(49152, 65000)
            ev.append(_ev(t, HOME_IP, srv, cp, 443, "UDP", rng.randint(120, 1350)))
            for i in range(rng.randint(1, 4)):
                ev.append(_ev(t + 0.02 + i * 0.015, srv, HOME_IP, 443, cp, "UDP", rng.randint(600, 1350)))
        else:  # random high-port datagram
            srv = f"198.51.100.{rng.randint(2, 250)}"
            ev.append(_ev(t, HOME_IP, srv, rng.randint(40000, 65000), rng.randint(10000, 60000), "UDP", rng.randint(80, 700)))

    def tcp_noise(t: float):
        srv = f"203.0.113.{rng.randint(2, 250)}"
        cp = rng.randint(49152, 65000)
        dp = rng.choice([8333, 6881, 5222, 1883, 9000, rng.randint(2000, 9999)])
        ev.append(_ev(t, HOME_IP, srv, cp, dp, "TCP", rng.randint(80, 600), "PA"))
        if rng.random() < 0.8:
            ev.append(_ev(t + rng.uniform(0.02, 0.1), srv, HOME_IP, dp, cp, "TCP", rng.randint(80, 900), "PA"))

    def smb_burst(t: float):
        # file copy to/from the NAS — chatty, large frames
        cp = rng.randint(49152, 65000)
        down = rng.random() < 0.5
        tt = t
        for _ in range(rng.randint(6, 20)):
            tt += rng.uniform(0.005, 0.03)
            if down:
                ev.append(_ev(tt, NAS_IP, HOME_IP, 445, cp, "TCP", rng.randint(1000, 1514), "PA"))
            else:
                ev.append(_ev(tt, HOME_IP, NAS_IP, cp, 445, "TCP", rng.randint(1000, 1514), "PA"))

    def snmp_poll(t: float):
        cp = rng.randint(49152, 65000)
        ev.append(_ev(t, HOME_IP, ROUTER_IP, cp, 161, "UDP", rng.randint(80, 140)))
        ev.append(_ev(t + rng.uniform(0.005, 0.03), ROUTER_IP, HOME_IP, 161, cp, "UDP", rng.randint(120, 400)))

    def rdp_session(t: float):
        cp = rng.randint(49152, 65000)
        tt = t
        for _ in range(rng.randint(3, 9)):
            tt += rng.uniform(0.03, 0.15)
            ev.append(_ev(tt, HOME_IP, RDP_HOST, cp, 3389, "TCP", rng.randint(100, 420), "PA"))
            ev.append(_ev(tt + rng.uniform(0.01, 0.05), RDP_HOST, HOME_IP, 3389, cp, "TCP", rng.randint(200, 1200), "PA"))

    def dhcp_renew(t: float):
        ev.append(_ev(t, HOME_IP, ROUTER_IP, 68, 67, "UDP", 342))
        ev.append(_ev(t + rng.uniform(0.01, 0.05), ROUTER_IP, HOME_IP, 67, 68, "UDP", 342))

    def filtered_syn(t: float):
        # SYN into a firewall black hole: retries, never answered -> half-open
        srv = rng.choice(WEB_HOSTS)
        cp = rng.randint(49152, 65000)
        dp = rng.choice([445, 25, 8443, 9100])
        ev.append(_ev(t, HOME_IP, srv, cp, dp, "TCP", 66, "S"))
        ev.append(_ev(t + 1.0, HOME_IP, srv, cp, dp, "TCP", 66, "S"))

    def refused_conn(t: float):
        # SYN answered by RST: port closed
        srv = rng.choice(WEB_HOSTS)
        cp = rng.randint(49152, 65000)
        dp = rng.choice([8081, 5000, 3000, 8888])
        ev.append(_ev(t, HOME_IP, srv, cp, dp, "TCP", 66, "S"))
        ev.append(_ev(t + rng.uniform(0.02, 0.08), srv, HOME_IP, dp, cp, "TCP", 60, "RA"))

    def scan_burst(t: float):
        # an external host probing us; we RST the closed ports
        scanner = f"198.51.100.{rng.randint(2, 250)}"
        tt = t
        for dp in rng.sample([21, 22, 23, 25, 80, 443, 445, 3389, 8080, 5900], rng.randint(4, 8)):
            tt += rng.uniform(0.02, 0.1)
            sp = rng.randint(40000, 65000)
            ev.append(_ev(tt, scanner, HOME_IP, sp, dp, "TCP", 66, "S"))
            if rng.random() < 0.7:
                ev.append(_ev(tt + rng.uniform(0.001, 0.01), HOME_IP, scanner, dp, sp, "TCP", 60, "RA"))

    actions = [(web_session, 0.32), (dns_only, 0.12), (ping, 0.06),
               (ssh_chatter, 0.07), (udp_noise, 0.12), (tcp_noise, 0.05),
               (smb_burst, 0.08), (snmp_poll, 0.07), (rdp_session, 0.04),
               (dhcp_renew, 0.02), (filtered_syn, 0.02), (refused_conn, 0.02),
               (scan_burst, 0.01)]
    t = t0
    end = t0 + duration
    while t < end:
        t += rng.expovariate(7.0)  # ~7 sessions/sec -> ~45 packets/sec average
        r = rng.random()
        acc = 0.0
        for fn, w in actions:
            acc += w
            if r <= acc:
                fn(t)
                break
    ev.sort(key=lambda e: e["ts"])
    return ev


class DemoStream:
    """Generates demo events pinned to the wall clock, consumed in batches."""

    def __init__(self):
        self.rng = random.Random()
        self.buf: list[dict] = []
        self.cursor = time.time()

    def next_batch(self, now: float) -> list[dict]:
        while self.cursor < now + 0.5:  # keep ~0.5 s of lookahead generated
            chunk = gen_events(self.cursor, 2.0, self.rng)
            self.buf.extend(chunk)
            self.buf.sort(key=lambda e: e["ts"])
            self.cursor += 2.0
        out = []
        i = 0
        while i < len(self.buf) and self.buf[i]["ts"] <= now:
            out.append(self.buf[i])
            i += 1
        del self.buf[:i]
        return out


_sample_lock = threading.Lock()
_sample_bytes: bytes | None = None


def build_sample_pcap_bytes(duration: float = 90.0, seed: int = 7) -> bytes:
    """Render the synthetic model into a genuine pcap file (cached)."""
    global _sample_bytes
    with _sample_lock:
        if _sample_bytes is not None:
            return _sample_bytes

        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw
        from scapy.utils import wrpcap

        rng = random.Random(seed)
        t0 = time.time() - duration
        events = gen_events(t0, duration, rng)
        pkts = []
        for e in events:
            eth = Ether(src=e["smac"], dst=e["dmac"])
            ip = IP(src=e["src"], dst=e["dst"], ttl=e["ttl"])
            if e["transport"] == "TCP":
                l4 = TCP(sport=e["sport"], dport=e["dport"], flags=e["flags"] or "PA")
            elif e["transport"] == "UDP":
                l4 = UDP(sport=e["sport"], dport=e["dport"])
            else:
                l4 = ICMP(type=8 if e["dir"] == "out" else 0)
            p = eth / ip / l4
            pad = e["size"] - len(p)
            if pad > 0:
                p = p / Raw(b"\x00" * pad)
            p.time = e["ts"]
            pkts.append(p)

        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        try:
            tmp.close()
            wrpcap(tmp.name, pkts)
            with open(tmp.name, "rb") as f:
                _sample_bytes = f.read()
        finally:
            os.unlink(tmp.name)
        return _sample_bytes
