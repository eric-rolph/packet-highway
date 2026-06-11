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
NAS_MAC = "aa:bb:cc:dd:ee:02"
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

OK_NAMES = [
    "example.com", "github.com", "cdn.shopfast.net", "api.weather.io",
    "updates.win-svc.com", "img.newsfeed.org", "auth.cloudid.net",
    "static.vidstream.tv", "mail.corpbox.com", "tiles.mapper.app",
]
BAD_NAMES = ["githib.com", "exmaple.cmo", "old-service.internal", "dead.startup.app"]


# LAN devices have their own MACs; external hosts arrive via the gateway's.
_MAC_BY_IP = {HOME_IP: HOME_MAC, "192.168.1.20": NAS_MAC, "192.168.1.1": GW_MAC}


def _make_event(ts, src, dst, sport, dport, transport, size, flags, rng, ttl_map, dns=None):
    out = src == HOME_IP
    # one TTL per host per generation run — a flow's TTL never jitters
    if src not in ttl_map:
        ttl_map[src] = 64 if src in _MAC_BY_IP else rng.choice((49, 52, 55, 57, 59, 61, 113, 118, 243))
    icmp = transport == "ICMP"
    multicast = dst.startswith(("224.", "239.")) or dst == "255.255.255.255"
    return {
        "ts": ts,
        "src": src,
        "dst": dst,
        "smac": _MAC_BY_IP.get(src, GW_MAC),
        "dmac": "01:00:5e:7f:ff:fa" if multicast else _MAC_BY_IP.get(dst, GW_MAC),
        "sport": sport,
        "dport": dport,
        "transport": transport,
        "proto": classify(transport, sport, dport),
        "size": size,
        "flags": flags,
        "ttl": ttl_map[src],
        "icmp_type": (8 if out else 0) if icmp else None,
        "icmp_code": 0 if icmp else None,
        "dns_id": dns["id"] if dns else None,
        "dns_qr": dns["qr"] if dns else None,
        "dns_rcode": dns.get("rcode", 0) if dns else None,
        "dns_qname": dns.get("qname") if dns else None,
        "dir": "out" if out else "in",
    }


def gen_events(t0: float, duration: float, rng: random.Random) -> list[dict]:
    """Generate a sorted burst of correlated traffic events in [t0, t0+duration]."""
    ev: list[dict] = []
    ttl_map: dict[str, int] = {}

    def _ev(ts, src, dst, sport, dport, transport, size, flags="", dns=None):
        return _make_event(ts, src, dst, sport, dport, transport, size, flags, rng, ttl_map, dns)

    def dns_pair(t, qname=None, rcode=0, answered=True):
        """A DNS lookup: query out, (optionally) response back."""
        server = rng.choice(DNS_SERVERS)
        qp = rng.randint(49152, 65000)
        did = rng.randint(0, 65535)
        qname = qname or rng.choice(OK_NAMES)
        ev.append(_ev(t, HOME_IP, server, qp, 53, "UDP", rng.randint(64, 96),
                      dns={"id": did, "qr": 0, "qname": qname}))
        if answered:
            ev.append(_ev(t + rng.uniform(0.012, 0.07), server, HOME_IP, 53, qp, "UDP",
                          rng.randint(96, 280),
                          dns={"id": did, "qr": 1, "rcode": rcode, "qname": qname}))

    def web_session(t: float):
        srv = rng.choice(WEB_HOSTS)
        cport = rng.randint(49152, 65000)
        port = 443 if rng.random() < 0.85 else 80
        dns_pair(t)  # lookup precedes the connection
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
        # Teardown: 60% clean FIN exchange, 30% RST, 10% left open
        r = rng.random()
        if r < 0.6:
            tf = tr + rng.uniform(0.05, 0.4)
            ev.append(_ev(tf, HOME_IP, srv, cport, port, "TCP", 60, "FA"))
            ev.append(_ev(tf + rtt, srv, HOME_IP, port, cport, "TCP", 60, "FA"))
            ev.append(_ev(tf + rtt * 1.4, HOME_IP, srv, cport, port, "TCP", 60, "A"))
        elif r < 0.9:
            ev.append(_ev(tr + rng.uniform(0.05, 0.2), srv, HOME_IP, port, cport, "TCP", 60, "R"))

    def dns_only(t: float):
        dns_pair(t)

    def dns_fail(t: float):
        r = rng.random()
        if r < 0.5:    # typo / dead name
            dns_pair(t, qname=rng.choice(BAD_NAMES), rcode=3)
        elif r < 0.8:  # resolver/upstream failure
            dns_pair(t, rcode=2)
        else:          # resolver never answers
            dns_pair(t, answered=False)

    def ssdp_noise(t: float):
        # discovery multicast chatter (SSDP)
        ev.append(_ev(t, HOME_IP, "239.255.255.250", rng.randint(49152, 65000),
                      1900, "UDP", rng.randint(130, 380)))

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

    actions = [(web_session, 0.30), (dns_only, 0.11), (ping, 0.06),
               (ssh_chatter, 0.07), (udp_noise, 0.11), (tcp_noise, 0.05),
               (smb_burst, 0.08), (snmp_poll, 0.07), (rdp_session, 0.04),
               (dhcp_renew, 0.02), (filtered_syn, 0.02), (refused_conn, 0.02),
               (scan_burst, 0.01), (dns_fail, 0.03), (ssdp_noise, 0.01)]
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
_sample_cache: dict[tuple[float, int], bytes] = {}


def build_sample_pcap_bytes(duration: float = 90.0, seed: int = 7) -> bytes:
    """Render the synthetic model into a genuine pcap file (cached per args)."""
    key = (duration, seed)
    with _sample_lock:
        cached = _sample_cache.get(key)
        if cached is not None:
            return cached

        from scapy.layers.dns import DNS, DNSQR, DNSRR
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
            pad_to_size = True
            if e["transport"] == "TCP":
                l4 = TCP(sport=e["sport"], dport=e["dport"], flags=e["flags"] or "PA")
            elif e["transport"] == "UDP":
                l4 = UDP(sport=e["sport"], dport=e["dport"])
                if e.get("dns_id") is not None:
                    # real DNS header so the parser round-trip exercises it
                    qd = DNSQR(qname=e["dns_qname"] or "example.com")
                    if e["dns_qr"] == 0:
                        l4 = l4 / DNS(id=e["dns_id"], qr=0, rd=1, qd=qd)
                    else:
                        an = DNSRR(rrname=qd.qname, rdata="93.184.216.34") if e["dns_rcode"] == 0 else None
                        l4 = l4 / DNS(id=e["dns_id"], qr=1, rcode=e["dns_rcode"], qd=qd, an=an)
                    pad_to_size = False  # the DNS payload defines the size
            else:
                l4 = ICMP(type=8 if e["dir"] == "out" else 0)
            p = eth / ip / l4
            if pad_to_size:
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
                _sample_cache[key] = f.read()
        finally:
            os.unlink(tmp.name)
        return _sample_cache[key]
