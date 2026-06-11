"""Packet summarization & PCAP parsing — shared by live capture and file mode.

Every packet is reduced to a small JSON-friendly dict ("summary") that the
frontend turns into a vehicle. Heavy lifting (scapy) stays on this side.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import tempfile
from collections import Counter

from scapy.config import conf

conf.verb = 0

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.utils import PcapReader

# Port groups used for protocol classification (and lane mapping client-side).
# Order matters: first match wins when src and dst ports both look well-known.
PORT_CLASSES: list[tuple[str, set[int]]] = [
    ("DNS", {53, 5353, 5355}),
    ("HTTPS", {443, 8443}),          # includes QUIC (udp/443)
    ("HTTP", {80, 8080, 8000, 8008}),
    ("SSH", {22, 23}),
    ("RDP", {3389}),
    ("SMB", {445, 139, 137, 138}),
    ("FTP", {20, 21}),
    ("SNMP", {161, 162}),
    ("DHCP", {67, 68, 546, 547}),
    ("NTP", {123}),
    ("SYSLOG", {514, 6514}),
    ("VPN", {1194, 51820, 500, 4500}),
    ("MAIL", {25, 110, 143, 465, 587, 993, 995}),
]


def classify(transport: str, sport: int | None, dport: int | None) -> str:
    """Map transport + ports to a display protocol."""
    if transport == "ICMP":
        return "ICMP"
    ports = {p for p in (sport, dport) if p}
    if ports:
        for name, well_known in PORT_CLASSES:
            if ports & well_known:
                return name
    if transport in ("TCP", "UDP", "ARP"):
        return transport
    return "OTHER"


def infer_dir(src: str | None, dst: str | None, ref_ips: set[str]) -> str:
    """'out' = leaving the vantage point, 'in' = arriving at it."""
    if src and src in ref_ips:
        return "out"
    if dst and dst in ref_ips:
        return "in"
    try:
        s_priv = ipaddress.ip_address(src).is_private if src else False
        d_priv = ipaddress.ip_address(dst).is_private if dst else False
        if s_priv and not d_priv:
            return "out"
        if d_priv and not s_priv:
            return "in"
    except ValueError:
        pass
    return "out"


def summarize_packet(pkt: Packet, pid: int, ref_ips: set[str]) -> dict | None:
    """Reduce a scapy packet to the metadata the frontend needs."""
    try:
        ts = float(pkt.time)
        size = int(getattr(pkt, "wirelen", 0) or 0) or len(pkt)

        smac = dmac = None
        if Ether in pkt:
            smac, dmac = pkt[Ether].src, pkt[Ether].dst

        src = dst = None
        ttl = None
        proto_num = None
        transport = "OTHER"

        if IP in pkt:
            ip = pkt[IP]
            src, dst, ttl, proto_num = ip.src, ip.dst, int(ip.ttl), int(ip.proto)
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            src, dst, ttl, proto_num = ip6.src, ip6.dst, int(ip6.hlim), int(ip6.nh)
        elif ARP in pkt:
            arp = pkt[ARP]
            src, dst = arp.psrc, arp.pdst
            transport = "ARP"

        sport = dport = None
        flags = ""
        if TCP in pkt:
            t = pkt[TCP]
            transport = "TCP"
            sport, dport = int(t.sport), int(t.dport)
            flags = str(t.flags)
        elif UDP in pkt:
            u = pkt[UDP]
            transport = "UDP"
            sport, dport = int(u.sport), int(u.dport)
        elif ICMP in pkt or (proto_num in (1, 58)):
            transport = "ICMP"

        return {
            "id": pid,
            "ts": ts,
            "src": src,
            "dst": dst,
            "smac": smac,
            "dmac": dmac,
            "sport": sport,
            "dport": dport,
            "transport": transport,
            "proto": classify(transport, sport, dport),
            "size": size,
            "flags": flags,
            "ttl": ttl,
            "dir": infer_dir(src, dst, ref_ips),
        }
    except Exception:
        return None  # malformed frame — skip rather than kill the stream


def get_local_ips() -> set[str]:
    """Best-effort set of this host's addresses (used to orient live traffic)."""
    ips: set[str] = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0].split("%")[0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        from scapy.interfaces import get_working_ifaces

        for iface in get_working_ifaces():
            try:
                for fam in (4, 6):
                    for addr in iface.ips.get(fam, []):
                        ips.add(addr.split("%")[0])
            except Exception:
                continue
    except Exception:
        pass
    return ips


def parse_pcap_bytes(data: bytes, limit: int = 50_000) -> dict:
    """Parse a pcap/pcapng byte blob into a playback timeline.

    Streams via PcapReader (memory-safe), caps at `limit` packets, then infers
    the capture's vantage point (most frequent endpoint, private preferred) so
    in/out direction is meaningful even without knowing the capturing host.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    try:
        tmp.write(data)
        tmp.close()
        summaries: list[dict] = []
        truncated = False
        with PcapReader(tmp.name) as reader:
            for pkt in reader:
                if len(summaries) >= limit:
                    truncated = True
                    break
                s = summarize_packet(pkt, len(summaries), set())
                if s:
                    summaries.append(s)
    finally:
        os.unlink(tmp.name)

    if not summaries:
        raise ValueError("No parseable packets found in this capture.")

    counts: Counter[str] = Counter()
    for s in summaries:
        for addr in (s["src"], s["dst"]):
            if addr:
                counts[addr] += 1

    def is_private(a: str) -> bool:
        try:
            return ipaddress.ip_address(a).is_private
        except ValueError:
            return False

    private = [(a, c) for a, c in counts.most_common(20) if is_private(a)]
    vantage = private[0][0] if private else (counts.most_common(1)[0][0] if counts else None)
    ref = {vantage} if vantage else set()
    for s in summaries:
        s["dir"] = infer_dir(s["src"], s["dst"], ref)

    summaries.sort(key=lambda s: s["ts"])
    start, end = summaries[0]["ts"], summaries[-1]["ts"]
    return {
        "meta": {
            "count": len(summaries),
            "truncated": truncated,
            "limit": limit,
            "start": start,
            "end": end,
            "duration": max(end - start, 0.001),
            "vantage": vantage,
        },
        "packets": summaries,
    }


def list_interfaces() -> list[dict]:
    """Capture-capable interfaces for the live-mode dropdown."""
    out = []
    try:
        from scapy.interfaces import get_working_ifaces

        for iface in get_working_ifaces():
            try:
                addrs = []
                for fam in (4, 6):
                    addrs.extend(iface.ips.get(fam, []))
                out.append(
                    {
                        "id": iface.name,
                        "description": getattr(iface, "description", "") or iface.name,
                        "mac": getattr(iface, "mac", None),
                        "ips": addrs[:4],
                    }
                )
            except Exception:
                continue
    except Exception:
        pass
    return out
