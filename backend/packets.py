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
    ("SSH", {22}),  # telnet/23 deliberately falls through to plain TCP
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


try:
    from scapy.layers.inet6 import _ICMPv6  # base class of all ICMPv6 layers
except ImportError:  # pragma: no cover - very old scapy
    class _ICMPv6:  # type: ignore[no-redef]
        pass

from scapy.packet import NoPayload


def _find_l4(ip_layer):
    """First transport layer under the FIRST IP header.

    Walks IPv6 extension headers but stops at a nested IP layer, so tunneled
    traffic (GRE, 6in4, VXLAN…) is summarized by its OUTER header instead of
    mixing outer addresses with inner ports.
    """
    cur = ip_layer.payload
    for _ in range(8):
        if cur is None or isinstance(cur, (NoPayload, IP, IPv6)):
            return None
        if isinstance(cur, (TCP, UDP, ICMP, _ICMPv6)):
            return cur
        cur = cur.payload
    return None


def _extract_sni(raw: bytes) -> str | None:
    """Server name from a TLS ClientHello, if this payload starts one.

    Hand-rolled (no scapy TLS layer dependency): TLS record 0x16/0x03…,
    handshake type 0x01, walk session-id/ciphers/compression to the
    extensions and find server_name (type 0).
    """
    try:
        if len(raw) < 60 or raw[0] != 0x16 or raw[1] != 0x03 or raw[5] != 0x01:
            return None
        idx = 9          # record header (5) + handshake type/len (4)
        idx += 2 + 32    # client version + random
        idx += 1 + raw[idx]                                    # session id
        idx += 2 + int.from_bytes(raw[idx:idx + 2], "big")     # cipher suites
        idx += 1 + raw[idx]                                    # compression
        if idx + 2 > len(raw):
            return None
        ext_end = min(idx + 2 + int.from_bytes(raw[idx:idx + 2], "big"), len(raw))
        idx += 2
        while idx + 4 <= ext_end:
            ext_type = int.from_bytes(raw[idx:idx + 2], "big")
            ext_len = int.from_bytes(raw[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0 and idx + 5 <= ext_end:  # server_name
                name_len = int.from_bytes(raw[idx + 3:idx + 5], "big")
                name = raw[idx + 5:idx + 5 + name_len].decode("utf-8", "replace")
                return name[:120] or None
            idx += ext_len
    except Exception:
        pass
    return None


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
        ip_layer = None

        if IP in pkt:
            ip_layer = pkt[IP]
            src, dst, ttl, proto_num = ip_layer.src, ip_layer.dst, int(ip_layer.ttl), int(ip_layer.proto)
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
            src, dst, ttl, proto_num = ip_layer.src, ip_layer.dst, int(ip_layer.hlim), int(ip_layer.nh)
        elif ARP in pkt:
            arp = pkt[ARP]
            src, dst = arp.psrc, arp.pdst
            transport = "ARP"

        sport = dport = None
        flags = ""
        icmp_type = icmp_code = None
        seq = plen = None
        sni = None
        l4 = _find_l4(ip_layer) if ip_layer is not None else None
        if isinstance(l4, TCP):
            transport = "TCP"
            sport, dport = int(l4.sport), int(l4.dport)
            flags = str(l4.flags)
            seq = int(l4.seq)
            plen = len(l4.payload)
            if plen > 50 and 443 in (sport, dport):
                sni = _extract_sni(bytes(l4.payload))
        elif isinstance(l4, UDP):
            transport = "UDP"
            sport, dport = int(l4.sport), int(l4.dport)
        elif isinstance(l4, ICMP):
            transport = "ICMP"
            icmp_type, icmp_code = int(l4.type), int(l4.code)
        elif isinstance(l4, _ICMPv6):
            transport = "ICMP"
            icmp_type = int(getattr(l4, "type", 0) or 0)
            icmp_code = int(getattr(l4, "code", 0) or 0)
        elif ip_layer is not None and proto_num in (1, 58):
            transport = "ICMP"  # ICMP behind unparsed extension headers

        proto = classify(transport, sport, dport)
        if transport == "OTHER" and proto_num in (50, 51):
            proto = "VPN"  # IPsec ESP/AH

        # DNS transaction header — lets the frontend match queries to
        # responses and surface NXDOMAIN / SERVFAIL / timeouts
        dns_id = dns_qr = dns_rcode = None
        dns_qname = None
        if proto == "DNS" and l4 is not None:
            try:
                dns = l4.payload
                if dns is not None and dns.__class__.__name__ == "DNS":
                    dns_id = int(dns.id)
                    dns_qr = int(dns.qr)
                    dns_rcode = int(dns.rcode)
                    if dns.qd:
                        qname = dns.qd[0].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", "replace")
                        dns_qname = qname.rstrip(".")[:120]
            except Exception:
                pass  # malformed DNS — keep the packet, drop the extras

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
            "proto": proto,
            "size": size,
            "flags": flags,
            "ttl": ttl,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "dns_id": dns_id,
            "dns_qr": dns_qr,
            "dns_rcode": dns_rcode,
            "dns_qname": dns_qname,
            "seq": seq,
            "plen": plen,
            "sni": sni,
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
    """Parse a pcap/pcapng byte blob (writes to a temp file, then parses)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    try:
        tmp.write(data)
        tmp.close()
        return parse_pcap_path(tmp.name, limit)
    finally:
        os.unlink(tmp.name)


def parse_pcap_path(path: str, limit: int = 50_000) -> dict:
    """Parse a pcap/pcapng file into a playback timeline.

    Streams via PcapReader (memory-safe), caps at `limit` packets, then infers
    the capture's vantage point (most frequent endpoint, private preferred) so
    in/out direction is meaningful even without knowing the capturing host.
    """
    summaries: list[dict] = []
    truncated = False
    with PcapReader(path) as reader:
        for pkt in reader:
            if len(summaries) >= limit:
                truncated = True
                break
            s = summarize_packet(pkt, len(summaries), set())
            if s:
                summaries.append(s)

    if not summaries:
        raise ValueError("No parseable packets found in this capture.")

    counts: Counter[str] = Counter()
    for s in summaries:
        for addr in (s["src"], s["dst"]):
            if addr:
                counts[addr] += 1

    def is_vantage_candidate(a: str) -> bool:
        # broadcast/multicast/link-local addresses can dominate discovery-heavy
        # captures but can never be the capturing host
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            return False
        return not (
            ip.is_multicast or ip.is_link_local or ip.is_unspecified
            or a == "255.255.255.255"
        )

    def is_private(a: str) -> bool:
        try:
            return ipaddress.ip_address(a).is_private
        except ValueError:
            return False

    ranked = [(a, c) for a, c in counts.most_common(50) if is_vantage_candidate(a)]
    private = [(a, c) for a, c in ranked if is_private(a)]
    vantage = private[0][0] if private else (ranked[0][0] if ranked else None)
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
