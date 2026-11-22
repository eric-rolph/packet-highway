"""Live capture session management.

Each WebSocket client gets its own LiveSession: either a scapy AsyncSniffer
(real traffic) or the DemoStream (synthetic). Packet summaries are batched
every 100 ms so the browser receives a few messages per second instead of
one per packet. Supports live BPF filter hot-reload and rolling .pcap export
over the bidirectional WebSocket channel.
"""
from __future__ import annotations

import asyncio
import base64
import collections
import contextlib
import io
import itertools
import json
import logging
import threading
import time

from fastapi import WebSocket, WebSocketDisconnect

from .packets import get_local_ips, summarize_packet
from .synth import DemoStream

log = logging.getLogger("packet-highway")

BATCH_INTERVAL = 0.1
QUEUE_CAP = 6000  # drop (but count) packets beyond this backlog
MAX_BATCH = 2000
LOCAL_IPS_TTL_SECONDS = 60.0
PCAP_RING_CAP = 5000  # rolling raw packet buffer for live .pcap export


_LOCAL_IPS: set[str] | None = None
_LOCAL_IPS_TS: float = 0.0
_LOCAL_IPS_LOCK = asyncio.Lock()


async def _local_ips_cached() -> set[str]:
    """get_local_ips() can hit DNS / enumerate NICs — cache with a 60 s TTL."""
    global _LOCAL_IPS, _LOCAL_IPS_TS
    now = time.monotonic()
    if _LOCAL_IPS is None or (now - _LOCAL_IPS_TS) >= LOCAL_IPS_TTL_SECONDS:
        async with _LOCAL_IPS_LOCK:
            now = time.monotonic()
            if _LOCAL_IPS is None or (now - _LOCAL_IPS_TS) >= LOCAL_IPS_TTL_SECONDS:
                _LOCAL_IPS = await asyncio.to_thread(get_local_ips)
                _LOCAL_IPS_TS = time.monotonic()
    return _LOCAL_IPS


class LiveSession:
    def __init__(self, ws: WebSocket, iface: str | None, bpf: str | None, demo: bool):
        self.ws = ws
        self.iface = iface
        self.bpf = bpf
        self.demo = demo
        self.queue: asyncio.Queue[dict] = asyncio.Queue()
        self.dropped = 0
        self.ids = itertools.count()
        self.sniffer = None
        self._stopped = False
        self._send_lock = asyncio.Lock()
        self._ring_lock = threading.Lock()
        self._pcap_ring: collections.deque = collections.deque(maxlen=PCAP_RING_CAP)

    async def _send_json(self, payload: dict) -> None:
        async with self._send_lock:
            await self.ws.send_text(json.dumps(payload))

    async def run(self) -> None:
        local_ips = await _local_ips_cached()
        await self._send_json({
            "type": "hello",
            "mode": "demo" if self.demo else "live",
            "iface": self.iface,
            "bpf": self.bpf,
            "local_ips": sorted(local_ips),
        })

        pump = asyncio.create_task(
            self._pump_demo() if self.demo else self._pump_sniffer(local_ips)
        )
        try:
            while True:
                raw_msg = await self.ws.receive_text()  # raises WebSocketDisconnect on close
                pump = await self._handle_client_control(raw_msg, pump, local_ips)
        except WebSocketDisconnect:
            pass
        finally:
            self._stopped = True
            pump.cancel()
            try:
                await pump
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("pump task failed")
            self._stop_sniffer()

    async def _handle_client_control(
        self, raw_msg: str, pump: asyncio.Task, local_ips: set[str]
    ) -> asyncio.Task:
        """Handle optional control commands over the live WebSocket."""
        try:
            cmd = json.loads(raw_msg)
        except (json.JSONDecodeError, TypeError):
            return pump
        if not isinstance(cmd, dict):
            return pump

        msg_type = cmd.get("type")
        if msg_type == "set_filter" and not self.demo:
            new_bpf = (cmd.get("bpf") or "").strip() or None
            if new_bpf == self.bpf:
                return pump
            self.bpf = new_bpf
            pump.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await pump
            self._stop_sniffer()
            self._stopped = False
            while not self.queue.empty():
                with contextlib.suppress(asyncio.QueueEmpty):
                    self.queue.get_nowait()
            await self._send_json({"type": "filter_updated", "bpf": self.bpf})
            return asyncio.create_task(self._pump_sniffer(local_ips))

        if msg_type == "export_pcap":
            pcap_bytes = await asyncio.to_thread(self._serialize_ring_pcap)
            if not pcap_bytes:
                await self._send_error("No captured packets in live ring buffer to export.")
            else:
                await self._send_json({
                    "type": "pcap_export",
                    "filename": f"packet-highway-{int(time.time())}.pcap",
                    "packet_count": len(self._pcap_ring),
                    "data_base64": base64.b64encode(pcap_bytes).decode("ascii"),
                })
        return pump

    def _serialize_ring_pcap(self) -> bytes:
        with self._ring_lock:
            pkts = list(self._pcap_ring)
        if not pkts:
            return b""
        from scapy.utils import wrpcap

        buf = io.BytesIO()
        wrpcap(buf, pkts)
        return buf.getvalue()

    # ---------------------------------------------------------------- demo
    async def _pump_demo(self) -> None:
        stream = DemoStream()
        while True:
            await asyncio.sleep(BATCH_INTERVAL)
            items = stream.next_batch(time.time())
            for it in items:
                it["id"] = next(self.ids)
            if items:
                await self._send_json({"type": "packets", "items": items})

    # ---------------------------------------------------------------- real
    async def _pump_sniffer(self, local_ips: set[str]) -> None:
        loop = asyncio.get_running_loop()

        def on_packet(pkt):  # runs in scapy's sniffer thread
            if self._stopped:
                return
            with self._ring_lock:
                self._pcap_ring.append(pkt)
            s = summarize_packet(pkt, next(self.ids), local_ips)
            if s:
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(self._enqueue, s)

        try:
            from scapy.sendrecv import AsyncSniffer

            self.sniffer = AsyncSniffer(
                prn=on_packet,
                store=False,
                iface=self.iface or None,
                filter=self.bpf or None,
            )
            self.sniffer.start()
        except Exception as exc:
            await self._send_error(f"Capture failed to start: {exc}")
            return

        # The sniffer thread dies silently if Npcap/libpcap or privileges are
        # missing — detect that and tell the user instead of streaming nothing.
        await asyncio.sleep(0.8)
        thread = getattr(self.sniffer, "thread", None)
        if thread is not None and not thread.is_alive():
            await self._send_error(
                "Capture thread exited immediately. On Windows install Npcap "
                "(npcap.com) and run as Administrator; on Linux/macOS run with "
                "sudo or grant CAP_NET_RAW. Demo mode works without capture."
            )
            return

        while True:
            await asyncio.sleep(BATCH_INTERVAL)
            # the sniffer thread can die later too (NIC sleep/unplug, driver
            # error) — tell the client instead of streaming silence forever
            thread = getattr(self.sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                await self._send_error(
                    "Capture stopped: the sniffer thread exited "
                    "(interface down, driver error, or invalid filter)."
                )
                return
            items = []
            while not self.queue.empty() and len(items) < MAX_BATCH:
                items.append(self.queue.get_nowait())
            if items:
                msg = {"type": "packets", "items": items}
                if self.dropped:
                    msg["dropped"] = self.dropped
                await self._send_json(msg)

    def _enqueue(self, summary: dict) -> None:
        if self._stopped:
            return
        if self.queue.qsize() >= QUEUE_CAP:
            self.dropped += 1
            return
        self.queue.put_nowait(summary)

    async def _send_error(self, message: str) -> None:
        log.warning("live session error: %s", message)
        with contextlib.suppress(Exception):
            await self._send_json({"type": "error", "message": message})

    def _stop_sniffer(self) -> None:
        self._stopped = True
        if self.sniffer is not None:
            with contextlib.suppress(Exception):
                self.sniffer.stop(join=False)
            self.sniffer = None
