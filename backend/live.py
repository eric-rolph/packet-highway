"""Live capture session management.

Each WebSocket client gets its own LiveSession: either a scapy AsyncSniffer
(real traffic) or the DemoStream (synthetic). Packet summaries are batched
every 100 ms so the browser receives a few messages per second instead of
one per packet.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import logging
import time

from fastapi import WebSocket, WebSocketDisconnect

from .packets import get_local_ips, summarize_packet
from .synth import DemoStream

log = logging.getLogger("packet-highway")

BATCH_INTERVAL = 0.1
QUEUE_CAP = 6000  # drop (but count) packets beyond this backlog
MAX_BATCH = 2000


_LOCAL_IPS: set[str] | None = None
_LOCAL_IPS_LOCK = asyncio.Lock()


async def _local_ips_cached() -> set[str]:
    """get_local_ips() can hit DNS / enumerate NICs — run it off-loop, once."""
    global _LOCAL_IPS
    if _LOCAL_IPS is None:
        async with _LOCAL_IPS_LOCK:
            if _LOCAL_IPS is None:
                _LOCAL_IPS = await asyncio.to_thread(get_local_ips)
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

    async def run(self) -> None:
        local_ips = await _local_ips_cached()
        await self.ws.send_text(json.dumps({
            "type": "hello",
            "mode": "demo" if self.demo else "live",
            "iface": self.iface,
            "bpf": self.bpf,
            "local_ips": sorted(local_ips),
        }))

        pump = asyncio.create_task(
            self._pump_demo() if self.demo else self._pump_sniffer(local_ips)
        )
        try:
            while True:
                await self.ws.receive_text()  # raises WebSocketDisconnect on close
        except WebSocketDisconnect:
            pass
        finally:
            pump.cancel()
            try:
                await pump
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("pump task failed")
            self._stop_sniffer()

    # ---------------------------------------------------------------- demo
    async def _pump_demo(self) -> None:
        stream = DemoStream()
        while True:
            await asyncio.sleep(BATCH_INTERVAL)
            items = stream.next_batch(time.time())
            for it in items:
                it["id"] = next(self.ids)
            if items:
                await self.ws.send_text(json.dumps({"type": "packets", "items": items}))

    # ---------------------------------------------------------------- real
    async def _pump_sniffer(self, local_ips: set[str]) -> None:
        loop = asyncio.get_running_loop()

        def on_packet(pkt):  # runs in scapy's sniffer thread
            s = summarize_packet(pkt, next(self.ids), local_ips)
            if s:
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
                await self.ws.send_text(json.dumps(msg))

    def _enqueue(self, summary: dict) -> None:
        if self.queue.qsize() >= QUEUE_CAP:
            self.dropped += 1
            return
        self.queue.put_nowait(summary)

    async def _send_error(self, message: str) -> None:
        log.warning("live session error: %s", message)
        try:
            await self.ws.send_text(json.dumps({"type": "error", "message": message}))
        except Exception:
            pass

    def _stop_sniffer(self) -> None:
        if self.sniffer is not None:
            try:
                self.sniffer.stop(join=False)
            except Exception:
                pass
            self.sniffer = None
