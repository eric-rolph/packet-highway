"""Packet Highway — FastAPI application.

Routes:
  GET  /api/interfaces   capture interfaces for the live-mode dropdown
  POST /api/pcap         upload a .pcap/.pcapng -> parsed playback timeline
  GET  /api/sample       synthetic 90 s capture, parsed (demo of PCAP mode)
  GET  /api/sample.pcap  the same capture as a downloadable pcap file
  WS   /ws/live          live packet stream (?iface=...&bpf=...&demo=1)
  /                      static frontend (zero-build Three.js app)

Security posture: the app is same-origin (the backend serves its own
frontend), so there is deliberately NO CORS middleware — browsers' default
same-origin policy keeps other websites away from the REST API. WebSockets
are not covered by that policy, so /ws/live enforces an Origin check itself
(otherwise any web page could quietly stream the user's live traffic).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, File, Query, Request, UploadFile, WebSocket
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .live import LiveSession
from .packets import list_interfaces, parse_pcap_bytes, parse_pcap_path
from .synth import build_sample_pcap_bytes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("packet-highway")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
MAX_UPLOAD = 250 * 1024 * 1024  # 250 MB
DEFAULT_LIMIT = 50_000

app = FastAPI(title="Packet Highway")


@app.middleware("http")
async def no_cache_frontend(request, call_next):
    """The frontend is served unbundled; force revalidation so edits show up."""
    response = await call_next(request)
    if not request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-cache"
    return response


async def _serialize(result: dict) -> Response:
    # timelines can be 200k packets — serialize off the event loop
    payload = await asyncio.to_thread(json.dumps, result)
    return Response(content=payload, media_type="application/json")


@app.get("/api/interfaces")
async def api_interfaces():
    return await asyncio.to_thread(list_interfaces)


@app.post("/api/pcap")
async def api_pcap(
    request: Request,
    file: UploadFile = File(...),
    limit: int = Query(DEFAULT_LIMIT, ge=100, le=200_000),
):
    # reject oversized uploads before buffering anything
    try:
        declared = int(request.headers.get("content-length") or 0)
    except ValueError:
        declared = 0
    if declared > MAX_UPLOAD + 1_048_576:
        return JSONResponse({"error": "File exceeds 250 MB limit."}, status_code=413)

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    path = tmp.name
    try:
        size = 0
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD:
                return JSONResponse({"error": "File exceeds 250 MB limit."}, status_code=413)
            tmp.write(chunk)
        tmp.close()
        if size == 0:
            return JSONResponse({"error": "Empty file."}, status_code=400)
        try:
            result = await asyncio.to_thread(parse_pcap_path, path, limit)
        except Exception as exc:
            log.exception("pcap parse failed")
            return JSONResponse({"error": f"Could not parse capture: {exc}"}, status_code=400)
        result["meta"]["filename"] = file.filename
        return await _serialize(result)
    finally:
        try:
            tmp.close()
        except Exception:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass


@app.get("/api/sample")
async def api_sample(limit: int = Query(DEFAULT_LIMIT, ge=100, le=200_000)):
    data = await asyncio.to_thread(build_sample_pcap_bytes)
    result = await asyncio.to_thread(parse_pcap_bytes, data, limit)
    result["meta"]["filename"] = "sample-traffic.pcap"
    return await _serialize(result)


@app.get("/api/sample.pcap")
async def api_sample_pcap():
    data = await asyncio.to_thread(build_sample_pcap_bytes)
    return Response(
        content=data,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment; filename=sample-traffic.pcap"},
    )


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _hostname(value: str | None) -> str:
    """Lowercased host portion of a Host header ('[::1]:8000' -> '::1')."""
    if not value:
        return ""
    value = value.strip().lower()
    if value.startswith("["):  # bracketed IPv6, maybe with port
        return value[1:].split("]", 1)[0]
    if value.count(":") == 1:  # host:port
        return value.split(":", 1)[0]
    return value  # bare hostname/IPv4, or raw IPv6 without port


def _origin_allowed(ws: WebSocket) -> bool:
    """Block cross-site WebSocket hijacking of the capture stream."""
    origin = ws.headers.get("origin")
    if not origin:
        return True  # non-browser clients (curl, scripts) send no Origin
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    origin_host = (parsed.hostname or "").lower()
    server_host = _hostname(ws.headers.get("host"))
    if origin_host and origin_host == server_host:
        return True
    return origin_host in _LOOPBACK_HOSTS and server_host in _LOOPBACK_HOSTS


@app.websocket("/ws/live")
async def ws_live(
    ws: WebSocket,
    iface: str | None = Query(None),
    bpf: str | None = Query(None),
    demo: int = Query(0),
):
    if not _origin_allowed(ws):
        log.warning("rejected cross-origin websocket from %s", ws.headers.get("origin"))
        await ws.close(code=1008)
        return
    await ws.accept()
    session = LiveSession(ws, iface=iface, bpf=bpf, demo=bool(demo))
    try:
        await session.run()
    except Exception:
        log.exception("live session crashed")


# Static frontend — mounted last so /api and /ws take precedence.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
