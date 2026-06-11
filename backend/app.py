"""Packet Highway — FastAPI application.

Routes:
  GET  /api/interfaces   capture interfaces for the live-mode dropdown
  POST /api/pcap         upload a .pcap/.pcapng -> parsed playback timeline
  GET  /api/sample       synthetic 90 s capture, parsed (demo of PCAP mode)
  GET  /api/sample.pcap  the same capture as a downloadable pcap file
  WS   /ws/live          live packet stream (?iface=...&bpf=...&demo=1)
  /                      static frontend (zero-build Three.js app)
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI, File, Query, UploadFile, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .live import LiveSession
from .packets import list_interfaces, parse_pcap_bytes
from .synth import build_sample_pcap_bytes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("packet-highway")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
MAX_UPLOAD = 250 * 1024 * 1024  # 250 MB
DEFAULT_LIMIT = 50_000

app = FastAPI(title="Packet Highway")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)


@app.middleware("http")
async def no_cache_frontend(request, call_next):
    """The frontend is served unbundled; force revalidation so edits show up."""
    response = await call_next(request)
    if not request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.get("/api/interfaces")
async def api_interfaces():
    return await asyncio.to_thread(list_interfaces)


@app.post("/api/pcap")
async def api_pcap(
    file: UploadFile = File(...),
    limit: int = Query(DEFAULT_LIMIT, ge=100, le=200_000),
):
    data = await file.read()
    if len(data) > MAX_UPLOAD:
        return JSONResponse({"error": "File exceeds 250 MB limit."}, status_code=413)
    if not data:
        return JSONResponse({"error": "Empty file."}, status_code=400)
    try:
        result = await asyncio.to_thread(parse_pcap_bytes, data, limit)
    except Exception as exc:
        log.exception("pcap parse failed")
        return JSONResponse({"error": f"Could not parse capture: {exc}"}, status_code=400)
    result["meta"]["filename"] = file.filename
    return result


@app.get("/api/sample")
async def api_sample(limit: int = Query(DEFAULT_LIMIT, ge=100, le=200_000)):
    data = await asyncio.to_thread(build_sample_pcap_bytes)
    result = await asyncio.to_thread(parse_pcap_bytes, data, limit)
    result["meta"]["filename"] = "sample-traffic.pcap"
    return result


@app.get("/api/sample.pcap")
async def api_sample_pcap():
    data = await asyncio.to_thread(build_sample_pcap_bytes)
    return Response(
        content=data,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment; filename=sample-traffic.pcap"},
    )


@app.websocket("/ws/live")
async def ws_live(
    ws: WebSocket,
    iface: str | None = Query(None),
    bpf: str | None = Query(None),
    demo: int = Query(0),
):
    await ws.accept()
    session = LiveSession(ws, iface=iface, bpf=bpf, demo=bool(demo))
    try:
        await session.run()
    except Exception:
        log.exception("live session crashed")


# Static frontend — mounted last so /api and /ws take precedence.
app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
