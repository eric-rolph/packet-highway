"""Backend & API tests for Packet Highway."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app import app
from backend.packets import classify, infer_dir, parse_pcap_bytes
from backend.synth import build_sample_pcap_bytes


def test_classify_and_infer_dir():
    assert classify("TCP", 51234, 443) == "HTTPS"
    assert classify("UDP", 51234, 53) == "DNS"
    assert classify("TCP", 51234, 22) == "SSH"
    assert classify("ICMP", None, None) == "ICMP"
    assert classify("UDP", 51820, 51820) == "VPN"

    assert infer_dir("192.168.1.42", "1.1.1.1", {"192.168.1.42"}) == "out"
    assert infer_dir("1.1.1.1", "192.168.1.42", {"192.168.1.42"}) == "in"
    assert infer_dir("10.0.0.5", "8.8.8.8", set()) == "out"
    assert infer_dir("8.8.8.8", "10.0.0.5", set()) == "in"


def test_sample_pcap_generation_and_parse():
    blob = build_sample_pcap_bytes()
    assert len(blob) > 1000
    parsed = parse_pcap_bytes(blob, limit=5000)
    assert parsed["meta"]["count"] > 50
    assert parsed["meta"]["duration"] > 0
    protos = {p["proto"] for p in parsed["packets"]}
    assert "HTTPS" in protos or "DNS" in protos


def test_fastapi_routes_and_pcap_upload():
    client = TestClient(app)

    r_iface = client.get("/api/interfaces")
    assert r_iface.status_code == 200
    assert isinstance(r_iface.json(), list)

    r_sample = client.get("/api/sample?limit=500")
    assert r_sample.status_code == 200
    body = r_sample.json()
    assert body["meta"]["filename"] == "sample-traffic.pcap"
    assert len(body["packets"]) > 20

    r_pcap = client.get("/api/sample.pcap")
    assert r_pcap.status_code == 200
    raw_pcap = r_pcap.content
    assert len(raw_pcap) > 1000

    # Upload real pcap bytes back to POST /api/pcap
    r_up = client.post(
        "/api/pcap",
        files={"file": ("uploaded.pcap", raw_pcap, "application/vnd.tcpdump.pcap")},
    )
    assert r_up.status_code == 200
    up_body = r_up.json()
    assert up_body["meta"]["filename"] == "uploaded.pcap"
    assert up_body["meta"]["count"] > 20

    # Empty upload rejected cleanly with 400
    r_empty = client.post(
        "/api/pcap",
        files={"file": ("empty.pcap", b"", "application/octet-stream")},
    )
    assert r_empty.status_code == 400


def test_websocket_demo_stream():
    client = TestClient(app)
    with client.websocket_connect("/ws/live?demo=1") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        assert hello["mode"] == "demo"
        batch = ws.receive_json()
        assert batch["type"] == "packets"
        assert len(batch["items"]) >= 1


def test_browser_js_pcap_parser_cross_check(tmp_path):
    """Cross-verify frontend/src/browser_engine.js parses real Scapy PCAP bytes."""
    import shutil

    node = shutil.which("node")
    if not node:
        return
    pcap_file = tmp_path / "sample.pcap"
    pcap_file.write_bytes(build_sample_pcap_bytes())
    js_url = (ROOT / "frontend" / "src" / "browser_engine.js").as_uri()
    script = (
        f"import fs from 'node:fs';"
        f"import {{ parsePcapBuffer, generateSampleTimeline }} from {json.dumps(js_url)};"
        f"const buf = fs.readFileSync({json.dumps(str(pcap_file))});"
        f"const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);"
        f"const res = parsePcapBuffer(ab, 'sample.pcap');"
        f"const sim = generateSampleTimeline();"
        f"console.log(JSON.stringify({{ pcapCount: res.meta.count, simCount: sim.meta.count, vantage: res.meta.vantage }}));"
    )
    p = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, check=True)
    info = json.loads(p.stdout.strip())
    assert info["pcapCount"] > 50
    assert info["simCount"] > 100
    assert info["vantage"] is not None
