# Packet Highway

<a href="https://youtu.be/A6Bwlk_j62g" target="_blank">
  <img src="https://img.youtube.com/vi/A6Bwlk_j62g/maxresdefault.jpg" alt="Watch the video" width="600" />
</a>

**A 3D network traffic visualizer.** Packets become vehicles on a divided highway:
inbound traffic drives one way, outbound the other, and each lane carries a class
of service (web, DNS, management, infrastructure, file transfer…). Watch your
network live, or replay a `.pcap` with full scrub/seek control.

Built with **FastAPI + Scapy** on the backend and **Three.js** (zero-build,
vanilla ES modules) on the frontend. Demo video above.

---

## The metaphor

| Traffic | Vehicle | Why |
|---|---|---|
| DNS | motorcycles | small, fast, weaving queries |
| HTTP / HTTPS | vans & trucks | payload carriers — length scales with bytes |
| SMB / FTP / VPN / MAIL | cargo vans | file & tunnel freight |
| SSH / RDP / other TCP | sedans | interactive sessions |
| ICMP | **police cars** (red/blue strobes) | the network's patrol & diagnostics |
| TCP SYN / SYN-ACK / FIN / RST | gray cars with colored strobes | control plane made visible |
| UDP (DHCP, NTP, SNMP, syslog, QUIC…) | **drones** | connectionless — never touches the road |
| ARP & other L2 | maintenance carts | slow housekeeping vehicles |
| Packet bursts | **convoy road-trains** | one long hauler = N packets (click for the breakdown) |

Direction is physical: the right side of the road flows **inbound** toward the
glowing `LOCALHOST` gate; the left side flows **outbound** toward `INTERNET`.

### Density: how packets become bandwidth

At low rates you see literal packets. Each lane enforces a minimum admission
headway; when a burst exceeds what a lane can admit, the burst is merged into a
single **convoy** scaled by packet count — the same shift from packet-level to
flow-level view that tools like sFlow/NetFlow make at scale. **Every packet is
always counted in the dashboard stats**; only the visual aggregates. The
`MERGED` HUD counter tells you how many packets rode in convoys.

### A timing-faithful road (and why vehicles never collide)

Every vehicle in a lane moves at the **lane's constant speed**, so a vehicle's
distance from its entry gate is exactly *(now − arrival time) × lane speed*:
the road is a scrolling timeline, and the spacing between same-lane vehicles
is their **real inter-arrival spacing**. Packets don't brake, and neither do
vehicles — because same-lane speeds never differ, overtaking (the only way
vehicles could ghost through each other) is geometrically impossible.

Collisions are avoided purely at admission: a packet arriving while the
previous one still occupies the entry takes the parallel **sub-lane** (each
lane is two files of traffic); when both files are occupied, the burst rides
as a **convoy** (log-scaled by packet count — engineers think in orders of
magnitude). UDP drones are airborne and separate by altitude instead.

### DNS health

DNS gets the same treatment as TCP: queries are matched to responses by
transaction id, and the panel tracks **resolved / NXDOMAIN / SERVFAIL /
timeouts** plus median lookup latency. Failed lookups ride as **red
motorcycles**, and shoulder flares stack per failing *name* (NXDOMAIN) or
per *resolver* (SERVFAIL/timeout) — one broken domain = one growing stack.
Multicast discovery queries (mDNS/SSDP) are exempt from timeout tracking
(they're unanswered by design); broadcast/multicast frames are counted in the
dashboard and a storm warning fires if they exceed 50/s. In PCAP mode the
scrubber histogram is **stacked by lane** (same colors as the road) with
red/amber **tick marks at RSTs and DNS failures** — scrub straight to the
anomaly.

### Is something wrong? (glanceability)

A **NETWORK STATUS pill** sits above the dashboard: green / amber / red with
the reason ("TCP connections failing", "DNS failures", "packet loss",
"broadcast storm", "view incomplete"), judged over the **last 60 seconds** so
old incidents age out. Failures are physical on the road too: failed
connections and lookups become **breakdowns** — tilted cars with blinking
hazards on the shoulder (amber = no answer, red = refused/bad name), growing
when the same target keeps failing. Convoys carry floating **×N labels**, and
each lane has a **utilization glow** that brightens with load, so bursts read
as literal lane heat. Every health number is **clickable** — half-open,
refused, RST, retransmissions, NXDOMAIN, SERVFAIL, timeouts each open a
recent-evidence list (which targets, how many times). Clicking a **Top
Talker** spotlights everything touching that host.

### TCP telemetry

Beyond the failure counters, the flow tracker passively measures **handshake
RTT** (SYN→SYN-ACK, median/p95 in the TCP HEALTH panel), counts **SYN
retries** (kernel retransmit schedules de-duplicated so one dead connect()
isn't counted as several failures), and detects **retransmissions** by
tracking sequence numbers — a data segment ending at-or-before the highest
seen end is the same truck making the trip twice, tinted red. TCP control
packets ride as whole-body **flag-colored cars**: amber = opening (SYN),
green = accepted (SYN-ACK), purple = closing (FIN), red = reset (RST).
**TLS SNI** is extracted from ClientHellos, so clicking an HTTPS vehicle
shows *which* server name the connection is for. Clicking any vehicle (or
breakdown) **spotlights its whole conversation**: every vehicle in that
4-tuple keeps its color while the rest of the road dims.

### TCP handshake troubleshooting

The flow tracker matches every `SYN` against its `SYN-ACK`:

* ✅ **established** — handshake completed
* ⚠️ **half-open** — SYN never answered (filtered port, dead host, or a scanner) → an **amber flare** appears on the shoulder
* ⛔ **refused** — SYN answered by RST (closed port) → a **red flare**
* **RST seen** — all resets, including mid-session aborts

Flares are clickable: the detail panel shows who tried to reach what, when, and
why it likely failed. The TCP HEALTH panel keeps a running success ratio.

---

## Quick start

Requires **Python 3.10+**. No Node/npm needed — the frontend is served by the
backend and loads Three.js from a pinned CDN (internet required on first load).

```bash
git clone https://github.com/eric-rolph/packet-highway
cd packet-highway

# create a venv and install
python -m venv .venv
# Windows:
.venv\Scripts\pip install -r backend/requirements.txt
# macOS / Linux:
.venv/bin/pip install -r backend/requirements.txt

# run
# Windows:
.venv\Scripts\python run.py
# macOS / Linux:
.venv/bin/python run.py
```

Open **http://127.0.0.1:8000** and either:

* **LIVE** → pick *Demo traffic* (works everywhere, no capture rights needed), or a real interface,
* **PCAP** → *Load sample capture*, or upload your own `.pcap` / `.pcapng`.

### Live capture of real traffic

| OS | Requirement |
|---|---|
| **Windows** | Install [Npcap](https://npcap.com) (WinPcap-compatible mode). Run the server from an elevated terminal if capture fails. |
| **macOS** | `sudo .venv/bin/python run.py` (or grant your terminal access to BPF devices). |
| **Linux** | `sudo .venv/bin/python run.py`, or grant the capability: `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)` |

An optional **BPF filter** (e.g. `tcp port 443`, `host 192.168.1.50`) limits
what the sniffer captures. If capture can't start, the UI explains why — demo
mode and PCAP mode never need privileges.

---

## UI guide

* **Drag** to orbit · **scroll** to zoom · **click any vehicle/breakdown** for details
* **Camera presets**: `1` overview · `2` top-down (lanes become a barcode
  timeline — same-lane spacing is literal inter-arrival time) · `3` gate cam
* The look is full night-highway: ACES tone mapping + bloom, headlights/
  taillights on every vehicle (white = coming at you, red = leaving — a
  direction cue, not just decoration), image-based lighting on bodies/glass,
  starfield, glowing gates, and per-lane utilization glow
* **PCAP mode**: histogram scrubber with per-bucket packet counts, play/pause
  (`Space`), seek (`←`/`→`), speeds 0.25×–16×
* **Dashboard**: in/out bandwidth + 60 s sparkline, protocol distribution,
  TCP handshake health, top talkers — all computed over a rolling window on
  whichever clock drives the scene (wall clock live, capture clock in replay)
* **HUD**: FPS, active vehicles, packets/sec, merged-into-convoy count

## Architecture

```
backend/  (Python)
  app.py       FastAPI: REST + WebSocket + static frontend
  live.py      per-client capture sessions (scapy AsyncSniffer), 100 ms batches
  packets.py   packet → JSON summary, protocol classification, pcap parsing,
               vantage-point inference for uploaded captures
  synth.py     synthetic traffic model → demo stream AND the sample .pcap
               (generated with real scapy packets, then re-parsed: the demo
               doubles as an end-to-end parser test)
frontend/ (ES modules, no build step)
  src/config.js    taxonomy: protocols, lanes, colors, vehicle specs (legend
                   is generated from this — colors always match the road)
  src/vehicles.js  InstancedMesh pools — the object pool IS the instance slots;
                   ~10 draw calls for thousands of vehicles
  src/traffic.js   lane headway scheduling, convoy aggregation, flares
  src/flows.js     SYN/SYN-ACK matcher (half-open / refused / RST)
  src/playback.js  pcap timeline clock: play/pause/scrub/speed
  src/stats.js     rolling-window stats engine (clock-agnostic)
  src/highway.js   road, lanes, gates, skyline
  src/picking.js   raycast click → detail panel
  src/ui.js        dashboard view layer
```

**Performance notes.** Vehicles are GPU-instanced (one draw call per vehicle
type), spawn/release reuses instance slots with zero per-packet allocation, and
matrices are the only per-frame writes. InstancedMesh bounding spheres are
pinned manually (three.js never recomputes them for dynamic instances — without
this, click-raycasts silently miss). Typical load: 60–165 FPS with hundreds of
active vehicles while ingesting 800+ packets/sec.

## API

| Route | Purpose |
|---|---|
| `GET /api/interfaces` | capture-capable NICs |
| `WS /ws/live?iface=…&bpf=…&demo=1` | packet summary stream (100 ms batches) |
| `POST /api/pcap?limit=50000` | upload capture → playback timeline JSON |
| `GET /api/sample` | parsed synthetic 90 s capture |
| `GET /api/sample.pcap` | the same capture as a downloadable file |

## Troubleshooting

* **"Capture thread exited immediately"** — Npcap missing (Windows) or no
  root/CAP_NET_RAW (macOS/Linux). Use demo mode to evaluate without privileges.
* **Empty interface list** — same cause; the list retries automatically for a
  few seconds after startup.
* **Large pcaps** — parsing caps at 50 k packets by default (`?limit=` up to
  200 k); the UI tells you when a capture was truncated.
* **Blank page on a locked-down network** — the frontend pins Three.js and
  Tailwind from jsDelivr CDNs; vendor them locally if you need offline use.
