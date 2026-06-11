"""Packet Highway launcher.

    python run.py [--host 127.0.0.1] [--port 8000]

Live capture of real traffic additionally needs Npcap (Windows) or
root/CAP_NET_RAW (Linux/macOS). Demo mode and PCAP mode need neither.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> None:
    parser = argparse.ArgumentParser(description="Packet Highway server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    import uvicorn

    from backend.app import app

    print(f"\n  Packet Highway -> http://{args.host}:{args.port}\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
