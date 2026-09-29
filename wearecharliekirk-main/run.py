"""Quick-start script for NetSentinel backend.

    python run.py                       # API + simulator, no capture
    sudo python run.py --live           # also capture the default interface
    sudo python run.py --live --iface wlan0
    python run.py --list-ifaces         # show capturable interfaces
"""
import argparse
import os

import uvicorn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSentinel backend")
    parser.add_argument("--live", action="store_true",
                        help="start live packet capture on startup (needs root/admin)")
    parser.add_argument("--iface", default=None,
                        help="interface to capture on (default: the one with the default route)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="list capturable interfaces and exit")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    if args.list_ifaces:
        from netsentinel.extractor.pcap_reader import default_interface, list_interfaces
        default = default_interface()
        for i in list_interfaces():
            mark = "*" if i["name"] == default else " "
            print(f" {mark} {i['name']:<24} {i['ip']:<16} {i['description']}")
        print("\n * = default (used when --iface is omitted)")
        raise SystemExit(0)

    if args.iface:
        os.environ["NETSENTINEL_IFACE"] = args.iface
    if args.live:
        os.environ["NETSENTINEL_LIVE"] = "1"

    uvicorn.run(
        "netsentinel.main:app",
        host=args.host,
        port=args.port,
        reload=False,  # Disabled to prevent WebSocket disconnects
        log_level="info",
    )
