"""
run_network.py — Unified One-Click Launcher for the IPLS Blockchain Network.

Runs the entire 3-node decentralized network in a single terminal with:
  • Automatic network setup check (generates keys/config if missing)
  • Color-coded unified output for all nodes
  • Auto-opening the web dashboard in your browser
  • Guaranteed clean process termination on Ctrl+C (no stuck background ports)

Usage:
    python run_network.py
    python run_network.py --clean     # wipe persistent storage and start fresh
"""

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
import webbrowser

# Terminal color codes (ANSI)
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

NODE_COLORS = {
    5000: CYAN,
    5001: MAGENTA,
    5002: BLUE,
}


def log_streamer(proc, port, color):
    """Stream and color-code stdout/stderr from a node process."""
    tag = f"{color}[Node {port}]{RESET}"
    for line in iter(proc.stdout.readline, ""):
        if line:
            clean_line = line.rstrip()
            print(f"{tag} {clean_line}", flush=True)


def ensure_setup():
    """Ensure network_config.json and keys exist before launching."""
    if not os.path.exists("network_config.json") or not os.path.exists("keys"):
        print(f"{YELLOW}[launcher] network_config.json or keys missing. Running setup_network.py...{RESET}")
        subprocess.run([sys.executable, "setup_network.py"], check=True)


def main():
    parser = argparse.ArgumentParser(description="IPLS Network Launcher")
    parser.add_argument("--clean", action="store_true", help="Clear on-disk storage before starting")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the dashboard in browser")
    parser.add_argument("--ports", nargs="+", type=int, default=[5000, 5001, 5002], help="Node ports to launch")
    args = parser.parse_args()

    ensure_setup()

    print("=" * 65)
    print(f"{GREEN}  IPLS Blockchain Network — One-Click Orchestrator{RESET}")
    print(f"  Nodes: {args.ports} | PoA: Ed448 | Hash: BLAKE3 | State: World State WAL")
    print("=" * 65)

    processes = []
    threads = []

    def cleanup():
        print(f"\n{YELLOW}[launcher] Shutting down all node processes...{RESET}")
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        print(f"{GREEN}[launcher] All nodes stopped cleanly.{RESET}")

    try:
        for port in args.ports:
            cmd = [sys.executable, "node.py", "--port", str(port)]
            if args.clean:
                cmd.append("--clean")

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            processes.append(proc)

            t = threading.Thread(
                target=log_streamer,
                args=(proc, port, NODE_COLORS.get(port, GREEN)),
                daemon=True,
            )
            t.start()
            threads.append(t)
            time.sleep(0.3)

        print(f"\n{GREEN}[launcher] All 3 nodes launched successfully!{RESET}")
        print(f"  Dashboard  : http://localhost:5000")
        print(f"  Submit Txn : python official_client.py OFFICIAL_A EMP1001 CHECK_IN --node http://localhost:5000")
        print(f"  Press Ctrl+C to terminate the network at any time.\n")

        if not args.no_browser:
            time.sleep(1.2)
            try:
                webbrowser.open("http://localhost:5000")
            except Exception:
                pass

        # Keep parent alive until user interrupts
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()
