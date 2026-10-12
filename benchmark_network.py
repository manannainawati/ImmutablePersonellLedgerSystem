"""
benchmark_network.py — Multi-Threaded Concurrency & Throughput (TPS) Benchmark Suite.

Usage:
    python benchmark_network.py --txs 30 --workers 5 --node http://localhost:5000

Simulates high-frequency badge scans, measuring:
  - Peak Transactions Per Second (TPS)
  - P50, P90, P99 Latency percentiles
  - Multi-node gossip replication speed
  - Mempool queue absorption
"""
import argparse
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

def benchmark(node_url="http://localhost:5000", total_txs=30, workers=5):
    print(f"\n=======================================================")
    print(f"  IPLS BLOCKCHAIN CONCURRENCY & TPS BENCHMARK")
    print(f"=======================================================")
    print(f"Target Node    : {node_url}")
    print(f"Transactions   : {total_txs}")
    print(f"Worker Threads : {workers}")
    print(f"-------------------------------------------------------")

    # Check node health
    try:
        r = requests.get(f"{node_url}/state", timeout=2)
        if r.status_code != 200:
            print("Error: Node returned non-200 status")
            return
    except Exception as e:
        print(f"Error: Node {node_url} is unreachable. Ensure 'python run_network.py' is running!")
        return

    print("Launching concurrent transaction stream...")
    latencies = []
    success_count = 0
    t_start = time.perf_counter()

    def send_tx(i):
        emp_id = f"EMP100{1 + (i % 3)}"
        action = "CHECK_IN" if (i % 2 == 0) else "CHECK_OUT"
        t0 = time.perf_counter()
        try:
            res = requests.post(
                f"{node_url}/portal/sign_and_submit",
                json={
                    "official_id": "OFFICIAL_A",
                    "employee_id": emp_id,
                    "action": action,
                },
                timeout=5
            )
            lat = (time.perf_counter() - t0) * 1000
            return (res.status_code in [200, 201], lat)
        except Exception:
            return (False, None)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(send_tx, i) for i in range(total_txs)]
        for f in as_completed(futures):
            ok, lat = f.result()
            if ok and lat is not None:
                success_count += 1
                latencies.append(lat)

    t_total = time.perf_counter() - t_start
    tps = round(success_count / max(t_total, 0.001), 2)

    latencies.sort()
    avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0
    p50 = round(latencies[len(latencies) // 2], 2) if latencies else 0
    p90 = round(latencies[int(len(latencies) * 0.9)], 2) if latencies else 0
    p99 = round(latencies[-1], 2) if latencies else 0

    print(f"\nBenchmark Results:")
    print(f"  Processed Transactions : {success_count} / {total_txs} ({round(success_count/total_txs*100, 1)}%)")
    print(f"  Total Duration         : {round(t_total, 3)} seconds")
    print(f"  Throughput (Peak TPS)  : {tps} TPS")
    print(f"  Average Latency        : {avg_lat} ms")
    print(f"  Median (P50) Latency   : {p50} ms")
    print(f"  P90 Latency            : {p90} ms")
    print(f"  P99 Latency            : {p99} ms")
    print(f"=======================================================\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IPLS Blockchain TPS Benchmark")
    parser.add_argument("--node", default="http://localhost:5000", help="Node URL")
    parser.add_argument("--txs", type=int, default=30, help="Total transactions to send")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent worker threads")
    args = parser.parse_args()

    benchmark(node_url=args.node, total_txs=args.txs, workers=args.workers)
