# OSWE Cheatsheet

A personal cheatsheet and toolkit built while preparing for the **OSWE (Offensive Security Web Expert)** exam. It collects reusable Python scripts for common exploitation techniques, JavaScript snippets for client-side attacks, and a manual testing checklist organized by vulnerability class.

> ⚠️ Everything here is for use in authorized security testing (labs, CTFs, your own exam environment) only. Payloads and scripts target a placeholder `target.local` / `ATTACKER_IP` and are meant to be adapted, not run blindly against systems you don't have permission to test.

## Contents

### Python (`py_*.py`)

| File | Covers |
|---|---|
| `py_01_http_requests.py` | GET/POST basics with `requests` (form, JSON, multipart, custom headers), a raw-socket request example (useful for smuggling/CRLF), and an SSRF probe against common metadata endpoints. |
| `py_02_sqli_blind.py` | Blind SQL injection: time-based and boolean-based oracles, generic binary-search extraction (`dump_value`), and `information_schema` enumeration. |
| `py_03_websocket.py` | WebSocket interaction: basic connect/send/receive, synchronous request-response helper, blind time-based SQLi over WS, and message fuzzing. |
| `py_04_jwt.py` | JWT attacks: unverified decode, `alg: none`, RS256→HS256 algorithm confusion, weak-secret brute force, `kid` header injection (path traversal / SQLi), `jku` injection. |
| `py_05_cookies_sessions.py` | Cookie/session forging: Flask (`itsdangerous`) session decode/forge, Django signed cookies, generic HMAC-signed cookies, and recognizing serialized payloads (Python pickle, PHP objects). |

### JavaScript (`js_fetch_and_cookies.js`)

Client-side snippets focused on `fetch()` and cookie handling for XSS/CSRF proof-of-concepts: GET/POST requests, cookie/localStorage exfiltration, CSRF token theft and reuse, ready-to-paste XSS payloads (`fetch`, `sendBeacon`, no-`<script>` variants), and `postMessage` exploitation.

### Checklist (`manual_testing_checklist.md`)

A vulnerability-by-vulnerability manual testing reference: SQLi, SSTI, XXE, SSRF, insecure deserialization (Java/PHP/Python/.NET), JWT/auth bypass, IDOR, path traversal (LFI/RFI), prototype pollution, RCE, XSS, CSRF, race conditions, and open redirect/CORS misconfiguration.

## Usage

Each Python file is self-contained and meant to be copy-pasted/adapted per target rather than run as-is:

```bash
pip install requests pyjwt cryptography itsdangerous websocket-client
```

Edit `BASE_URL` / `ATTACKER_HOST` / `target.local` placeholders at the top of each file before use.

## Disclaimer

For educational and authorized penetration testing purposes only. The author is not responsible for misuse.