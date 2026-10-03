# OSWE Cheatsheet

A personal cheatsheet and toolkit built while preparing for the **OSWE (Offensive Security Web Expert)** exam. It collects reusable Python scripts for common exploitation techniques, JavaScript snippets for client-side attacks, and a manual testing checklist organized by vulnerability class.

> ⚠️ Everything here is for use in authorized security testing (labs, CTFs, your own exam environment) only. Payloads and scripts target a placeholder `target.local` / `ATTACKER_IP` and are meant to be adapted, not run blindly against systems you don't have permission to test.

## Contents

### Python (`python/`)

| File | Covers |
|---|---|
| `http_request.py` | GET/POST basics with `requests` (form, JSON, multipart, custom headers), a raw-socket request example (useful for smuggling/CRLF), and an SSRF probe against common metadata endpoints. |
| `sql_blind.py` | Blind SQL injection: time-based and boolean-based oracles for MySQL/MSSQL/Postgres/Oracle, generic binary-search extraction (`dump_value`), and `information_schema` table/column enumeration. |
| `ws_client.py` | WebSocket interaction: basic connect/send/receive, synchronous request-response helper, blind time-based SQLi over WS, and action fuzzing. |
| `jwt_attacks.py` | JWT attacks: unverified decode, `alg: none`, RS256→HS256 algorithm confusion, weak-secret brute force, `kid` header injection (path traversal / SQLi), `jku` injection. |
| `cookies.py` | Cookie/session forging: Flask (`itsdangerous`) session decode/forge, Django signed cookies, generic HMAC-signed cookies, and recognizing serialized payloads (Python pickle, PHP objects). |
| `ssti.py` | Server-Side Template Injection: detection polyglot, engine fingerprinting, and RCE payloads for Jinja2/Twig/Freemarker/Velocity/Smarty/ERB. |
| `rce.py` | OS command injection (reflected and blind time-based), reverse-shell one-liner generator, and a webshell command sender. |
| `xxe.py` | XXE: local file read, PHP-filter read, OOB detection, and blind OOB exfiltration with a hostable external DTD template. |
| `race_condition.py` | Race conditions: fire N concurrent requests released simultaneously via a barrier to beat a server-side check. |

### JavaScript (`js/`)

| File | Covers |
|---|---|
| `js_request.js` | `fetch()`-based requests (GET, JSON/form/query POST), add-admin-user variants, CSRF (with and without token theft), and `postMessage` exploitation. |
| `js_cookies.js` | Cookie/localStorage/CSRF-token exfiltration and ready-to-paste XSS payloads (`fetch`, `sendBeacon`, no-`<script>` variants). Set `ATTACKER_HOST` at the top. |
| `prototype_pollution.js` | Prototype-pollution payloads (JSON body and query-string variants), a JSON sender, and a local `isPolluted` confirmation helper. |

### Checklist (`Manual_Testing.md`)

A vulnerability-by-vulnerability manual testing reference: SQLi, SSTI, XXE, SSRF, insecure deserialization (Java/PHP/Python/.NET), JWT/auth bypass, IDOR, path traversal (LFI/RFI), prototype pollution, RCE, XSS, CSRF, race conditions, and open redirect/CORS misconfiguration.

## Usage

Each Python file is self-contained and meant to be copy-pasted/adapted per target rather than run as-is:

```bash
pip install requests pyjwt cryptography itsdangerous websocket-client flask
```

Edit the `BASE_URL` / `ATTACKER_IP` / `target.local` placeholders at the top of each file before use. The JavaScript snippets export their functions via `module.exports` so they can be required in Node, but are primarily meant to be pasted into a browser console or an XSS payload.

## Disclaimer

For educational and authorized penetration testing purposes only.
