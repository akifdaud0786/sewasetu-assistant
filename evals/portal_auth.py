# -*- coding: utf-8 -*-
"""
Sign in to Sewa Setu the way a person would, but scripted, for evals and smoke tests:
register an OAuth client, open the authorization page, sign in (citizen: mobile + OTP read
from the simulated SMS gateway; officer: departmental login), consent, exchange the code.

Returns an access token for the given MCP endpoint (the token's audience).
"""

import base64
import hashlib
import re
import secrets
import time
from urllib.parse import urlparse, parse_qs

import requests

REDIRECT = "http://localhost:53682/callback"


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _rid(resp):
    return parse_qs(urlparse(resp.headers["Location"]).query)["rid"][0]


def get_token(base, resource, role, mobile=None, username="admin", password=None,
              client_name="Sewa Setu eval harness"):
    s = requests.Session()
    reg = s.post(base + "/oauth/register", json={"client_name": client_name, "redirect_uris": [REDIRECT]}).json()
    cid = reg["client_id"]
    verifier, challenge = _pkce()
    r = s.get(base + "/oauth/authorize", params={
        "client_id": cid, "redirect_uri": REDIRECT, "response_type": "code", "scope": role,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": "x", "resource": resource},
        allow_redirects=False)
    rid = _rid(r)
    if role == "citizen":
        sent_after = time.time() - 1
        s.post(base + "/oauth/login", params={"rid": rid}, data={"mobile": mobile})
        otp = None
        for _ in range(30):
            msgs = s.get(base + "/__gateway/api/messages", params={"to": mobile}).json()["messages"]
            fresh = [m for m in msgs if m["delivered"] and m["sent_at"] >= sent_after and "OTP" in (m["text"] or "")]
            if fresh:
                otp = re.search(r"\b(\d{6})\b", fresh[-1]["text"]).group(1)
                break
            time.sleep(1)
        if not otp:
            raise RuntimeError("OTP never arrived for %s" % mobile)
        r = s.post(base + "/oauth/login", params={"rid": rid}, data={"otp": otp}, allow_redirects=False)
    else:
        r = s.post(base + "/oauth/login", params={"rid": rid},
                   data={"username": username, "password": password}, allow_redirects=False)
    if r.status_code != 302:
        raise RuntimeError("sign-in failed (%s)" % r.status_code)
    r = s.post(base + "/oauth/consent", params={"rid": rid}, data={"decision": "allow"}, allow_redirects=False)
    code = parse_qs(urlparse(r.headers["Location"]).query)["code"][0]
    tok = s.post(base + "/oauth/token", data={
        "grant_type": "authorization_code", "code": code, "client_id": cid, "redirect_uri": REDIRECT,
        "code_verifier": verifier, "resource": resource}).json()
    return tok["access_token"], tok, cid
