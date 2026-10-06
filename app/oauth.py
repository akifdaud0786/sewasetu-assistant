# -*- coding: utf-8 -*-
"""
Sewa Setu as an OAuth 2.1 authorization server.

A third-party application can act for a citizen (scope `citizen`) or for a
block officer (scope `officer`) with that person's consent. The person signs in
on the portal's own pages (citizens by mobile + OTP, officers by departmental
login) and approves the application; the application then holds a short-lived
access token and a refresh token. Tokens are signed JWTs: any service can verify
them with the public keys at /.well-known/jwks.json.

Implements the subset of OAuth 2.1 that interoperable clients expect:
  - authorization server metadata (RFC 8414) at /.well-known/oauth-authorization-server
  - dynamic client registration (RFC 7591) at /oauth/register
  - client ID metadata documents (client_id is an HTTPS URL describing the client)
  - authorization code grant with PKCE S256 (public clients), /oauth/authorize
  - token endpoint with refresh-token rotation, /oauth/token
  - resource indicators (RFC 8707): the `resource` the client asks for becomes the
    token's audience, so a token minted for one service cannot be used at another
  - `iss` in authorization responses (RFC 9207)

Long-lived "program tokens" for unattended use are issued by an administrator at
/admin/tokens; they are the same JWT shape with a longer life.
"""

import os
import json
import time
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode, urlparse

import jwt
import requests as http
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import (Blueprint, request, jsonify, redirect, render_template, session,
                   flash, url_for, abort)

import app as portal

oauth = Blueprint("oauth", __name__)

ISSUER = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
# Sign-ins are short and absolute: a session ends at a fixed time counted from the
# consent, however often it is refreshed. Portals are used on shared phones and kiosks.
SESSION = {
    "citizen": {"access": 20 * 60, "session": 2 * 3600},   # 2-hour session, like the form's draft
    "officer": {"access": 30 * 60, "session": 8 * 3600},   # one working day
}
CODE_TTL = 300                    # 5 minutes
SCOPES = {
    "citizen": "act for you on the Old Age Pension portal: check eligibility, apply, "
               "see and manage your own application",
    "officer": "act as a block officer: see applications in the queue, verify them, "
               "record approve/reject decisions",
}


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

_KEY_CACHE = {}


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def signing_key():
    """The portal's RSA signing key, generated once and shared via the database."""
    if "priv" in _KEY_CACHE:
        return _KEY_CACHE["kid"], _KEY_CACHE["priv"]
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT kid, private_pem FROM oauth_keys ORDER BY created_at ASC LIMIT 1")
    row = cur.fetchone()
    if not row:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode("ascii")
        kid = secrets.token_hex(8)
        cur.execute("INSERT INTO oauth_keys (kid, private_pem, created_at) VALUES (%s, %s, %s) "
                    "ON CONFLICT DO NOTHING", (kid, pem, datetime.now()))
        conn.commit()
        cur.execute("SELECT kid, private_pem FROM oauth_keys ORDER BY created_at ASC LIMIT 1")
        row = cur.fetchone()
    cur.close(); conn.close()
    _KEY_CACHE["kid"] = row[0]
    _KEY_CACHE["priv"] = serialization.load_pem_private_key(row[1].encode("ascii"), password=None)
    return _KEY_CACHE["kid"], _KEY_CACHE["priv"]


def public_jwks():
    kid, priv = signing_key()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return {"keys": [jwk]}


def mint_access_token(subject, role, scope, audience, client_id, ttl=None, kind="access",
                      session_ends=None):
    kid, priv = signing_key()
    now = int(time.time())
    if ttl is None:
        ttl = SESSION[role]["access"]
    exp = now + ttl
    if session_ends:
        exp = min(exp, int(session_ends.timestamp()))
    claims = {
        "iss": ISSUER, "sub": subject, "aud": audience, "scope": scope, "role": role,
        "client_id": client_id, "iat": now, "exp": exp, "jti": secrets.token_hex(12),
        "kind": kind,
    }
    if session_ends:
        claims["session_ends"] = int(session_ends.timestamp())
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": kid}), claims


def verify_token(token, audience):
    """Verify a token issued by this portal for `audience`. Returns claims or None.
    Services elsewhere do the same with the JWKS; this is the in-process shortcut."""
    kid, priv = signing_key()
    try:
        return jwt.decode(token, priv.public_key(), algorithms=["RS256"],
                          audience=audience, issuer=ISSUER)
    except jwt.PyJWTError:
        return None


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

@oauth.get("/.well-known/oauth-authorization-server")
def as_metadata():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/oauth/authorize",
        "token_endpoint": ISSUER + "/oauth/token",
        "registration_endpoint": ISSUER + "/oauth/register",
        "jwks_uri": ISSUER + "/.well-known/jwks.json",
        "revocation_endpoint": ISSUER + "/oauth/revoke",
        "scopes_supported": list(SCOPES),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "authorization_response_iss_parameter_supported": True,
        "client_id_metadata_document_supported": True,
        "service_documentation": ISSUER + "/about",
    })


@oauth.get("/.well-known/jwks.json")
def jwks():
    return jsonify(public_jwks())


@oauth.after_app_request
def _cors(resp):
    # Discovery, registration and token endpoints may be called from browser-based clients.
    if request.path.startswith("/.well-known/") or request.path.startswith("/oauth/"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


# ---------------------------------------------------------------------------
# clients
# ---------------------------------------------------------------------------

LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "[::1]", "::1")


def redirect_allowed(registered, uri):
    """Exact match, except for loopback redirects (RFC 8252 s7.3): native clients listen
    on an ephemeral port, so a registered http://localhost/callback matches any port."""
    if uri in registered:
        return True
    try:
        u = urlparse(uri)
    except ValueError:
        return False
    if u.scheme != "http" or u.hostname not in LOOPBACK_HOSTS:
        return False
    for r in registered:
        rp = urlparse(r)
        if rp.scheme == "http" and rp.hostname in LOOPBACK_HOSTS and rp.path == u.path \
                and rp.query == u.query and rp.hostname == u.hostname:
            return True
    return False


def _is_url_client(client_id):
    return client_id.startswith("https://") or client_id.startswith("http://localhost")


def load_client(client_id):
    """Registered client, or a client described by its metadata document URL."""
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT client_id, client_name, redirect_uris, secret_hash, kind, fetched_at "
                "FROM oauth_clients WHERE client_id = %s", (client_id,))
    row = cur.fetchone()
    if row and (row[4] != "cimd" or (datetime.now() - row[5]).total_seconds() < 3600):
        cur.close(); conn.close()
        return {"client_id": row[0], "client_name": row[1], "redirect_uris": row[2],
                "secret_hash": row[3], "kind": row[4]}
    if _is_url_client(client_id):
        try:
            doc = http.get(client_id, timeout=5, headers={"Accept": "application/json"}).json()
        except Exception:
            cur.close(); conn.close()
            return None
        if doc.get("client_id") != client_id or not isinstance(doc.get("redirect_uris"), list):
            cur.close(); conn.close()
            return None
        cur.execute("INSERT INTO oauth_clients (client_id, client_name, redirect_uris, secret_hash, "
                    "kind, created_at, fetched_at) VALUES (%s, %s, %s, NULL, 'cimd', %s, %s) "
                    "ON CONFLICT (client_id) DO UPDATE SET client_name = EXCLUDED.client_name, "
                    "redirect_uris = EXCLUDED.redirect_uris, fetched_at = EXCLUDED.fetched_at",
                    (client_id, doc.get("client_name", client_id), json.dumps(doc["redirect_uris"]),
                     datetime.now(), datetime.now()))
        conn.commit()
        cur.close(); conn.close()
        return {"client_id": client_id, "client_name": doc.get("client_name", client_id),
                "redirect_uris": doc["redirect_uris"], "secret_hash": None, "kind": "cimd"}
    cur.close(); conn.close()
    return None


@oauth.post("/oauth/register")
def register():
    body = request.get_json(silent=True) or {}
    uris = body.get("redirect_uris")
    if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
        return jsonify({"error": "invalid_redirect_uri",
                        "error_description": "redirect_uris must be a non-empty list"}), 400
    for u in uris:
        p = urlparse(u)
        if p.scheme not in ("https", "http") or (p.scheme == "http" and p.hostname not in ("localhost", "127.0.0.1")):
            return jsonify({"error": "invalid_redirect_uri",
                            "error_description": "redirect URIs must be https, or http on localhost"}), 400
    method = body.get("token_endpoint_auth_method", "none")
    if method not in ("none", "client_secret_post"):
        return jsonify({"error": "invalid_client_metadata",
                        "error_description": "token_endpoint_auth_method must be none or client_secret_post"}), 400
    client_id = "ssc_" + secrets.token_urlsafe(16)
    secret = secrets.token_urlsafe(32) if method == "client_secret_post" else None
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO oauth_clients (client_id, client_name, redirect_uris, secret_hash, kind, "
                "created_at, fetched_at) VALUES (%s, %s, %s, %s, 'dcr', %s, %s)",
                (client_id, (body.get("client_name") or "Unnamed application")[:100], json.dumps(uris),
                 hashlib.sha256(secret.encode()).hexdigest() if secret else None,
                 datetime.now(), datetime.now()))
    conn.commit()
    cur.close(); conn.close()
    out = {
        "client_id": client_id, "client_name": body.get("client_name", "Unnamed application"),
        "redirect_uris": uris, "token_endpoint_auth_method": method,
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "client_id_issued_at": int(time.time()),
    }
    if secret:
        out["client_secret"] = secret
        out["client_secret_expires_at"] = 0
    return jsonify(out), 201


# ---------------------------------------------------------------------------
# authorization: validate -> login (citizen OTP / officer password) -> consent -> code
# ---------------------------------------------------------------------------

def _err_redirect(redirect_uri, state, error, desc):
    q = {"error": error, "error_description": desc, "iss": ISSUER}
    if state:
        q["state"] = state
    return redirect(redirect_uri + ("&" if "?" in redirect_uri else "?") + urlencode(q))


def _load_request(rid):
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, params, subject, role, pending_mobile, created_at FROM oauth_requests "
                "WHERE id = %s", (rid,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row or (datetime.now() - row[5]).total_seconds() > 900:
        return None
    return {"id": row[0], "params": row[1], "subject": row[2], "role": row[3],
            "pending_mobile": row[4]}


def _update_request(rid, **cols):
    conn = portal.get_db()
    cur = conn.cursor()
    sets = ", ".join("%s = %%s" % k for k in cols)
    cur.execute("UPDATE oauth_requests SET %s WHERE id = %%s" % sets, list(cols.values()) + [rid])
    conn.commit()
    cur.close(); conn.close()


@oauth.get("/oauth/authorize")
def authorize():
    q = request.args
    client_id = q.get("client_id", "")
    redirect_uri = q.get("redirect_uri", "")
    client = load_client(client_id) if client_id else None
    if not client:
        return render_template("oauth_error.html", error="Unknown application",
                               detail="client_id is not registered and is not a valid client metadata URL."), 400
    if not redirect_allowed(client["redirect_uris"], redirect_uri):
        return render_template("oauth_error.html", error="Bad redirect URI",
                               detail="redirect_uri is not one the application registered."), 400
    state = q.get("state")
    if q.get("response_type") != "code":
        return _err_redirect(redirect_uri, state, "unsupported_response_type", "only code is supported")
    if q.get("code_challenge_method", "S256") != "S256" or not q.get("code_challenge"):
        return _err_redirect(redirect_uri, state, "invalid_request", "PKCE with S256 is required")
    scopes = [s for s in (q.get("scope") or "citizen").split() if s]
    unknown = [s for s in scopes if s not in SCOPES]
    if unknown or len(scopes) != 1:
        return _err_redirect(redirect_uri, state, "invalid_scope",
                             "request exactly one of: " + ", ".join(SCOPES))
    resource = q.get("resource") or ISSUER
    rid = secrets.token_urlsafe(24)
    params = {
        "client_id": client_id, "client_name": client["client_name"], "redirect_uri": redirect_uri,
        "state": state, "code_challenge": q["code_challenge"], "scope": scopes[0],
        "resource": resource,
    }
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO oauth_requests (id, params, role, created_at) VALUES (%s, %s, %s, %s)",
                (rid, json.dumps(params), scopes[0], datetime.now()))
    conn.commit()
    cur.close(); conn.close()
    return redirect(url_for("oauth.login", rid=rid))


@oauth.route("/oauth/login", methods=["GET", "POST"])
def login():
    rid = request.args.get("rid", "")
    req = _load_request(rid)
    if not req:
        return render_template("oauth_error.html", error="Request expired",
                               detail="Please start again from your application."), 400
    role = req["role"]
    if request.method == "POST":
        if role == "citizen":
            if request.form.get("otp"):
                mobile = req["pending_mobile"] or ""
                code = request.form.get("otp", "").strip()
                conn = portal.get_db()
                cur = conn.cursor()
                cur.execute("SELECT code, created_at FROM otps WHERE mobile = %s ORDER BY id DESC LIMIT 1",
                            (mobile,))
                row = cur.fetchone()
                cur.close(); conn.close()
                if row and secrets.compare_digest(row[0], code) and \
                        (datetime.now() - row[1]).total_seconds() <= portal.OTP_VALIDITY_SECONDS:
                    _update_request(rid, subject="citizen:" + mobile)
                    return redirect(url_for("oauth.consent", rid=rid))
                flash("Invalid or expired OTP.")
            else:
                mobile = request.form.get("mobile", "").strip()
                if len(mobile) != 10 or not mobile.isdigit():
                    flash("Please enter a valid 10-digit mobile number.")
                else:
                    code = "%06d" % secrets.randbelow(1000000)
                    conn = portal.get_db()
                    cur = conn.cursor()
                    cur.execute("INSERT INTO otps (mobile, code, created_at) VALUES (%s, %s, %s)",
                                (mobile, code, datetime.now()))
                    conn.commit()
                    cur.close(); conn.close()
                    portal.send_sms(mobile, "Your Sewa Setu OTP is %s. Valid for 5 minutes." % code)
                    _update_request(rid, pending_mobile=mobile)
                    req["pending_mobile"] = mobile
        else:
            if (portal.ADMIN_PASSWORD and request.form.get("username") == portal.ADMIN_USERNAME and
                    request.form.get("password") == portal.ADMIN_PASSWORD):
                _update_request(rid, subject="officer:" + portal.ADMIN_USERNAME)
                return redirect(url_for("oauth.consent", rid=rid))
            flash("Invalid credentials.")
    return render_template("oauth_login.html", rid=rid, role=role,
                           client_name=req["params"]["client_name"],
                           pending_mobile=req["pending_mobile"])


@oauth.route("/oauth/consent", methods=["GET", "POST"])
def consent():
    rid = request.args.get("rid", "")
    req = _load_request(rid)
    if not req or not req["subject"]:
        return render_template("oauth_error.html", error="Request expired",
                               detail="Please start again from your application."), 400
    p = req["params"]
    if request.method == "POST":
        if request.form.get("decision") != "allow":
            _update_request(rid, subject=None)
            return _err_redirect(p["redirect_uri"], p["state"], "access_denied", "the user declined")
        code = secrets.token_urlsafe(32)
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, scope, code_challenge, "
                    "resource, subject, role, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (hashlib.sha256(code.encode()).hexdigest(), p["client_id"], p["redirect_uri"],
                     p["scope"], p["code_challenge"], p["resource"], req["subject"], req["role"],
                     datetime.now()))
        cur.execute("DELETE FROM oauth_requests WHERE id = %s", (rid,))
        conn.commit()
        cur.close(); conn.close()
        q = {"code": code, "iss": ISSUER}
        if p["state"]:
            q["state"] = p["state"]
        return redirect(p["redirect_uri"] + ("&" if "?" in p["redirect_uri"] else "?") + urlencode(q))
    who = req["subject"].split(":", 1)[1]
    hours = SESSION[req["role"]]["session"] // 3600
    return render_template("oauth_consent.html", rid=rid, client_name=p["client_name"],
                           scope=p["scope"], scope_text=SCOPES[p["scope"]], who=who,
                           role=req["role"], resource=p["resource"], session_hours=hours)


# ---------------------------------------------------------------------------
# token endpoint
# ---------------------------------------------------------------------------

def _token_error(error, desc, status=400):
    return jsonify({"error": error, "error_description": desc}), status


def _check_client_auth(client, form):
    if client["secret_hash"]:
        given = form.get("client_secret", "")
        return secrets.compare_digest(hashlib.sha256(given.encode()).hexdigest(), client["secret_hash"])
    return True


def _issue(subject, role, scope, audience, client_id, session_ends=None, client_name=""):
    if session_ends is None:
        session_ends = datetime.now() + timedelta(seconds=SESSION[role]["session"])
    access, claims = mint_access_token(subject, role, scope, audience, client_id,
                                       session_ends=session_ends)
    refresh = secrets.token_urlsafe(32)
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO oauth_refresh_tokens (token_hash, client_id, client_name, subject, role, "
                "scope, resource, created_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (hashlib.sha256(refresh.encode()).hexdigest(), client_id, client_name, subject, role,
                 scope, audience, datetime.now(), session_ends))
    conn.commit()
    cur.close(); conn.close()
    return jsonify({"access_token": access, "token_type": "Bearer",
                    "expires_in": claims["exp"] - int(time.time()),
                    "refresh_token": refresh, "scope": scope,
                    "session_ends": session_ends.isoformat(timespec="seconds")})


@oauth.post("/oauth/token")
def token():
    f = request.form
    grant = f.get("grant_type")
    client_id = f.get("client_id", "")
    client = load_client(client_id) if client_id else None
    if not client:
        return _token_error("invalid_client", "unknown client", 401)
    if not _check_client_auth(client, f):
        return _token_error("invalid_client", "client authentication failed", 401)

    if grant == "authorization_code":
        code = f.get("code", "")
        verifier = f.get("code_verifier", "")
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM oauth_codes WHERE code_hash = %s RETURNING client_id, redirect_uri, "
                    "scope, code_challenge, resource, subject, role, created_at",
                    (hashlib.sha256(code.encode()).hexdigest(),))
        row = cur.fetchone()
        conn.commit()
        cur.close(); conn.close()
        if not row:
            return _token_error("invalid_grant", "code is unknown or already used")
        c_client, c_redirect, c_scope, c_challenge, c_resource, subject, role, created = row
        if c_client != client_id:
            return _token_error("invalid_grant", "code was issued to a different client")
        if f.get("redirect_uri") and f.get("redirect_uri") != c_redirect:
            return _token_error("invalid_grant", "redirect_uri mismatch")
        if (datetime.now() - created).total_seconds() > CODE_TTL:
            return _token_error("invalid_grant", "code expired")
        if not verifier or _b64url(hashlib.sha256(verifier.encode()).digest()) != c_challenge:
            return _token_error("invalid_grant", "PKCE verification failed")
        if f.get("resource") and f.get("resource") != c_resource:
            return _token_error("invalid_target", "resource differs from the authorization request")
        return _issue(subject, role, c_scope, c_resource, client_id, client_name=client["client_name"])

    if grant == "refresh_token":
        rt = f.get("refresh_token", "")
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("UPDATE oauth_refresh_tokens SET revoked_at = %s WHERE token_hash = %s AND "
                    "revoked_at IS NULL AND expires_at > %s RETURNING client_id, subject, role, "
                    "scope, resource, expires_at, client_name",
                    (datetime.now(), hashlib.sha256(rt.encode()).hexdigest(), datetime.now()))
        row = cur.fetchone()
        conn.commit()
        cur.close(); conn.close()
        if not row or row[0] != client_id:
            return _token_error("invalid_grant", "refresh token is invalid, expired or revoked; "
                                                 "the person must sign in again")
        _, subject, role, scope, resource, session_ends, client_name = row
        if f.get("resource") and f.get("resource") != resource:
            return _token_error("invalid_target", "resource differs from the original grant")
        # the session window is absolute: rotation never extends it
        return _issue(subject, role, scope, resource, client_id, session_ends=session_ends,
                      client_name=client_name)

    return _token_error("unsupported_grant_type", "use authorization_code or refresh_token")


@oauth.post("/oauth/revoke")
def revoke():
    """RFC 7009: a client signs the person out by revoking its refresh token. Access
    tokens are short-lived JWTs and simply expire."""
    f = request.form
    tok = f.get("token", "")
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("UPDATE oauth_refresh_tokens SET revoked_at = %s WHERE token_hash = %s AND revoked_at IS NULL",
                (datetime.now(), hashlib.sha256(tok.encode()).hexdigest()))
    conn.commit()
    cur.close(); conn.close()
    return ("", 200)


def _revoke_grants(subject, token_hash=None):
    conn = portal.get_db()
    cur = conn.cursor()
    if token_hash:
        cur.execute("UPDATE oauth_refresh_tokens SET revoked_at = %s WHERE subject = %s AND token_hash = %s "
                    "AND revoked_at IS NULL", (datetime.now(), subject, token_hash))
    else:
        cur.execute("UPDATE oauth_refresh_tokens SET revoked_at = %s WHERE subject = %s AND revoked_at IS NULL",
                    (datetime.now(), subject))
    n = cur.rowcount
    conn.commit()
    cur.close(); conn.close()
    return n


def _active_grants(subject):
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT token_hash, client_name, client_id, created_at, expires_at FROM oauth_refresh_tokens "
                "WHERE subject = %s AND revoked_at IS NULL AND expires_at > %s ORDER BY created_at DESC",
                (subject, datetime.now()))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


@oauth.route("/status/connections", methods=["GET", "POST"])
def citizen_connections():
    """Applications currently allowed to act for this citizen, with revoke."""
    if not session.get("logged_in") or not session.get("portal_mobile"):
        flash("Please login to manage connected applications.")
        return redirect(url_for("status_login"))
    subject = "citizen:" + session["portal_mobile"]
    if request.method == "POST":
        n = _revoke_grants(subject, request.form.get("token_hash") or None)
        flash("%d sign-in(s) ended." % n)
        return redirect(url_for("oauth.citizen_connections"))
    return render_template("connections.html", rows=_active_grants(subject), who=session["portal_mobile"],
                           post_url=url_for("oauth.citizen_connections"))


# ---------------------------------------------------------------------------
# program tokens (admin-issued, long-lived, for unattended use)
# ---------------------------------------------------------------------------

@oauth.route("/admin/tokens", methods=["GET", "POST"])
def admin_tokens():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    issued = None
    if request.method == "POST" and not request.form.get("revoke_subject"):
        label = (request.form.get("label") or "program").strip()[:100]
        audience = (request.form.get("audience") or "").strip() or ISSUER
        days = max(1, min(int(request.form.get("days") or 90), 365))
        subject = "officer:" + session.get("admin_user", portal.ADMIN_USERNAME)
        issued, claims = mint_access_token(subject, "officer", "officer", audience,
                                           "admin-issued", ttl=days * 86400, kind="program")
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO oauth_program_tokens (jti, label, subject, audience, issued_by, "
                    "created_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (claims["jti"], label, subject, audience, session.get("admin_user", portal.ADMIN_USERNAME),
                     datetime.now(), datetime.fromtimestamp(claims["exp"])))
        conn.commit()
        cur.close(); conn.close()
    if request.method == "POST" and request.form.get("revoke_subject"):
        n = _revoke_grants(request.form["revoke_subject"], request.form.get("token_hash") or None)
        flash("%d officer sign-in(s) ended." % n)
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT label, subject, audience, issued_by, created_at, expires_at FROM "
                "oauth_program_tokens ORDER BY id DESC LIMIT 20")
    rows = cur.fetchall()
    cur.execute("SELECT client_name, kind, created_at FROM oauth_clients ORDER BY id DESC LIMIT 20")
    clients = cur.fetchall()
    cur.close(); conn.close()
    grants = _active_grants("officer:" + session.get("admin_user", portal.ADMIN_USERNAME))
    return render_template("admin_tokens.html", token=issued, rows=rows, clients=clients, issuer=ISSUER,
                           grants=grants, subject="officer:" + session.get("admin_user", portal.ADMIN_USERNAME))
