# -*- coding: utf-8 -*-
"""
The portal's official channel for AI assistants.

The two MCP servers (citizen and officer) are thin: every rule lives here, in the portal,
and goes through the same functions the web form and the admin pages use
(validate_application / create_application / decide_application). An assistant is just
another way to apply; it can never get anyone a pension the counter would not.

Authentication: the bearer token the person's assistant received from the portal's OAuth
server, forwarded unchanged by the MCP server. It must be signed by this portal, be meant
for one of the two MCP endpoints (audience), carry the matching role, and belong to a
sign-in that has not been ended.
"""

import base64
import hashlib
import json
import os
import re
import secrets
from datetime import timedelta
from functools import wraps

import jwt
from flask import Blueprint, request, jsonify, g, render_template, abort

import app as portal
import oauth

agent_api = Blueprint("agent_api", __name__)

PUBLIC_BASE_URL = oauth.ISSUER
CITIZEN_MCP_URL = os.environ.get("CITIZEN_MCP_URL", PUBLIC_BASE_URL + "/mcp/citizen").rstrip("/")
OFFICER_MCP_URL = os.environ.get("OFFICER_MCP_URL", PUBLIC_BASE_URL + "/mcp/officer").rstrip("/")
AUDIENCE_FOR_ROLE = {"citizen": CITIZEN_MCP_URL, "officer": OFFICER_MCP_URL}

UPLOAD_LINK_MINUTES = 30
MAX_DOC_BYTES = 5 * 1024 * 1024
DOC_TYPES = {  # extension -> (magic bytes, mime)
    "pdf": (b"%PDF", "application/pdf"),
    "png": (b"\x89PNG", "image/png"),
    "jpg": (b"\xff\xd8\xff", "image/jpeg"),
    "jpeg": (b"\xff\xd8\xff", "image/jpeg"),
}
DRAFT_FIELDS = ("applicant_name", "dob", "gender", "marital_status", "husband_name",
                "village", "block", "bank_account", "ifsc")

STATUS_TEXT = {
    "PENDING": "Submitted and waiting for the block officer's decision.",
    "APPROVED": "Approved by the block officer. The pension of Rs. 250 a month is credited "
                "to the bank account by DBT.",
    "DEEMED_APPROVED": "Approved automatically under the Right to Public Services Act because "
                       "it was not decided within %d days. The pension of Rs. 250 a month is "
                       "credited to the bank account by DBT." % portal.SLA_DAYS,
    "REJECTED": "Rejected by the block officer (see the reason). A fresh application can be made.",
    "WITHDRAWN": "Withdrawn by the applicant. A fresh application can be made.",
}


# ---------------------------------------------------------------------------
# plumbing
# ---------------------------------------------------------------------------

def _err(code, message, http_status=400, **extra):
    body = {"ok": False, "error": code, "message": message}
    body.update(extra)
    return jsonify(body), http_status


def _log(action, ok, detail=""):
    try:
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO agent_calls (at, role, subject, client_id, action, ok, detail) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (portal.now_ist(), g.get("role"), g.get("subject"), g.get("client_id"),
                     action, ok, (detail or "")[:300]))
        conn.commit()
        cur.close(); conn.close()
    except Exception as e:  # logging must never break the request
        portal.app.logger.error("agent_calls log failed: %s" % e)


def requires(role):
    """Bearer-token guard for one role."""
    def deco(fn):
        @wraps(fn)
        def inner(*a, **kw):
            auth = request.headers.get("Authorization", "")
            if not auth.lower().startswith("bearer "):
                return _err("unauthorized", "sign in required", 401)
            token = auth.split(None, 1)[1].strip()
            kid, priv = oauth.signing_key()
            try:
                claims = jwt.decode(token, priv.public_key(), algorithms=["RS256"],
                                    audience=AUDIENCE_FOR_ROLE[role], issuer=oauth.ISSUER)
            except jwt.ExpiredSignatureError:
                return _err("token_expired", "the sign-in token has expired; refresh or sign in again", 401)
            except jwt.PyJWTError:
                return _err("unauthorized", "token is not valid for this service", 401)
            if claims.get("role") != role or claims.get("scope") != role:
                return _err("forbidden", "this sign-in is not allowed to do that", 403)
            if not oauth.token_is_live(claims):
                return _err("session_ended", "this sign-in has been ended; please sign in again", 401)
            g.claims = claims
            g.role = role
            g.subject = claims["sub"]
            g.client_id = claims.get("client_id", "")
            g.who = claims["sub"].split(":", 1)[1]
            return fn(*a, **kw)
        return inner
    return deco


def _client_label():
    """A short, human name for the assistant, for the audit trail."""
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT client_name FROM oauth_clients WHERE client_id = %s", (g.client_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    name = (row[0] if row else "") or g.client_id or "assistant"
    return ("AI assistant (%s)" % name)[:80]


def mask_account(acct):
    acct = acct or ""
    return ("X" * max(0, len(acct) - 4)) + acct[-4:] if acct else ""


def deemed_date(submitted_at):
    return (submitted_at + timedelta(days=portal.SLA_DAYS)).date()


def scheme_facts():
    return {
        "scheme": "Old Age Pension Scheme, Department of Social Welfare, Government of Purvanchal",
        "pension_amount": "Rs. 250 per month, credited by DBT to the applicant's own bank account",
        "who_can_apply": "Residents of Purvanchal aged %d years or above on the day of applying"
                         % portal.MIN_AGE,
        "application_deadline": portal.SCHEME_DEADLINE.strftime("%d %B %Y, %I:%M %p IST"),
        "window_open": portal.now_ist() <= portal.SCHEME_DEADLINE,
        "documents": "One age proof: birth certificate, school leaving certificate or Voter ID "
                     "(JPG, PNG or PDF, up to 5 MB)",
        "needed_details": ["full name as on the age proof", "date of birth (DD/MM/YYYY)",
                           "gender", "marital status (and late husband's name if widowed, optional)",
                           "village or town", "block", "bank account number and IFSC (account in "
                           "the applicant's own name)"],
        "one_application_rule": "One active (pending or approved) application per mobile number. "
                                "A pending application can be withdrawn and a fresh one made.",
        "decision_time": "The block officer decides within %d days. If not decided in %d days, "
                         "the application stands approved automatically (deemed approval) - "
                         "unless it breaks a scheme rule, in which case an officer decides."
                         % (portal.SLA_DAYS, portal.SLA_DAYS),
        "fees": "There is no fee. Nobody should ask for money to apply.",
        "all_blocks": portal.BLOCKS,
        "assistant_blocks": portal.AGENT_BLOCKS,
        "assistant_note": "Applying through an AI assistant is being piloted in these blocks only: "
                          + ", ".join(portal.AGENT_BLOCKS) + ". People in other blocks can apply on "
                          "the website (" + PUBLIC_BASE_URL + "/apply) or at the block office counter. "
                          "Anyone can check their own application status through the assistant.",
        "website": PUBLIC_BASE_URL,
        "status_portal": PUBLIC_BASE_URL + "/status (mobile number + password = date of birth as DDMMYYYY)",
    }


# ---------------------------------------------------------------------------
# citizen: drafts
# ---------------------------------------------------------------------------

def _normalise_field(key, value):
    value = "" if value is None else str(value).strip()
    if key == "dob":
        m = re.fullmatch(r"(\d{4})-(\d{1,2})-(\d{1,2})", value)
        if m:  # ISO date -> the portal's DD/MM/YYYY
            value = "%02d/%02d/%s" % (int(m.group(3)), int(m.group(2)), m.group(1))
        m = re.fullmatch(r"(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4})", value)
        if m:
            value = "%02d/%02d/%s" % (int(m.group(1)), int(m.group(2)), m.group(3))
    elif key == "block":
        for b in portal.BLOCKS:
            if value.lower() == b.lower():
                value = b
    elif key == "gender":
        value = {"m": "Male", "male": "Male", "f": "Female", "female": "Female",
                 "other": "Other"}.get(value.lower(), value)
    elif key == "marital_status":
        value = {"married": "Married", "unmarried": "Unmarried", "single": "Unmarried",
                 "never married": "Unmarried", "widowed": "Widowed", "widow": "Widowed",
                 "widower": "Widowed"}.get(value.lower(), value)
    return value


def _load_draft(cur, mobile):
    cur.execute("SELECT data, doc_path, doc_name, updated_at FROM agent_drafts WHERE mobile = %s",
                (mobile,))
    row = cur.fetchone()
    if not row:
        return {}, "", ""
    return row[0] or {}, row[1] or "", row[2] or ""


def _review_code(data, doc_path):
    blob = json.dumps({k: data.get(k, "") for k in DRAFT_FIELDS}, sort_keys=True) + "|" + doc_path
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:8].upper()


def _draft_view(cur, mobile):
    """Everything an assistant needs to tell the applicant what is still needed."""
    data, doc_path, doc_name = _load_draft(cur, mobile)
    errors, cleaned = portal.validate_application(data, doc_path)
    if cleaned["block"] and cleaned["block"] in portal.BLOCKS and \
            cleaned["block"] not in portal.AGENT_BLOCKS:
        errors.append("applying through an assistant is not yet available in %s block; please "
                      "apply on the website or at the block office (assistant pilot blocks: %s)"
                      % (cleaned["block"], ", ".join(portal.AGENT_BLOCKS)))
    missing = [k for k in DRAFT_FIELDS if not data.get(k) and k != "husband_name"]
    if not doc_path:
        missing.append("age_proof_document")
    existing = portal.active_application(cur, mobile)
    view = {
        "mobile": mobile,
        "fields": {k: data.get(k, "") for k in DRAFT_FIELDS},
        "age_proof_document": doc_name or None,
        "missing": missing,
        "problems": errors,
        "ready_to_submit": not errors and not existing,
    }
    if cleaned.get("dob"):
        view["age_today"] = portal.age_on(cleaned["dob"], portal.now_ist().date())
    if existing:
        view["blocked_by_existing_application"] = {
            "application_no": existing[1], "status": existing[2],
            "message": "This mobile number already has an active application. A pending one can "
                       "be withdrawn first if it needs to be redone; an approved one cannot be "
                       "applied for again."}
    if view["ready_to_submit"]:
        view["review_code"] = _review_code(data, doc_path)
        view["summary_to_read_back"] = (
            "Name: %s; Date of birth: %s (age %d); Gender: %s; Marital status: %s%s; "
            "Village: %s; Block: %s; Bank account: %s; IFSC: %s; Age proof: %s"
            % (cleaned["applicant_name"], data.get("dob"), view["age_today"], cleaned["gender"],
               cleaned["marital_status"],
               ("; Late husband: %s" % cleaned["husband_name"]) if cleaned["husband_name"] else "",
               cleaned["village"], cleaned["block"], cleaned["bank_account"], cleaned["ifsc"],
               doc_name))
        view["declaration"] = DECLARATION
        view["next_step"] = ("Read the summary and the declaration to the applicant. Only if they "
                             "confirm it is correct and agree to the declaration, call submit with "
                             "this review_code.")
    return view


DECLARATION = ("I hereby declare that the information furnished above is true to the best of my "
               "knowledge and belief. I understand that furnishing false information is punishable "
               "under applicable law and will result in cancellation of pension.")


@agent_api.get("/api/agent/v1/citizen/whoami")
@requires("citizen")
def api_whoami_citizen():
    return jsonify({"ok": True, "role": "citizen", "mobile": g.who})


@agent_api.get("/api/agent/v1/officer/whoami")
@requires("officer")
def api_whoami_officer():
    return jsonify({"ok": True, "role": "officer", "officer": g.who})


@agent_api.get("/api/agent/v1/scheme")
def api_scheme():
    return jsonify({"ok": True, **scheme_facts()})


@agent_api.get("/api/agent/v1/villages")
@requires("citizen")
def api_villages():
    return _villages()


@agent_api.get("/api/agent/v1/officer/villages")
@requires("officer")
def api_villages_officer():
    return _villages()


def _villages():
    q = (request.args.get("q") or "").strip()
    conn = portal.get_db()
    cur = conn.cursor()
    if q:
        cur.execute("SELECT village, block, count(*) FROM applications WHERE village ILIKE %s "
                    "GROUP BY village, block ORDER BY count(*) DESC LIMIT 15", ("%" + q + "%",))
    else:
        cur.execute("SELECT village, block, count(*) FROM applications "
                    "GROUP BY village, block ORDER BY block, village")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify({"ok": True, "matches": [
        {"village": v, "block": b, "assistant_available": b in portal.AGENT_BLOCKS}
        for v, b, _ in rows],
        "note": "Villages already known to the portal. A village not listed may still be valid; "
                "ask the applicant for their block."})


@agent_api.get("/api/agent/v1/citizen/draft")
@requires("citizen")
def api_get_draft():
    conn = portal.get_db()
    cur = conn.cursor()
    view = _draft_view(cur, g.who)
    cur.close(); conn.close()
    return jsonify({"ok": True, **view})


@agent_api.post("/api/agent/v1/citizen/draft")
@requires("citizen")
def api_update_draft():
    body = request.get_json(silent=True) or {}
    unknown = [k for k in body if k not in DRAFT_FIELDS]
    if unknown:
        return _err("unknown_fields", "unknown fields: %s; allowed: %s"
                    % (", ".join(unknown), ", ".join(DRAFT_FIELDS)))
    conn = portal.get_db()
    cur = conn.cursor()
    data, doc_path, doc_name = _load_draft(cur, g.who)
    for k, v in body.items():
        data[k] = _normalise_field(k, v)
    cur.execute("INSERT INTO agent_drafts (mobile, data, doc_path, doc_name, updated_at) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (mobile) DO UPDATE SET data = EXCLUDED.data, "
                "updated_at = EXCLUDED.updated_at",
                (g.who, json.dumps(data), doc_path, doc_name, portal.now_ist()))
    conn.commit()
    view = _draft_view(cur, g.who)
    cur.close(); conn.close()
    _log("update_draft", True, "fields=" + ",".join(sorted(body)))
    return jsonify({"ok": True, **view})


@agent_api.delete("/api/agent/v1/citizen/draft")
@requires("citizen")
def api_discard_draft():
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM agent_drafts WHERE mobile = %s", (g.who,))
    conn.commit()
    cur.close(); conn.close()
    _log("discard_draft", True)
    return jsonify({"ok": True, "message": "The draft has been discarded."})


def _save_document(mobile, file_name, content):
    """Check and store an age-proof file; returns (path, display_name) or raises ValueError."""
    file_name = os.path.basename(file_name or "").strip() or "document"
    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    if ext not in DOC_TYPES:
        raise ValueError("the age proof must be a JPG, PNG or PDF file")
    if not content:
        raise ValueError("the file is empty")
    if len(content) > MAX_DOC_BYTES:
        raise ValueError("the file is larger than 5 MB")
    if not content.startswith(DOC_TYPES[ext][0]):
        raise ValueError("the file is not a real %s (its contents do not match)" % ext.upper())
    folder = os.path.join(portal.UPLOAD_DIR, "agent")
    os.makedirs(folder, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", file_name)[-60:]
    path = os.path.join(folder, "%s_%s_%s" % (mobile, secrets.token_hex(4), safe))
    with open(path, "wb") as out:
        out.write(content)
    return path, file_name[:200]


def _attach_document(cur, mobile, path, name):
    cur.execute("INSERT INTO agent_drafts (mobile, data, doc_path, doc_name, updated_at) "
                "VALUES (%s, '{}'::jsonb, %s, %s, %s) ON CONFLICT (mobile) DO UPDATE SET "
                "doc_path = EXCLUDED.doc_path, doc_name = EXCLUDED.doc_name, "
                "updated_at = EXCLUDED.updated_at", (mobile, path, name, portal.now_ist()))


@agent_api.post("/api/agent/v1/citizen/draft/document")
@requires("citizen")
def api_upload_document():
    body = request.get_json(silent=True) or {}
    try:
        content = base64.b64decode(re.sub(r"^data:[^,]*,", "", body.get("content_base64") or ""),
                                   validate=False)
        path, name = _save_document(g.who, body.get("file_name"), content)
    except (ValueError, base64.binascii.Error) as e:
        _log("upload_document", False, str(e))
        return _err("bad_document", str(e))
    conn = portal.get_db()
    cur = conn.cursor()
    _attach_document(cur, g.who, path, name)
    conn.commit()
    view = _draft_view(cur, g.who)
    cur.close(); conn.close()
    _log("upload_document", True, name)
    return jsonify({"ok": True, **view})


@agent_api.post("/api/agent/v1/citizen/draft/upload-link")
@requires("citizen")
def api_upload_link():
    token = secrets.token_urlsafe(24)
    now = portal.now_ist()
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO agent_upload_links (token_hash, mobile, created_at, expires_at) "
                "VALUES (%s, %s, %s, %s)", (hashlib.sha256(token.encode()).hexdigest(), g.who, now,
                                            now + timedelta(minutes=UPLOAD_LINK_MINUTES)))
    conn.commit()
    cur.close(); conn.close()
    _log("upload_link", True)
    return jsonify({"ok": True, "upload_url": PUBLIC_BASE_URL + "/agent-upload/" + token,
                    "valid_minutes": UPLOAD_LINK_MINUTES,
                    "message": "Open this link on the phone that has the photo or scan of the age "
                               "proof and upload it there. Then check the draft again."})


@agent_api.route("/agent-upload/<token>", methods=["GET", "POST"])
def upload_page(token):
    """A plain page where the applicant (or family) uploads the age proof from their phone."""
    th = hashlib.sha256(token.encode()).hexdigest()
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT mobile, expires_at, used_at FROM agent_upload_links WHERE token_hash = %s", (th,))
    row = cur.fetchone()
    if not row or row[1] < portal.now_ist() or row[2]:
        cur.close(); conn.close()
        return render_template("agent_upload.html", state="expired"), 410
    mobile = row[0]
    if request.method == "POST":
        f = request.files.get("document")
        try:
            if f is None or not f.filename:
                raise ValueError("please choose a file")
            path, name = _save_document(mobile, f.filename, f.read())
        except ValueError as e:
            cur.close(); conn.close()
            return render_template("agent_upload.html", state="form", error=str(e),
                                   masked=mask_account(mobile))
        _attach_document(cur, mobile, path, name)
        cur.execute("UPDATE agent_upload_links SET used_at = %s WHERE token_hash = %s",
                    (portal.now_ist(), th))
        conn.commit()
        cur.close(); conn.close()
        return render_template("agent_upload.html", state="done", name=name)
    cur.close(); conn.close()
    return render_template("agent_upload.html", state="form", masked=mask_account(mobile))


@agent_api.post("/api/agent/v1/citizen/submit")
@requires("citizen")
def api_submit():
    body = request.get_json(silent=True) or {}
    if body.get("declaration_accepted") is not True:
        return _err("declaration_required", "the applicant must hear and accept the declaration "
                                            "before the application is submitted")
    conn = portal.get_db()
    cur = conn.cursor()
    data, doc_path, doc_name = _load_draft(cur, g.who)
    if not data:
        existing = portal.active_application(cur, g.who)
        cur.close(); conn.close()
        if existing:
            return _err("already_submitted", "there is no draft; this mobile already has application "
                        "%s (%s)" % (existing[1], existing[2]), 409,
                        application_no=existing[1], status=existing[2])
        return _err("no_draft", "there is no application draft yet")
    view = _draft_view(cur, g.who)
    if not view["ready_to_submit"]:
        cur.close(); conn.close()
        _log("submit", False, "not ready")
        return _err("not_ready", "the application cannot be submitted yet", 422,
                    problems=view["problems"], missing=view["missing"],
                    blocked_by_existing_application=view.get("blocked_by_existing_application"))
    if (body.get("review_code") or "").strip().upper() != view["review_code"]:
        cur.close(); conn.close()
        return _err("review_code_mismatch", "the review_code does not match the current draft; get the "
                    "draft again, read the summary back to the applicant, then submit with its "
                    "review_code", 409)
    errors, cleaned = portal.validate_application(data, doc_path)
    try:
        new_id, app_no = portal.create_application(cur, g.who, cleaned, channel=_client_label())
    except portal.DuplicateApplication as dup:
        conn.rollback()
        cur.close(); conn.close()
        return _err("already_has_application", "this mobile already has application %s (%s)"
                    % (dup.existing[1], dup.existing[2]), 409,
                    application_no=dup.existing[1], status=dup.existing[2])
    cur.execute("DELETE FROM agent_drafts WHERE mobile = %s", (g.who,))
    conn.commit()
    cur.execute("SELECT submitted_at FROM applications WHERE id = %s", (new_id,))
    submitted_at = cur.fetchone()[0]
    cur.close(); conn.close()
    portal.send_sms(g.who, "Sewa Setu: application %s received. Track at the status portal "
                           "with mobile no. and password (DOB as DDMMYYYY)." % app_no)
    _log("submit", True, app_no)
    return jsonify({
        "ok": True, "application_no": app_no, "status": "PENDING",
        "submitted_at": submitted_at.strftime("%d/%m/%Y %H:%M IST"),
        "decision_due_by": deemed_date(submitted_at).strftime("%d/%m/%Y"),
        "message": "Application %s has been submitted. An SMS has been sent to %s. The block officer "
                   "will decide by %s; if not decided by then it stands approved automatically. "
                   "The status can be checked any time through this assistant or at %s/status "
                   "(password: date of birth as DDMMYYYY)."
                   % (app_no, g.who, deemed_date(submitted_at).strftime("%d/%m/%Y"), PUBLIC_BASE_URL)})


# ---------------------------------------------------------------------------
# citizen: follow-up
# ---------------------------------------------------------------------------

def _decision_note(cur, app_id, status):
    if status not in ("APPROVED", "REJECTED", "WITHDRAWN", "DEEMED_APPROVED"):
        return None
    cur.execute("SELECT note FROM audit_log WHERE application_id = %s AND action = %s "
                "ORDER BY at DESC LIMIT 1", (app_id, "WITHDRAW" if status == "WITHDRAWN" else status))
    row = cur.fetchone()
    note = (row[0] if row else "") or ""
    return re.sub(r"\s*\[via [^\]]*\]$", "", note) or None


@agent_api.get("/api/agent/v1/citizen/applications")
@requires("citizen")
def api_my_applications():
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, application_no, applicant_name, dob, village, block, bank_account, ifsc, "
                "status, submitted_at, decided_at, gender, marital_status FROM applications "
                "WHERE mobile = %s ORDER BY submitted_at DESC", (g.who,))
    rows = cur.fetchall()
    out = []
    for (app_id, no, name, dob, village, block, acct, ifsc, status, sub, dec, gender, marital) in rows:
        item = {
            "application_no": no, "applicant_name": name,
            "date_of_birth": dob.strftime("%d/%m/%Y") if dob else None,
            "gender": gender, "marital_status": marital,
            "village": village, "block": block,
            "bank_account": mask_account(acct), "ifsc": ifsc,
            "status": status, "what_it_means": STATUS_TEXT.get(status, status),
            "submitted_at": sub.strftime("%d/%m/%Y %H:%M") if sub else None,
            "decided_at": dec.strftime("%d/%m/%Y %H:%M") if dec else None,
            "can_withdraw": status == "PENDING",
        }
        if status == "PENDING" and sub:
            item["decision_due_by"] = deemed_date(sub).strftime("%d/%m/%Y")
        reason = _decision_note(cur, app_id, status)
        if reason:
            item["reason" if status == "REJECTED" else "note"] = reason
        out.append(item)
    draft = _draft_view(cur, g.who)
    cur.close(); conn.close()
    _log("my_applications", True, "%d found" % len(out))
    return jsonify({"ok": True, "mobile": g.who, "applications": out,
                    "note": None if out else "No application has been made with this mobile number.",
                    "draft_in_progress": bool(any(draft["fields"].values()) or draft["age_proof_document"])})


@agent_api.post("/api/agent/v1/citizen/withdraw")
@requires("citizen")
def api_withdraw():
    body = request.get_json(silent=True) or {}
    app_no = (body.get("application_no") or "").strip().upper()
    if body.get("confirmed") is not True:
        return _err("confirmation_required", "withdrawing cannot be undone; ask the applicant to "
                                             "confirm and call again with confirmed=true")
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("UPDATE applications SET status = 'WITHDRAWN', decided_at = %s, decided_by = 'APPLICANT' "
                "WHERE application_no = %s AND mobile = %s AND status = 'PENDING' RETURNING id",
                (portal.now_ist(), app_no, g.who))
    row = cur.fetchone()
    if not row:
        cur.execute("SELECT status FROM applications WHERE application_no = %s AND mobile = %s",
                    (app_no, g.who))
        r = cur.fetchone()
        cur.close(); conn.close()
        _log("withdraw", False, app_no)
        if not r:
            return _err("not_found", "no application %s for this mobile number" % app_no, 404)
        return _err("not_pending", "only a pending application can be withdrawn; %s is %s"
                    % (app_no, r[0]), 409)
    portal.write_audit(cur, row[0], "WITHDRAW", "applicant:%s" % g.who,
                       (body.get("reason") or "").strip()[:200] + " [via %s]" % _client_label())
    conn.commit()
    cur.close(); conn.close()
    _log("withdraw", True, app_no)
    return jsonify({"ok": True, "application_no": app_no, "status": "WITHDRAWN",
                    "message": "Application %s has been withdrawn. A fresh application can now be "
                               "made with this mobile number." % app_no})


# ---------------------------------------------------------------------------
# officer
# ---------------------------------------------------------------------------

def _officer_blocks(requested):
    if requested:
        b = _normalise_field("block", requested)
        if b not in portal.AGENT_BLOCKS:
            return None
        return [b]
    return list(portal.AGENT_BLOCKS)


def _checks(cur, row):
    """Automatic checks an officer would otherwise do by hand. Returns a list of
    {level, check, detail}: level is BLOCKER (cannot be approved), WARNING or OK."""
    (app_id, no, name, mobile, dob, gender, marital, husband, village, block, acct, ifsc,
     doc_path, status, sub, dec, dec_by) = row
    out = []
    problems = portal.eligibility_problems(dob, sub)
    if problems:
        out.append({"level": "BLOCKER", "check": "age", "detail": "; ".join(problems)})
    else:
        out.append({"level": "OK", "check": "age",
                    "detail": "%d on the date of application" % portal.age_on(dob, sub.date())})
    if not doc_path:
        out.append({"level": "WARNING", "check": "age_proof",
                    "detail": "no age proof file on record (older applications were migrated "
                              "without documents); verify from the physical file"})
    elif not os.path.isfile(doc_path):
        out.append({"level": "WARNING", "check": "age_proof",
                    "detail": "age proof recorded but the file is not available on this server"})
    else:
        out.append({"level": "OK", "check": "age_proof", "detail": "age proof on file; view it before deciding"})
    if not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", ifsc or ""):
        out.append({"level": "WARNING", "check": "ifsc",
                    "detail": "IFSC %r is not a valid 11-character code; DBT credit may fail" % ifsc})
    if not re.fullmatch(r"\d{9,18}", acct or ""):
        out.append({"level": "WARNING", "check": "bank_account", "detail": "bank account number looks invalid"})
    cur.execute("SELECT application_no, mobile, status FROM applications WHERE id <> %s AND "
                "status IN %s AND (bank_account = %s OR (lower(applicant_name) = lower(%s) AND dob = %s))",
                (app_id, portal.ACTIVE_STATUSES, acct, name, dob))
    dups = cur.fetchall()
    if dups:
        out.append({"level": "WARNING", "check": "possible_duplicate",
                    "detail": "another active application has the same bank account or the same "
                              "name and date of birth: " + ", ".join(
                                  "%s (%s, mobile %s)" % (d[0], d[2], d[1]) for d in dups[:5])})
    else:
        out.append({"level": "OK", "check": "possible_duplicate",
                    "detail": "no other active application with this bank account or name + date of birth"})
    if gender == "Male" and husband:
        out.append({"level": "WARNING", "check": "consistency", "detail": "late husband's name given for a male applicant"})
    if status == "PENDING":
        days_left = (deemed_date(sub) - portal.now_ist().date()).days
        cur.execute("SELECT 1 FROM audit_log WHERE application_id = %s AND action = 'DEEMED_HELD'", (app_id,))
        if cur.fetchone():
            out.append({"level": "WARNING", "check": "sla",
                        "detail": "past the %d-day SLA; held back from deemed approval because it "
                                  "breaks a scheme rule" % portal.SLA_DAYS})
        elif days_left < 0:
            out.append({"level": "WARNING", "check": "sla", "detail": "past the SLA; the nightly job will deem it approved"})
        else:
            out.append({"level": "OK" if days_left > 3 else "WARNING", "check": "sla",
                        "detail": "%d day(s) left before it stands approved automatically (%s)"
                                  % (days_left, deemed_date(sub).strftime("%d/%m/%Y"))})
    return out


APP_COLS = ("id, application_no, applicant_name, mobile, dob, gender, marital_status, husband_name, "
            "village, block, bank_account, ifsc, doc_path, status, submitted_at, decided_at, decided_by")


def _find_app(cur, app_no):
    cur.execute("SELECT " + APP_COLS + " FROM applications WHERE application_no = %s",
                ((app_no or "").strip().upper(),))
    return cur.fetchone()


@agent_api.get("/api/agent/v1/officer/summary")
@requires("officer")
def api_officer_summary():
    conn = portal.get_db()
    cur = conn.cursor()
    today = portal.now_ist()
    cur.execute("SELECT block, count(*), "
                "count(*) FILTER (WHERE submitted_at < %s), "
                "count(*) FILTER (WHERE submitted_at >= %s AND submitted_at < %s), "
                "min(submitted_at) "
                "FROM applications WHERE status = 'PENDING' AND block IN %s GROUP BY block ORDER BY block",
                (today - timedelta(days=portal.SLA_DAYS), today - timedelta(days=portal.SLA_DAYS),
                 today - timedelta(days=portal.SLA_DAYS - 3), tuple(portal.AGENT_BLOCKS)))
    rows = cur.fetchall()
    cur.execute("SELECT count(*) FROM audit_log l JOIN applications a ON a.id = l.application_id "
                "WHERE a.status = 'PENDING' AND l.action = 'DEEMED_HELD' AND a.block IN %s",
                (tuple(portal.AGENT_BLOCKS),))
    held = cur.fetchone()[0]
    cur.execute("SELECT count(*) FILTER (WHERE status = 'APPROVED'), count(*) FILTER (WHERE status = 'REJECTED') "
                "FROM applications WHERE decided_by = %s AND decided_at >= %s",
                (g.who, today.replace(hour=0, minute=0, second=0, microsecond=0)))
    mine = cur.fetchone()
    cur.close(); conn.close()
    _log("officer_summary", True)
    return jsonify({"ok": True, "officer": g.who, "blocks": portal.AGENT_BLOCKS,
                    "pending_by_block": [{"block": b, "pending": n, "past_sla": over,
                                          "due_within_3_days": soon,
                                          "oldest_submitted": old.strftime("%d/%m/%Y") if old else None}
                                         for b, n, over, soon, old in rows],
                    "held_back_from_deemed_approval": held,
                    "decided_by_you_today": {"approved": mine[0], "rejected": mine[1]},
                    "sla_days": portal.SLA_DAYS})


@agent_api.get("/api/agent/v1/officer/queue")
@requires("officer")
def api_officer_queue():
    blocks = _officer_blocks(request.args.get("block"))
    if blocks is None:
        return _err("block_not_in_pilot", "the officer assistant covers these blocks: "
                    + ", ".join(portal.AGENT_BLOCKS))
    try:
        limit = max(1, min(int(request.args.get("limit", 10)), 50))
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        return _err("bad_paging", "limit and offset must be numbers")
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM applications WHERE status = 'PENDING' AND block IN %s", (tuple(blocks),))
    total = cur.fetchone()[0]
    cur.execute("SELECT " + APP_COLS + " FROM applications WHERE status = 'PENDING' AND block IN %s "
                "ORDER BY submitted_at ASC LIMIT %s OFFSET %s", (tuple(blocks), limit, offset))
    items = []
    for row in cur.fetchall():
        checks = _checks(cur, row)
        items.append({
            "application_no": row[1], "applicant_name": row[2], "village": row[8], "block": row[9],
            "age_at_application": portal.age_on(row[4], row[14].date()) if row[4] else None,
            "submitted_at": row[14].strftime("%d/%m/%Y %H:%M"),
            "decide_by": deemed_date(row[14]).strftime("%d/%m/%Y"),
            "blockers": [c["detail"] for c in checks if c["level"] == "BLOCKER"],
            "warnings": [c["check"] for c in checks if c["level"] == "WARNING"],
        })
    cur.close(); conn.close()
    _log("officer_queue", True, "%s n=%d" % (",".join(blocks), len(items)))
    return jsonify({"ok": True, "blocks": blocks, "total_pending": total, "offset": offset,
                    "order": "oldest first (closest to deemed approval)", "applications": items})


@agent_api.get("/api/agent/v1/officer/search")
@requires("officer")
def api_officer_search():
    q = (request.args.get("q") or "").strip()
    if len(q) < 3:
        return _err("query_too_short", "search with at least 3 characters: application number, "
                                       "mobile number or part of the name")
    conn = portal.get_db()
    cur = conn.cursor()
    cur.execute("SELECT application_no, applicant_name, mobile, village, block, status, submitted_at "
                "FROM applications WHERE block IN %s AND (application_no = %s OR mobile = %s OR "
                "applicant_name ILIKE %s) ORDER BY submitted_at DESC LIMIT 20",
                (tuple(portal.AGENT_BLOCKS), q.upper(), q, "%" + q + "%"))
    rows = cur.fetchall()
    cur.close(); conn.close()
    _log("officer_search", True, "n=%d" % len(rows))
    return jsonify({"ok": True, "results": [
        {"application_no": r[0], "applicant_name": r[1], "mobile": r[2], "village": r[3],
         "block": r[4], "status": r[5], "submitted_at": r[6].strftime("%d/%m/%Y %H:%M")} for r in rows]})


@agent_api.get("/api/agent/v1/officer/application/<app_no>")
@requires("officer")
def api_officer_application(app_no):
    conn = portal.get_db()
    cur = conn.cursor()
    row = _find_app(cur, app_no)
    if not row or row[9] not in portal.AGENT_BLOCKS:
        cur.close(); conn.close()
        return _err("not_found", "no application %s in the assistant's blocks (%s)"
                    % (app_no, ", ".join(portal.AGENT_BLOCKS)), 404)
    checks = _checks(cur, row)
    cur.execute("SELECT at, action, actor, note FROM audit_log WHERE application_id = %s ORDER BY at", (row[0],))
    audit = [{"at": a.strftime("%d/%m/%Y %H:%M"), "action": b, "by": c, "note": d or ""} for a, b, c, d in cur.fetchall()]
    cur.execute("SELECT application_no, status, submitted_at FROM applications WHERE mobile = %s AND id <> %s "
                "ORDER BY submitted_at DESC", (row[3], row[0]))
    history = [{"application_no": a, "status": b, "submitted_at": c.strftime("%d/%m/%Y")} for a, b, c in cur.fetchall()]
    cur.close(); conn.close()
    (app_id, no, name, mobile, dob, gender, marital, husband, village, block, acct, ifsc,
     doc_path, status, sub, dec, dec_by) = row
    _log("officer_view", True, no)
    return jsonify({"ok": True, "application": {
        "application_no": no, "applicant_name": name, "mobile": mobile,
        "date_of_birth": dob.strftime("%d/%m/%Y") if dob else None,
        "age_at_application": portal.age_on(dob, sub.date()) if dob else None,
        "gender": gender, "marital_status": marital, "late_husband_name": husband or None,
        "village": village, "block": block, "bank_account": acct, "ifsc": ifsc,
        "age_proof_on_file": bool(doc_path and os.path.isfile(doc_path)),
        "status": status, "submitted_at": sub.strftime("%d/%m/%Y %H:%M"),
        "decided_at": dec.strftime("%d/%m/%Y %H:%M") if dec else None, "decided_by": dec_by},
        "checks": checks,
        "can_approve": status == "PENDING" and not any(c["level"] == "BLOCKER" for c in checks),
        "other_applications_from_this_mobile": history,
        "audit_trail": audit})


@agent_api.get("/api/agent/v1/officer/application/<app_no>/document")
@requires("officer")
def api_officer_document(app_no):
    conn = portal.get_db()
    cur = conn.cursor()
    row = _find_app(cur, app_no)
    cur.close(); conn.close()
    if not row or row[9] not in portal.AGENT_BLOCKS:
        return _err("not_found", "no application %s in the assistant's blocks" % app_no, 404)
    path = row[12]
    if not path or not os.path.isfile(path):
        return _err("no_document", "no age proof file is available for %s; verify from the physical "
                                   "file" % row[1], 404)
    ext = path.rsplit(".", 1)[-1].lower()
    mime = DOC_TYPES.get(ext, (None, "application/octet-stream"))[1]
    with open(path, "rb") as fh:
        content = fh.read()
    _log("officer_document", True, row[1])
    return jsonify({"ok": True, "application_no": row[1], "mime_type": mime,
                    "file_name": os.path.basename(path).split("_", 2)[-1],
                    "content_base64": base64.b64encode(content).decode("ascii")})


@agent_api.post("/api/agent/v1/officer/application/<app_no>/decision")
@requires("officer")
def api_officer_decide(app_no):
    body = request.get_json(silent=True) or {}
    decision = (body.get("decision") or "").strip().lower()
    reason = (body.get("reason") or "").strip()
    new_status = {"approve": "APPROVED", "approved": "APPROVED",
                  "reject": "REJECTED", "rejected": "REJECTED"}.get(decision)
    if not new_status:
        return _err("bad_decision", "decision must be 'approve' or 'reject'")
    if not reason:
        return _err("reason_required", "record the reason for the decision; it is kept against the "
                                       "officer's name and, for a rejection, shown to the applicant")
    conn = portal.get_db()
    cur = conn.cursor()
    row = _find_app(cur, app_no)
    if not row or row[9] not in portal.AGENT_BLOCKS:
        cur.close(); conn.close()
        return _err("not_found", "no application %s in the assistant's blocks" % app_no, 404)
    ok, message, no = portal.decide_application(cur, row[0], new_status, g.who, reason,
                                                channel=_client_label())
    if not ok:
        conn.rollback()
        cur.close(); conn.close()
        _log("officer_decide", False, "%s %s: %s" % (no, decision, message))
        return _err("decision_refused", message, 409)
    conn.commit()
    cur.close(); conn.close()
    if new_status == "REJECTED":
        portal.send_sms(row[3], "Sewa Setu: your pension application %s was not approved. Reason: %s. "
                                "You may apply again." % (no, reason[:120]))
    else:
        portal.send_sms(row[3], "Sewa Setu: your pension application %s has been approved." % no)
    _log("officer_decide", True, "%s %s" % (no, new_status))
    return jsonify({"ok": True, "application_no": no, "status": new_status,
                    "recorded_reason": reason, "decided_by": g.who, "message": message})
