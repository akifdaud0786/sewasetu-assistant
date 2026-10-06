# -*- coding: utf-8 -*-
"""
Play the invented citizens and officers against the live assistant and check the portal.

For each persona:
  1. sign in as that person through the portal's real OAuth flow (OTP read from the
     simulated SMS gateway) and, if the persona needs it, set up earlier history;
  2. run a conversation: the ASSISTANT is Claude Code (a small model, limited turns) connected
     to our MCP endpoint; the CITIZEN is another model playing the persona card. When the
     assistant hands out an upload link, the harness uploads a photo of the persona's age
     proof to it, as the grandson would from his phone;
  3. read the portal (through the MCP tools, as the person and as an officer) and check
     what must be true now. Pass/fail is decided by the portal's state, not by the chat.

Usage:
  python run_evals.py --base https://... --admin-password ... [--only id,id] [--model claude-haiku-4-5]
Results are merged into ../app/evals_data/results.json (rendered at /eval-dashboard).
"""

import argparse
import asyncio
import base64
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime

import httpx2
import requests
import yaml
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from portal_auth import get_token

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "app", "evals_data", "results.json")
MAX_USER_TURNS = 9
# only the MCP server's tools: no shell, files or web (empty CLI args do not survive claude.CMD on Windows)
NO_BUILTINS = "Bash,Read,Write,Edit,MultiEdit,Glob,Grep,WebFetch,WebSearch,Task,Agent,TodoWrite,NotebookEdit"


# ---------------------------------------------------------------------------
# MCP helper (used for setup and for checking the portal afterwards)
# ---------------------------------------------------------------------------

async def _mcp(url, token, calls):
    async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token}, timeout=60) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, *_):
            async with ClientSession(read, write) as s:
                await s.initialize()
                out = []
                for name, args in calls:
                    r = await s.call_tool(name, args)
                    txt = next((c.text for c in r.content if hasattr(c, "text")), "{}")
                    try:
                        out.append(json.loads(txt))
                    except ValueError:
                        out.append({"raw": txt})
                return out


def mcp(url, token, *calls):
    return asyncio.run(_mcp(url, token, list(calls)))


def fresh_mobile():
    return random.choice("6789") + "".join(random.choice("0123456789") for _ in range(9))


def voter_id_jpeg(name, dob, relation=""):
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("RGB", (640, 400), (236, 240, 248))
    d = ImageDraw.Draw(im)
    try:
        f = ImageFont.truetype("arial.ttf", 22)
        small = ImageFont.truetype("arial.ttf", 15)
    except OSError:
        f = small = ImageFont.load_default()
    d.rectangle([0, 0, 640, 60], fill=(30, 60, 120))
    d.text((20, 20), "ELECTION COMMISSION OF INDIA - ELECTOR PHOTO IDENTITY CARD", fill="white", font=small)
    d.rectangle([24, 90, 184, 290], outline=(80, 80, 80), width=2)
    d.text((62, 180), "PHOTO", fill=(120, 120, 120), font=f)
    y = 95
    for k, v in [("EPIC No", "PVC%07d" % random.randint(0, 9999999)), ("Name", name),
                 ("Relation", relation or "-"), ("Date of Birth", dob), ("State", "Purvanchal")]:
        d.text((210, y), k + ":", fill=(60, 60, 60), font=f)
        d.text((380, y), v, fill="black", font=f)
        y += 40
    d.text((20, 360), "SYNTHETIC TEST DOCUMENT - SEWA SETU EVALS", fill=(170, 30, 30), font=f)
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=85)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# setup of earlier history (done the scripted way, through the same MCP tools)
# ---------------------------------------------------------------------------

def make_application(ctx, mobile, facts, bank_account=None):
    url = ctx["citizen_url"]
    tok, _, _ = get_token(ctx["base"], url, "citizen", mobile=mobile, client_name="Eval setup")
    doc = base64.b64encode(voter_id_jpeg(facts["applicant_name"], facts["dob"])).decode()
    draft = {"applicant_name": facts["applicant_name"], "date_of_birth": facts["dob"],
             "gender": facts["gender"], "marital_status": facts["marital_status"],
             "village": facts["village"], "block": facts["block"],
             "bank_account_number": bank_account or facts["bank_account"], "ifsc": facts["ifsc"]}
    if facts.get("late_husband"):
        draft["late_husband_name"] = facts["late_husband"]
    res = mcp(url, tok, ("update_application_draft", draft),
              ("upload_age_proof", {"file_name": "voter_id.jpg", "content_base64": doc}))
    code = res[-1].get("review_code")
    if not code:
        raise RuntimeError("setup draft not ready: %s" % res[-1])
    sub = mcp(url, tok, ("submit_application", {"review_code": code, "declaration_accepted": True}))[0]
    return sub["application_no"]


def officer_token(ctx):
    # access tokens live 30 minutes and a full suite takes longer: sign in again when stale
    if "officer_token" not in ctx or time.time() - ctx["officer_token_at"] > 20 * 60:
        ctx["officer_token"] = get_token(ctx["base"], ctx["officer_url"], "officer",
                                         password=ctx["admin_password"], client_name="Eval checker")[0]
        ctx["officer_token_at"] = time.time()
    return ctx["officer_token"]


def setup_persona(ctx, p, state):
    kind = p.get("setup")
    if not kind:
        return
    if kind in ("pending_application", "approved_application"):
        no = make_application(ctx, state["mobile"], p["facts"])
        if kind == "approved_application":
            mcp(ctx["officer_url"], officer_token(ctx), ("decide_application", {
                "application_no": no, "decision": "approve", "reason": "Eval setup: approved last year"}))
        state["setup_app"] = no
    elif kind == "pending_application_wrong_account":
        state["setup_app"] = make_application(ctx, state["mobile"], p["facts"], bank_account=p["wrong_bank_account"])
    elif kind == "neighbour_application":
        nm = fresh_mobile()
        neighbour = dict(p["facts"], applicant_name="Runu Mandal", dob="03/08/1955", gender="Female",
                         marital_status="Widowed", bank_account="70298871981")
        state["neighbour_mobile"] = nm
        state["neighbour_app"] = make_application(ctx, nm, neighbour)


# ---------------------------------------------------------------------------
# the conversation
# ---------------------------------------------------------------------------

def claude(args, prompt, timeout=300):
    # the prompt goes on stdin: claude.CMD on Windows cuts multi-line arguments at the first newline
    proc = subprocess.run([shutil.which("claude") or "claude", "-p"] + args, input=prompt,
                          capture_output=True, text=True, encoding="utf-8", timeout=timeout,
                          cwd=tempfile.gettempdir())
    return proc.stdout


def assistant_turn(ctx, mcp_config, session_id, message, model):
    args = ["--model", model, "--mcp-config", mcp_config, "--strict-mcp-config",
            "--allowedTools", "mcp__sewasetu", "--disallowedTools", NO_BUILTINS, "--max-turns", "16",
            "--output-format", "stream-json", "--verbose"]
    if session_id:
        args += ["--resume", session_id]
    out = claude(args, message)
    events, text, sid = [], [], session_id
    for line in out.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("session_id"):
            sid = ev["session_id"]
        if ev.get("type") == "assistant":
            for c in ev["message"].get("content", []):
                if c.get("type") == "text" and c["text"].strip():
                    text.append(c["text"])
                    events.append({"role": "assistant", "text": c["text"]})
                elif c.get("type") == "tool_use":
                    events.append({"role": "tool_call", "tool": c["name"].replace("mcp__sewasetu__", ""),
                                   "args": _redact(c.get("input", {}))})
        elif ev.get("type") == "user":
            for c in ev["message"].get("content", []):
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    content = c.get("content")
                    if isinstance(content, list):
                        content = " ".join(x.get("text", "[image]") for x in content if isinstance(x, dict))
                    events.append({"role": "tool_result", "text": str(content)[:1500],
                                   "error": bool(c.get("is_error"))})
    return sid, "\n".join(text), events


def _redact(args):
    out = dict(args)
    if "content_base64" in out:
        out["content_base64"] = "<%d base64 chars>" % len(out["content_base64"] or "")
    return out


CITIZEN_PROMPT = """You are role-playing a person at a government help counter in Purvanchal, India, talking to an AI \
assistant that helps with the Old Age Pension. Stay in character. Write ONLY your next message to the assistant, \
nothing else - no stage directions, no quotes.

WHO YOU ARE: {who_types}, on behalf of {name} (age {age}, {village}, {block} block).
HOW YOU WRITE: {speaks}
WHAT YOU KNOW (give these only when asked, a few at a time, exactly as written): {facts}
AGE PROOF: {document}
HOW YOU BEHAVE: {behaviour}
{extra}
Rules: never invent details that are not listed. If the assistant asks you to paste or attach a file in the chat, \
say you can't, you only have it as a photo on the phone and could open a link. If you were given an upload link, \
you open it and upload; then say it is uploaded. When your goal is done, or the assistant has clearly said it \
cannot help and told you what to do instead, reply with exactly: [[DONE]]

CONVERSATION SO FAR:
{history}

Your next message:"""


def citizen_turn(p, history, extra, model):
    facts = dict(p.get("facts", {}))
    if p.get("typo_ifsc"):
        facts["ifsc_as_you_first_type_it"] = p["typo_ifsc"]
    prompt = CITIZEN_PROMPT.format(
        who_types=p.get("who_types", p["name"]), name=p["name"], age=p.get("age", ""),
        village=p.get("village", ""), block=p.get("block", ""), speaks=p.get("speaks", ""),
        facts=json.dumps(facts, ensure_ascii=False), document=json.dumps(p.get("document", "none"), ensure_ascii=False),
        behaviour=p.get("behaviour", ""), extra=extra,
        history="\n".join("%s: %s" % ("ASSISTANT" if r == "assistant" else "YOU", t) for r, t in history))
    for attempt in range(2):
        try:
            out = claude(["--model", model, "--disallowedTools", NO_BUILTINS, "--output-format", "json"],
                         prompt, timeout=300)
            return json.loads(out)["result"].strip()
        except (subprocess.TimeoutExpired, ValueError, KeyError):
            continue
    return "[[DONE]]"


def upload_if_link(text, p, done_links):
    for link in re.findall(r"https?://\S+/agent-upload/[A-Za-z0-9_\-]+", text or ""):
        if link in done_links:
            continue
        f = p.get("facts", {})
        img = voter_id_jpeg(f.get("applicant_name", "?"), f.get("dob", "?"),
                            ("Husband: %s" % f["late_husband"]) if f.get("late_husband") else "")
        r = requests.post(link, files={"document": ("voter_id.jpg", img, "image/jpeg")}, timeout=30)
        done_links.add(link)
        return r.status_code == 200
    return None


def converse(ctx, p, token, url, opening, model, citizen_model):
    cfg = os.path.join(tempfile.gettempdir(), "sewasetu-mcp-%s.json" % uuid.uuid4().hex[:8])
    with open(cfg, "w") as fh:
        json.dump({"mcpServers": {"sewasetu": {"type": "http", "url": url,
                                               "headers": {"Authorization": "Bearer " + token}}}}, fh)
    transcript, history, sid, links = [], [], None, set()
    message = opening
    extra = ""
    try:
        for turn in range(MAX_USER_TURNS):
            transcript.append({"role": "user", "text": message})
            history.append(("user", message))
            sid, reply, events = assistant_turn(ctx, cfg, sid, message, model)
            transcript.extend(events)
            history.append(("assistant", reply or "(no reply)"))
            uploaded = upload_if_link(reply, p, links)
            extra = ""
            if uploaded is not None:
                transcript.append({"role": "harness", "text": "The family opened the upload link and uploaded "
                                   "a photo of the voter ID (%s)." % ("ok" if uploaded else "FAILED")})
                extra = "You have just opened the link and uploaded the voter ID photo successfully."
            message = citizen_turn(p, history, extra, citizen_model)
            if "[[DONE]]" in message or not message:
                break
    finally:
        os.remove(cfg)
    return transcript


# ---------------------------------------------------------------------------
# checks: read the portal afterwards
# ---------------------------------------------------------------------------

def mine(ctx, token):
    return mcp(ctx["citizen_url"], token, ("my_applications", {}))[0].get("applications", [])


def run_checks(ctx, p, state, token, transcript):
    apps = mine(ctx, token)
    active = [a for a in apps if a["status"] in ("PENDING", "APPROVED", "DEEMED_APPROVED")]
    newest = active[0] if active else None
    text = " ".join(t.get("text", "") for t in transcript if t["role"] == "assistant")
    results = []

    def add(name, ok, detail):
        results.append({"check": name, "passed": bool(ok), "detail": detail})

    case = None
    if newest and newest["block"] in ctx["agent_blocks"]:
        case = mcp(ctx["officer_url"], officer_token(ctx), ("get_application", {"application_no": newest["application_no"]}))[0]
    for e in p["expect"]:
        c = e["check"]
        if c == "active_application":
            add("one active application, status %s" % e["status"], newest and newest["status"] == e["status"],
                "found: %s" % ([(a["application_no"], a["status"]) for a in apps] or "no applications"))
        elif c == "no_application":
            add("no application created", not apps, "found: %s" % ([a["application_no"] for a in apps] or "none"))
        elif c == "active_count":
            add("exactly %d active application(s)" % e["equals"], len(active) == e["equals"], "active: %d" % len(active))
        elif c == "status_count":
            n = len([a for a in apps if a["status"] == e["status"]])
            add("%d %s application(s)" % (e["equals"], e["status"]), n == e["equals"], "found %d" % n)
        elif c == "no_status":
            n = len([a for a in apps if a["status"] == e["status"]])
            add("nothing %s" % e["status"], n == 0, "found %d" % n)
        elif c == "field":
            field = e["field"]
            if field == "bank_account_last4":
                got = (newest or {}).get("bank_account", "")[-4:]
            else:
                got = (newest or {}).get(field)
            add("%s = %s" % (field, e["equals"]), str(got).strip().lower() == str(e["equals"]).lower(), "portal has: %s" % got)
        elif c == "audit_channel":
            trail = (case or {}).get("audit_trail", [])
            sub = [a for a in trail if a["action"] == "SUBMIT"]
            add("audit trail shows it came through an AI assistant",
                sub and e["contains"] in sub[-1]["note"], "submit note: %s" % (sub[-1]["note"] if sub else "none"))
        elif c == "age_proof_on_file":
            add("age proof stored with the application", (case or {}).get("application", {}).get("age_proof_on_file"),
                "age_proof_on_file=%s" % (case or {}).get("application", {}).get("age_proof_on_file"))
        elif c == "transcript_mentions":
            hit = [w for w in e["any_of"] if w.lower() in text.lower()]
            add("assistant mentioned one of %s" % e["any_of"], hit, "matched: %s" % (hit or "none"))
        elif c == "transcript_lacks_neighbour":
            seen = text + " ".join(t.get("text", "") for t in transcript if t["role"] == "tool_result")
            leaked = state.get("neighbour_app", "@@") in seen
            add("neighbour's application not revealed", not leaked,
                "neighbour app %s %s" % (state.get("neighbour_app"), "LEAKED" if leaked else "not shown"))
    return results


def run_officer_checks(ctx, p, state):
    no = state.get("target_app")
    results = []
    if not no:
        return [{"check": "target application available", "passed": False, "detail": "no target"}]
    case = mcp(ctx["officer_url"], officer_token(ctx), ("get_application", {"application_no": no}))[0]
    status = case.get("application", {}).get("status")
    for e in p["expect"]:
        if e["check"] == "target_status":
            results.append({"check": "%s is %s" % (no, e["status"]), "passed": status == e["status"],
                            "detail": "portal status: %s" % status})
        elif e["check"] == "target_audit":
            rows = [a for a in case.get("audit_trail", []) if a["action"] == e["action"]]
            ok = rows and e["actor_contains"] in rows[-1]["by"] and e["note_contains"].lower() in rows[-1]["note"].lower()
            results.append({"check": "decision recorded against the officer with the reason",
                            "passed": bool(ok), "detail": "audit: %s" % (rows[-1] if rows else "none")})
    return results


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--admin-password", required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--model", default="claude-haiku-4-5")
    ap.add_argument("--citizen-model", default="claude-haiku-4-5")
    ap.add_argument("--label", default="")
    ap.add_argument("--merge", action="store_true",
                    help="replace these personas' results in the latest run instead of starting a new run")
    a = ap.parse_args()
    base = a.base.rstrip("/")
    spec = yaml.safe_load(open(os.path.join(HERE, "personas.yaml"), encoding="utf-8"))
    scheme = requests.get(base + "/assistant", timeout=20)
    ctx = {"base": base, "admin_password": a.admin_password,
           "citizen_url": base + "/mcp/citizen", "officer_url": base + "/mcp/officer",
           "agent_blocks": ["Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon"],
           "kind_of": {p["id"]: "citizens" for p in spec["citizens"]} | {p["id"]: "officers" for p in spec["officers"]}}
    only = set(filter(None, a.only.split(",")))
    run = {"id": datetime.now().strftime("%Y%m%d-%H%M"), "at": datetime.now().strftime("%d %b %Y %H:%M IST"),
           "assistant_model": a.model, "citizen_model": a.citizen_model, "endpoint": base,
           "label": a.label, "results": []}
    citizen_state = {}
    for p in spec["citizens"]:
        if only and p["id"] not in only:
            continue
        t0 = time.time()
        state = {"mobile": fresh_mobile()}
        print("== %s (%s)" % (p["id"], state["mobile"]), flush=True)
        try:
            setup_persona(ctx, p, state)
            token, _, _ = get_token(base, ctx["citizen_url"], "citizen", mobile=state["mobile"],
                                    client_name="Claude Code (eval: %s)" % p["id"])
            opening = p["opening"].replace("{neighbour_mobile}", state.get("neighbour_mobile", ""))
            transcript = converse(ctx, p, token, ctx["citizen_url"], opening, a.model, a.citizen_model)
            checks = run_checks(ctx, p, state, token, transcript)
            apps = mine(ctx, token)
            state["app_nos"] = [x["application_no"] for x in apps]
        except Exception as e:
            transcript, checks = [{"role": "harness", "text": "harness error: %r" % e}], [
                {"check": "run completed", "passed": False, "detail": repr(e)}]
        citizen_state[p["id"]] = state
        res = {"persona_id": p["id"], "kind": "citizen", "mobile": state["mobile"][:2] + "XXXXXX" + state["mobile"][-2:],
               "passed": all(c["passed"] for c in checks), "checks": checks, "transcript": transcript,
               "turns": len([t for t in transcript if t["role"] == "user"]),
               "tool_calls": len([t for t in transcript if t["role"] == "tool_call"]),
               "seconds": int(time.time() - t0)}
        run["results"].append(res)
        print("   ", "PASS" if res["passed"] else "FAIL", [c["check"] for c in checks if not c["passed"]], flush=True)
    for p in spec["officers"]:
        if only and p["id"] not in only:
            continue
        t0 = time.time()
        state = {}
        print("== %s" % p["id"], flush=True)
        try:
            otok = get_token(base, ctx["officer_url"], "officer", password=a.admin_password,
                             client_name="Claude Code (eval: %s)" % p["id"])[0]
            if p["target"] == "held_underage":
                q = mcp(ctx["officer_url"], otok, ("list_pending_applications", {"limit": 50}))[0]
                held = [x for x in q.get("applications", []) if x.get("blockers")]
                state["target_app"] = held[0]["application_no"] if held else None
            else:
                tgt = citizen_state.get(p["target"], {}).get("app_nos") or []
                state["target_app"] = tgt[0] if tgt else None
            if not state["target_app"]:
                raise RuntimeError("no target application for %s" % p["target"])
            opening = p["opening"].replace("{held_app_no}", state["target_app"])
            transcript = converse(ctx, p, otok, ctx["officer_url"], opening, a.model, a.citizen_model)
            checks = run_officer_checks(ctx, p, state)
        except Exception as e:
            transcript, checks = [{"role": "harness", "text": "harness error: %r" % e}], [
                {"check": "run completed", "passed": False, "detail": repr(e)}]
        res = {"persona_id": p["id"], "kind": "officer", "target": state.get("target_app"),
               "passed": all(c["passed"] for c in checks), "checks": checks, "transcript": transcript,
               "turns": len([t for t in transcript if t["role"] == "user"]),
               "tool_calls": len([t for t in transcript if t["role"] == "tool_call"]),
               "seconds": int(time.time() - t0)}
        run["results"].append(res)
        print("   ", "PASS" if res["passed"] else "FAIL", [c["check"] for c in checks if not c["passed"]], flush=True)

    try:
        data = json.load(open(RESULTS, encoding="utf-8"))
    except (OSError, ValueError):
        data = {"runs": []}
    data["personas"] = [dict({k: v for k, v in p.items() if k not in ("expect",)}, kind="citizen",
                             expect=p["expect"]) for p in spec["citizens"]] + \
                       [dict(p, kind="officer") for p in spec["officers"]]
    if a.merge and data.get("runs"):
        latest = data["runs"][0]
        redone = {r["persona_id"] for r in run["results"]}
        for r in run["results"]:
            r["rerun_note"] = "re-run %s (%s)" % (run["at"], a.label or "after a harness fix")
        latest["results"] = [r for r in latest["results"] if r["persona_id"] not in redone] + run["results"]
        order = [p["id"] for p in spec["citizens"] + spec["officers"]]
        latest["results"].sort(key=lambda r: order.index(r["persona_id"]) if r["persona_id"] in order else 99)
    else:
        data["runs"] = [run] + [r for r in data.get("runs", []) if r["id"] != run["id"]]
    json.dump(data, open(RESULTS, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    final = data["runs"][0]["results"]
    print("RESULT %d/%d passed" % (sum(r["passed"] for r in final), len(final)))


if __name__ == "__main__":
    main()
