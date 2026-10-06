# -*- coding: utf-8 -*-
"""
Sewa Setu MCP servers: one for citizens (and the families or CSC operators helping
them), one for block officers. Two separate endpoints on one process:

    /mcp/citizen   tools to apply for the old age pension and follow it up
    /mcp/officer   tools to work the block officer's queue and record decisions

Both are OAuth 2.1 protected resources (RFC 9728). The authorization server is the
Sewa Setu portal itself: a citizen signs in there with mobile + OTP, an officer with the
departmental login, and the assistant never sees either. A token minted for one endpoint
is refused by the other (audience), so a citizen's assistant cannot even list the
officer's tools.

The servers hold no rules and no data. Every call is forwarded, with the person's own
token, to the portal's agent API, which applies the same validations as the website and
remains the system of record.
"""

import base64
import contextlib
import os
import time
from typing import Annotated, Any

import anyio
import jwt
import requests
import uvicorn
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Image, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import ToolAnnotations
from pydantic import Field
from starlette.applications import Starlette
from starlette.responses import JSONResponse

PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")
PORTAL_INTERNAL_URL = os.environ.get("PORTAL_INTERNAL_URL", "http://app:8000").rstrip("/")
CITIZEN_URL = os.environ.get("CITIZEN_MCP_URL", PUBLIC_BASE_URL + "/mcp/citizen").rstrip("/")
OFFICER_URL = os.environ.get("OFFICER_MCP_URL", PUBLIC_BASE_URL + "/mcp/officer").rstrip("/")


# ---------------------------------------------------------------------------
# token verification (resource server side)
# ---------------------------------------------------------------------------

class PortalTokenVerifier:
    """Accepts a portal-issued JWT for exactly one endpoint and role, and only while the
    sign-in behind it is still standing (checked with the portal, cached briefly)."""

    _jwks: dict[str, Any] = {}
    _jwks_at = 0.0

    def __init__(self, role: str, resource: str):
        self.role = role
        self.resource = resource
        self._live: dict[str, float] = {}

    def _key(self, kid):
        if kid not in self._jwks or time.time() - PortalTokenVerifier._jwks_at > 3600:
            doc = requests.get(PORTAL_INTERNAL_URL + "/.well-known/jwks.json", timeout=5).json()
            PortalTokenVerifier._jwks = {k["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(k)
                                         for k in doc["keys"]}
            PortalTokenVerifier._jwks_at = time.time()
        return self._jwks.get(kid)

    def _check(self, token: str) -> AccessToken | None:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            key = self._key(kid)
            if key is None:
                return None
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.resource,
                                issuer=PUBLIC_BASE_URL)
        except Exception:
            return None
        if claims.get("role") != self.role or claims.get("scope") != self.role:
            return None
        if self._live.get(token, 0) < time.time():
            r = requests.get("%s/api/agent/v1/%s/whoami" % (PORTAL_INTERNAL_URL, self.role),
                             headers={"Authorization": "Bearer " + token}, timeout=5)
            if r.status_code != 200:
                return None
            self._live[token] = time.time() + 30
            if len(self._live) > 5000:
                self._live = {t: e for t, e in self._live.items() if e > time.time()}
        return AccessToken(token=token, client_id=claims.get("client_id", ""), scopes=[self.role],
                           expires_at=claims.get("exp"), resource=self.resource,
                           subject=claims.get("sub"), claims=claims)

    async def verify_token(self, token: str) -> AccessToken | None:
        return await anyio.to_thread.run_sync(self._check, token)


# ---------------------------------------------------------------------------
# calling the portal with the person's own token
# ---------------------------------------------------------------------------

def _call(method: str, path: str, **kw) -> dict:
    tok = get_access_token()
    headers = {"Authorization": "Bearer " + tok.token} if tok else {}
    try:
        r = requests.request(method, PORTAL_INTERNAL_URL + "/api/agent/v1" + path,
                             headers=headers, timeout=30, **kw)
        body = r.json()
    except Exception as e:
        return {"ok": False, "error": "portal_unreachable",
                "message": "The Sewa Setu portal could not be reached (%s). Nothing was changed; "
                           "try again in a minute." % type(e).__name__}
    if r.status_code == 401:
        body["message"] = body.get("message", "") + ". Ask the person to sign in again."
    return body


async def portal(method: str, path: str, **kw) -> dict:
    return await anyio.to_thread.run_sync(lambda: _call(method, path, **kw))


READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
FINAL = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)


# ---------------------------------------------------------------------------
# citizen server
# ---------------------------------------------------------------------------

CITIZEN_INSTRUCTIONS = """\
You are helping an elderly person in Purvanchal apply for the Old Age Pension (Rs. 250 a month,
age 60+) on the official Sewa Setu portal, or follow up an application. Often a grandchild,
son/daughter or CSC operator is typing for them. The person is signed in with THEIR mobile number
(the one they verified by OTP); every application here belongs to that mobile number.

How to help well:
- Use scheme_information for any fact about the scheme. Never guess amounts, dates or rules.
- To apply: collect the details in plain, short questions (a few at a time), saving them with
  update_application_draft as you go. The portal tells you what is missing or wrong; relay that
  simply. Do not invent or assume any detail (name spelling, date of birth, bank account, IFSC,
  block) - ask. If they know only their village, use find_block_for_village.
- The age proof must be a real file: upload_age_proof if you have the file, otherwise
  get_age_proof_upload_link and give the link to the person.
- Before submitting, read the summary_to_read_back and the declaration to the applicant and get a
  clear yes. Then call submit_application with the review_code. Never submit without that yes.
- After submitting, give the application number and the decision date, and say an SMS was sent.
- For status questions use my_applications. Explain status and reasons in simple words.
- Applying through an assistant works only in the pilot blocks listed by scheme_information;
  for other blocks, tell them to apply on the website or at the block office counter.
- Never ask for or repeat an OTP or password in the chat. Never promise approval: the block
  officer decides. If the person is under 60, explain kindly that they cannot apply yet.
- Reply in the language the person uses (Hindi, Assamese, Bengali, English or a mix)."""

citizen = MCPServer(
    "sewasetu-citizen",
    title="Sewa Setu - Old Age Pension (citizen)",
    instructions=CITIZEN_INSTRUCTIONS,
    website_url=PUBLIC_BASE_URL + "/assistant",
    token_verifier=PortalTokenVerifier("citizen", CITIZEN_URL),
    auth=AuthSettings(issuer_url=PUBLIC_BASE_URL, resource_server_url=CITIZEN_URL,
                      required_scopes=["citizen"], validate_token_resource=True,
                      service_documentation_url=PUBLIC_BASE_URL + "/assistant"),
)


@citizen.tool(annotations=READ)
async def scheme_information() -> dict:
    """Official, current facts about the Old Age Pension scheme: amount, who can apply, deadline,
    documents, decision time, the pilot blocks where assistants may apply. Use this instead of
    your own knowledge."""
    return await portal("GET", "/scheme")


@citizen.tool(annotations=READ)
async def find_block_for_village(
    village: Annotated[str, Field(description="Village or town name, or part of it")],
) -> dict:
    """Find which block a village belongs to (and whether assistant applications are open there)."""
    return await portal("GET", "/villages", params={"q": village})


@citizen.tool(annotations=READ)
async def my_applications() -> dict:
    """Applications made with the signed-in mobile number: status in plain words, decision date,
    rejection reason, and whether it can be withdrawn. Use for any 'what happened to my
    application' question."""
    return await portal("GET", "/citizen/applications")


@citizen.tool(annotations=READ)
async def get_application_draft() -> dict:
    """The application being prepared for this mobile number: details saved so far, what is still
    missing, any problems, and - when complete - the summary to read back and the review_code."""
    return await portal("GET", "/citizen/draft")


@citizen.tool(annotations=WRITE)
async def update_application_draft(
    applicant_name: Annotated[str | None, Field(description="Full name exactly as on the age proof document")] = None,
    date_of_birth: Annotated[str | None, Field(description="Date of birth as DD/MM/YYYY")] = None,
    gender: Annotated[str | None, Field(description="Male, Female or Other")] = None,
    marital_status: Annotated[str | None, Field(description="Married, Unmarried or Widowed")] = None,
    late_husband_name: Annotated[str | None, Field(description="Only for a widow: late husband's name (optional)")] = None,
    village: Annotated[str | None, Field(description="Village or town")] = None,
    block: Annotated[str | None, Field(description="Block (e.g. Sonari)")] = None,
    bank_account_number: Annotated[str | None, Field(description="Applicant's own bank account number, digits only")] = None,
    ifsc: Annotated[str | None, Field(description="11-character IFSC of the bank branch, from the passbook")] = None,
) -> dict:
    """Save one or more details of the pension application (only the ones given are changed).
    Nothing is submitted. Returns what is still missing and any problems, in plain words."""
    body = {k: v for k, v in {
        "applicant_name": applicant_name, "dob": date_of_birth, "gender": gender,
        "marital_status": marital_status, "husband_name": late_husband_name, "village": village,
        "block": block, "bank_account": bank_account_number, "ifsc": ifsc}.items() if v is not None}
    if not body:
        return await portal("GET", "/citizen/draft")
    return await portal("POST", "/citizen/draft", json=body)


@citizen.tool(annotations=WRITE)
async def upload_age_proof(
    file_name: Annotated[str, Field(description="File name with extension: .jpg, .jpeg, .png or .pdf")],
    content_base64: Annotated[str, Field(description="The file's bytes, base64-encoded (max 5 MB)")],
) -> dict:
    """Attach the age proof (birth certificate, school leaving certificate or Voter ID) to the
    draft. Only a real image or PDF of the document is accepted."""
    return await portal("POST", "/citizen/draft/document",
                        json={"file_name": file_name, "content_base64": content_base64})


@citizen.tool(annotations=WRITE)
async def get_age_proof_upload_link() -> dict:
    """A one-time link (valid 30 minutes) where the person can upload a photo of the age proof from
    their own phone. Use when you cannot attach the file yourself."""
    return await portal("POST", "/citizen/draft/upload-link")


@citizen.tool(annotations=FINAL)
async def submit_application(
    review_code: Annotated[str, Field(description="The review_code from the latest draft, after reading the summary back")],
    declaration_accepted: Annotated[bool, Field(description="True only if the applicant heard the declaration and agreed to it")],
) -> dict:
    """Submit the pension application. Call only after reading summary_to_read_back and the
    declaration to the applicant and getting a clear yes. Returns the application number."""
    return await portal("POST", "/citizen/submit",
                        json={"review_code": review_code, "declaration_accepted": declaration_accepted})


@citizen.tool(annotations=FINAL)
async def withdraw_application(
    application_no: Annotated[str, Field(description="Application number, e.g. SSP26123456")],
    confirmed: Annotated[bool, Field(description="True only after the applicant confirmed they want to withdraw")],
    reason: Annotated[str | None, Field(description="Why, in a few words (optional)")] = None,
) -> dict:
    """Withdraw a PENDING application (cannot be undone), e.g. to correct a mistake and apply
    afresh. Approved applications cannot be withdrawn here."""
    return await portal("POST", "/citizen/withdraw",
                        json={"application_no": application_no, "confirmed": confirmed, "reason": reason or ""})


@citizen.tool(annotations=FINAL)
async def discard_application_draft() -> dict:
    """Throw away the unsubmitted draft for this mobile number and start again."""
    return await portal("DELETE", "/citizen/draft")


# ---------------------------------------------------------------------------
# officer server
# ---------------------------------------------------------------------------

OFFICER_INSTRUCTIONS = """\
You are assisting a block officer of the Department of Social Welfare, Purvanchal, with the
Old Age Pension queue on Sewa Setu. Only the pilot blocks are covered.

- Start with queue_summary, then list_pending_applications (oldest first: closest to deemed
  approval after 15 days). Show blockers and warnings clearly.
- Before recommending a decision, open the case with get_application and, if an age proof is on
  file, look at it with view_age_proof. Explain the checks in plain words.
- Decisions are the officer's: call decide_application only when the officer has said which
  decision to record for which application, with a reason in their words. The reason is kept
  against the officer's name; a rejection reason is sent to the applicant. The portal refuses to
  approve an application that breaks a scheme rule (e.g. under 60 on the date of application).
- Never decide several applications in bulk without the officer naming each one."""

officer = MCPServer(
    "sewasetu-officer",
    title="Sewa Setu - Block officer",
    instructions=OFFICER_INSTRUCTIONS,
    website_url=PUBLIC_BASE_URL + "/assistant",
    token_verifier=PortalTokenVerifier("officer", OFFICER_URL),
    auth=AuthSettings(issuer_url=PUBLIC_BASE_URL, resource_server_url=OFFICER_URL,
                      required_scopes=["officer"], validate_token_resource=True,
                      service_documentation_url=PUBLIC_BASE_URL + "/assistant"),
)


@officer.tool(annotations=READ)
async def queue_summary() -> dict:
    """What is waiting: pending applications per pilot block, how many are past or near the 15-day
    deemed-approval date, cases held back from deemed approval, and today's decisions by you."""
    return await portal("GET", "/officer/summary")


@officer.tool(annotations=READ)
async def list_pending_applications(
    block: Annotated[str | None, Field(description="One pilot block, or omit for all")] = None,
    limit: Annotated[int, Field(description="How many (1-50)", ge=1, le=50)] = 10,
    offset: Annotated[int, Field(description="Skip this many (for the next page)", ge=0)] = 0,
) -> dict:
    """Pending applications, oldest first, each with its decide-by date, blockers and warnings."""
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if block:
        params["block"] = block
    return await portal("GET", "/officer/queue", params=params)


@officer.tool(annotations=READ)
async def search_applications(
    query: Annotated[str, Field(description="Application number, mobile number or part of the applicant's name")],
) -> dict:
    """Find applications (any status) in the pilot blocks."""
    return await portal("GET", "/officer/search", params={"q": query})


@officer.tool(annotations=READ)
async def get_application(
    application_no: Annotated[str, Field(description="Application number, e.g. SSP26123456")],
) -> dict:
    """Full case: applicant details, automatic checks (age on the date of application, age proof,
    IFSC, possible duplicates, days left before deemed approval), earlier applications from the
    same mobile, and the audit trail."""
    return await portal("GET", "/officer/application/" + application_no.strip())


@officer.tool(annotations=READ, structured_output=False)
async def view_age_proof(
    application_no: Annotated[str, Field(description="Application number")],
) -> Any:
    """Show the uploaded age proof document so it can be read and compared with the application."""
    res = await portal("GET", "/officer/application/%s/document" % application_no.strip())
    if not res.get("ok"):
        return res
    data = base64.b64decode(res["content_base64"])
    if res["mime_type"].startswith("image/"):
        return [Image(data=data, format=res["mime_type"].split("/", 1)[1]),
                "Age proof for %s (%s)" % (res["application_no"], res["file_name"])]
    return {"ok": True, "application_no": res["application_no"], "mime_type": res["mime_type"],
            "file_name": res["file_name"],
            "message": "The age proof is a PDF; open it from the admin page: %s/admin" % PUBLIC_BASE_URL,
            "content_base64": res["content_base64"] if len(data) < 300_000 else None}


@officer.tool(annotations=FINAL)
async def decide_application(
    application_no: Annotated[str, Field(description="Application number")],
    decision: Annotated[str, Field(description="'approve' or 'reject'")],
    reason: Annotated[str, Field(description="The officer's reason, recorded against their name (required)")],
) -> dict:
    """Record the officer's decision on a PENDING application, with the reason. Only when the
    officer has asked for this decision on this application."""
    return await portal("POST", "/officer/application/%s/decision" % application_no.strip(),
                        json={"decision": decision, "reason": reason})


@officer.tool(annotations=READ)
async def scheme_rules() -> dict:
    """The scheme's rules and facts (age, amount, deadline, SLA, pilot blocks)."""
    return await portal("GET", "/scheme")


# ---------------------------------------------------------------------------
# one process, two endpoints
# ---------------------------------------------------------------------------

def build_app():
    hosts = [h for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(hosts),
        allowed_hosts=hosts, allowed_origins=["https://" + h for h in hosts])
    citizen_app = citizen.streamable_http_app(streamable_http_path="/mcp/citizen",
                                              transport_security=security, host="0.0.0.0")
    officer_app = officer.streamable_http_app(streamable_http_path="/mcp/officer",
                                              transport_security=security, host="0.0.0.0")

    async def health(request):
        return JSONResponse({"ok": True})

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with citizen.session_manager.run(), officer.session_manager.run():
            yield

    health_app = Starlette(routes=[])
    health_app.add_route("/healthz", health)

    async def router(scope, receive, send):
        if scope["type"] == "lifespan":
            return await outer(scope, receive, send)
        path = scope.get("path", "")
        if path.startswith("/mcp/officer") or path.startswith("/.well-known/oauth-protected-resource/mcp/officer"):
            return await officer_app(scope, receive, send)
        if path.startswith("/mcp/citizen") or path.startswith("/.well-known/oauth-protected-resource/mcp/citizen"):
            return await citizen_app(scope, receive, send)
        return await health_app(scope, receive, send)

    outer = Starlette(lifespan=lifespan)
    return router


app = build_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8100")))
