# Sewa Setu, agent-ready: design note

**What exists.** Two MCP servers over streamable HTTP on the portal's own origin:
`/mcp/citizen` (apply, upload age proof, submit, follow up, withdraw) and `/mcp/officer` (queue,
case with automatic checks, view the age proof, approve or reject with a reason). Both are OAuth 2.1
protected resources whose authorization server is the portal itself. A citizen signs in on the portal
with mobile number + OTP, an officer with the departmental login. An eval dashboard is at
`/eval-dashboard`. Assistant applications are piloted in four blocks: Sonari, Rajapara,
Dhemaji Pathar and Borgaon (`AGENT_BLOCKS`).

## The three decisions that mattered most

**1. The rules stay in the portal; the MCP servers are thin.**
The MCP servers hold no rules and no data. Every tool forwards the person's own token to a portal
agent API. That API calls the same `validate_application` / `create_application` /
`decide_application` the web form and the admin pages call. "An assistant is just another way to
apply" then holds by construction, not by discipline: an application made in either place is the same
row, and visible in both.

While doing this I tightened the shared rules, so every channel gained them:
- IFSC, gender and marital status are now required.
- A date of birth cannot be in the future.
- The age-proof file must actually exist.
- One active application per mobile is enforced under a lock and a unique index. Before this, a
  retried request or two channels could create a second live application.
- An approval, whether by an officer or by the nightly deemed-approval job, is refused if the
  applicant was under 60 on the date of application. The seed data had 2,849 such pensions already
  granted. The deemed-approval job would have kept adding to them.

**2. Two endpoints, two audiences, and the person consents on the portal.**
A token's audience is the endpoint it was minted for, and its role comes from how the person signed
in. A citizen's assistant therefore cannot list the officer's tools, let alone call them. The OTP is
typed only on the portal's page, never in the chat. Every sign-in carries a session id kept across
token rotation, so a citizen who taps "end sign-in" on a shared phone or kiosk stops the assistant at
once, not 20 minutes later. A token is checked twice: by the MCP server (so the client is asked to
re-authenticate) and again by the portal.

**3. The submit step is built for an elderly person, not for the model.**
The assistant fills a server-side draft, so nothing lives in the chat's memory. The portal answers each
save with what is missing, in plain words. When the draft is complete, the portal returns a summary to
read back, the declaration, and a short review code. `submit` requires that code and an explicit
`declaration_accepted`. If anything changed after the read-back, the code no longer matches and the
submit is refused.

The age proof does not have to pass through the chat. The assistant hands out a one-time link that
the grandson opens on his phone. Officers get the reverse: the case comes with the checks they would
otherwise do by hand. A decision needs a reason, recorded against the officer's name. A rejection
reason is shown to the applicant.

## What the evals changed

Ten citizens and two officers are played by a model against Claude Code (Haiku) connected to the live
endpoints. Each run is judged by the portal's state afterwards, not by the chat.

- **First run:** the assistant told the grandson on the bus that the application had to come from his
  grandmother's own phone, and sent them to the counter. My instructions had said "signed in with
  THEIR mobile". The portal has no such rule. The instructions and scheme facts now say plainly that a
  family member's phone is fine.
- **Second run:** the assistant asked one question per message and ran out of turns before submitting.
  The assessor also runs with limited turns, so it now asks for everything missing in one message and
  gives the upload link up front.

The dashboard shows each run's pass rate.

## What I would do differently with more time

I would give each block officer their own login, mapped to their block, instead of the single
departmental `admin` account. Today the officer assistant covers all four pilot blocks, and "recorded
against her name" means against `admin`. That is the weakest point of the officer design. The portal
needs an officers table, with block-scoped queues and decisions, before the assistant's audit trail
means what the Director wants it to mean.
