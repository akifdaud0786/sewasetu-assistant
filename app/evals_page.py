# -*- coding: utf-8 -*-
"""/eval-dashboard: the personas, conversations, checks and results of the evals."""

import json
import os

from flask import Blueprint, render_template, abort

evals_page = Blueprint("evals_page", __name__)

RESULTS_PATH = os.environ.get("EVAL_RESULTS",
                              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "evals_data", "results.json"))


def _load():
    try:
        with open(RESULTS_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"runs": [], "personas": []}


def describe(e):
    """One expectation from personas.yaml, in words."""
    c = e.get("check")
    return {
        "active_application": lambda: "one active application, status %s" % e.get("status"),
        "no_application": lambda: "no application created",
        "active_count": lambda: "exactly %s active application(s) for the mobile" % e.get("equals"),
        "status_count": lambda: "%s application(s) %s" % (e.get("equals"), e.get("status")),
        "no_status": lambda: "nothing %s" % e.get("status"),
        "field": lambda: "%s is %s" % (e.get("field", "").replace("_", " "), e.get("equals")),
        "audit_channel": lambda: "audit trail says it came through an AI assistant",
        "age_proof_on_file": lambda: "age proof stored with the application",
        "transcript_mentions": lambda: "assistant mentions %s" % " / ".join(e.get("any_of", [])),
        "transcript_lacks_neighbour": lambda: "neighbour's application never revealed",
        "target_status": lambda: "the application is %s" % e.get("status"),
        "target_audit": lambda: "%s recorded against the officer, with the reason" % e.get("action"),
    }.get(c, lambda: str(e))()


@evals_page.app_template_filter("expectation")
def _expectation_filter(e):
    return describe(e)


@evals_page.get("/eval-dashboard")
def dashboard():
    return render_template("eval_dashboard.html", data=_load())


@evals_page.get("/eval-dashboard/<run_id>/<persona_id>")
def conversation(run_id, persona_id):
    data = _load()
    for run in data.get("runs", []):
        if run.get("id") == run_id:
            for res in run.get("results", []):
                if res.get("persona_id") == persona_id:
                    persona = next((p for p in data.get("personas", []) if p.get("id") == persona_id), {})
                    return render_template("eval_conversation.html", run=run, res=res, persona=persona)
    abort(404)


@evals_page.get("/eval-dashboard.json")
def dashboard_json():
    return _load()
