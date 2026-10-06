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
