# -*- coding: utf-8 -*-
"""
Nightly deemed-approval job.

Under the Purvanchal Right to Public Services Act, an application not processed
within the statutory SLA stands approved. This job marks such applications
DEEMED_APPROVED and notifies the applicant by SMS.

Deemed approval cannot grant what an officer could not: an application whose
applicant was under the minimum age on the date of application is held for an
officer's decision (once, with an audit entry) instead of being auto-approved.

Scheduled via cron, 02:00 daily. See deploy/crontab.
"""

import os
import sys
import configparser
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import psycopg2
import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

config = configparser.ConfigParser()
CONFIG_PATH = os.path.join(BASE_DIR, "config", "app.ini")
with open(CONFIG_PATH) as fh:
    config.read_file(fh)

for _section, _key, _env in (("database", "host", "DB_HOST"), ("database", "port", "DB_PORT"),
                             ("database", "name", "DB_NAME"), ("database", "user", "DB_USER"),
                             ("database", "password", "DB_PASSWORD"),
                             ("app", "sms_gateway_url", "SMS_GATEWAY_URL")):
    if os.environ.get(_env):
        config.set(_section, _key, os.environ[_env])

SLA_DAYS = config.getint("pension", "sla_days")
MIN_AGE = config.getint("pension", "min_age")
SMS_GATEWAY_URL = config.get("app", "sms_gateway_url")
IST = ZoneInfo("Asia/Kolkata")


def now_ist():
    """Submission times are stored in IST (the portal's clock); compare like with like."""
    return datetime.now(IST).replace(tzinfo=None)


def main():
    conn = psycopg2.connect(
        host=config.get("database", "host"),
        port=config.get("database", "port"),
        dbname=config.get("database", "name"),
        user=config.get("database", "user"),
        password=config.get("database", "password"),
    )
    cur = conn.cursor()
    now = now_ist()
    cutoff = now - timedelta(days=SLA_DAYS)
    of_age = "dob IS NOT NULL AND dob <= (submitted_at::date - make_interval(years => %s))"

    cur.execute(
        "SELECT a.id FROM applications a "
        "WHERE a.status = 'PENDING' AND a.submitted_at < %s AND NOT (" + of_age + ") "
        "AND NOT EXISTS (SELECT 1 FROM audit_log l WHERE l.application_id = a.id "
        "                AND l.action = 'DEEMED_HELD')",
        (cutoff, MIN_AGE))
    held = [r[0] for r in cur.fetchall()]
    for app_id in held:
        cur.execute("INSERT INTO audit_log (application_id, action, actor, note, at) "
                    "VALUES (%s, 'DEEMED_HELD', 'system:rtps-cron', %s, %s)",
                    (app_id, "SLA passed but the applicant was under %d on the date of "
                             "application; needs an officer's decision" % MIN_AGE, now))

    cur.execute(
        "UPDATE applications "
        "SET status = 'DEEMED_APPROVED', decided_at = %s, decided_by = 'RTPS-AUTO' "
        "WHERE status = 'PENDING' AND submitted_at < %s AND " + of_age + " "
        "RETURNING id, application_no, mobile",
        (now, cutoff, MIN_AGE))
    rows = cur.fetchall()
    for app_id, _, _ in rows:
        cur.execute("INSERT INTO audit_log (application_id, action, actor, note, at) "
                    "VALUES (%s, 'DEEMED_APPROVED', 'system:rtps-cron', "
                    "'not processed within SLA', %s)", (app_id, now))
    conn.commit()
    for _, app_no, mobile in rows:
        try:
            requests.post(SMS_GATEWAY_URL + "/api/send", json={
                "to": mobile,
                "text": "Sewa Setu: your pension application %s stands approved "
                        "under the RTPS Act." % app_no}, timeout=5)
        except Exception:
            pass
    print("%s deemed approval: %d applications approved, %d held for an officer"
          % (now.strftime("%Y-%m-%d %H:%M:%S"), len(rows), len(held)))
    cur.close()
    conn.close()


if __name__ == "__main__":
    sys.exit(main())
