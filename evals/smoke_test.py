# -*- coding: utf-8 -*-
"""
End-to-end smoke test through a real MCP client: a citizen applies, the officer approves.
Usage: python smoke_test.py <portal base> <citizen mcp url> <officer mcp url> <admin password>
"""

import asyncio
import base64
import json
import random
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

import httpx2
from portal_auth import get_token

# smallest valid PNG (1x1)
PNG = base64.b64encode(bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360000002000154a24f5d0000000049454e44ae426082")).decode()


def show(label, result):
    text = result.content[0].text if result.content and hasattr(result.content[0], "text") else str(result.content)
    print("--", label, "->", text[:600])
    try:
        return json.loads(text)
    except ValueError:
        return {}


async def session_call(url, token, calls):
    async with httpx2.AsyncClient(headers={"Authorization": "Bearer " + token}, timeout=60) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, *_):
            async with ClientSession(read, write) as s:
                await s.initialize()
                tools = await s.list_tools()
                print("tools:", [t.name for t in tools.tools])
                out = {}
                for label, name, args in calls:
                    if callable(args):
                        args = args(out)
                    out[label] = show(label, await s.call_tool(name, args))
                return out


async def main(base, curl, ourl, admin_pw):
    mobile = "9" + "".join(random.choice("0123456789") for _ in range(9))
    print("citizen mobile", mobile)
    ctok, _, _ = get_token(base, curl, "citizen", mobile=mobile)
    res = await session_call(curl, ctok, [
        ("scheme", "scheme_information", {}),
        ("village", "find_block_for_village", {"village": "Lakhi"}),
        ("draft1", "update_application_draft", {"applicant_name": "Kamala Devi Gogoi", "date_of_birth": "12/03/1955",
                                                "gender": "Female", "marital_status": "Widowed",
                                                "late_husband_name": "Bhupen Gogoi", "village": "Lakhipur", "block": "sonari"}),
        ("draft2", "update_application_draft", {"bank_account_number": "3456 7890 1234", "ifsc": "sbin0003077"}),
        ("doc", "upload_age_proof", {"file_name": "voter_id.png", "content_base64": PNG}),
        ("bad_submit", "submit_application", {"review_code": "WRONG", "declaration_accepted": True}),
        ("submit", "submit_application", lambda o: {"review_code": o["doc"]["review_code"], "declaration_accepted": True}),
        ("again", "submit_application", lambda o: {"review_code": o["doc"]["review_code"], "declaration_accepted": True}),
        ("mine", "my_applications", {}),
    ])
    app_no = res["submit"]["application_no"]
    # a citizen token must not work on the officer endpoint
    try:
        await session_call(ourl, ctok, [])
        print("!! citizen token accepted by officer endpoint")
    except Exception as e:
        print("officer endpoint refused citizen token:", type(e).__name__)
    otok, _, _ = get_token(base, ourl, "officer", password=admin_pw)
    await session_call(ourl, otok, [
        ("summary", "queue_summary", {}),
        ("queue", "list_pending_applications", {"block": "Sonari", "limit": 3}),
        ("case", "get_application", {"application_no": app_no}),
        ("doc", "view_age_proof", {"application_no": app_no}),
        ("no_reason", "decide_application", {"application_no": app_no, "decision": "approve", "reason": ""}),
        ("approve", "decide_application", {"application_no": app_no, "decision": "approve",
                                           "reason": "Age verified from voter ID; bank details in order"}),
    ])
    await session_call(curl, ctok, [("after", "my_applications", {})])


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:5]))
