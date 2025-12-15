import os
import sys
from typing import Any, Dict, List

import requests
from requests.auth import HTTPBasicAuth
from slack_sdk import WebClient

from mcp.server.fastmcp import Context, FastMCP

REQUIRED_ENV_VARS = [
    "MCP_API_KEY",
    "SLACK_BOT_TOKEN",
    "ZENDESK_SUBDOMAIN",
    "ZENDESK_EMAIL",
    "ZENDESK_API_TOKEN",
]


def _require_env() -> Dict[str, str]:
    missing = [name for name in REQUIRED_ENV_VARS if not os.getenv(name)]
    if missing:
        print(f"Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)
    return {name: os.getenv(name, "") for name in REQUIRED_ENV_VARS}


ENV = _require_env()

mcp = FastMCP("zendesk_slack_tools", host="0.0.0.0")
API_KEY = ENV["MCP_API_KEY"]
slack_client = WebClient(token=ENV["SLACK_BOT_TOKEN"])
ZENDESK_BASE = f"https://{ENV['ZENDESK_SUBDOMAIN']}.zendesk.com/api/v2"
zendesk_auth = HTTPBasicAuth(f"{ENV['ZENDESK_EMAIL']}/token", ENV["ZENDESK_API_TOKEN"])
REQUEST_TIMEOUT = 30


def _require_key(ctx: Context):
    auth = (ctx.request.headers.get("authorization") or "").strip()
    if not auth.lower().startswith("bearer "):
        raise PermissionError("Missing MCP key")
    token = auth.split(" ", 1)[1].strip()
    if token != API_KEY:
        raise PermissionError("Invalid MCP key")


@mcp.tool()
def ping():
    return {"ok": True, "service": "mcpzd"}


@mcp.tool()
def slack_post_message(text: str, ctx: Context):
    _require_key(ctx)
    parts = text.split("|", 1)
    if len(parts) != 2:
        raise ValueError("text must be formatted as 'CHANNEL_ID|message'")
    channel, message = parts[0].strip(), parts[1].strip()
    if not channel or not message:
        raise ValueError("Both channel and message are required")
    slack_client.chat_postMessage(channel=channel, text=message)
    return {"status": "sent"}


@mcp.tool()
def zendesk_add_internal_note(ticket_id: str, note: str, ctx: Context):
    _require_key(ctx)
    payload = {
        "ticket": {
            "comment": {
                "body": note,
                "public": False,
            }
        }
    }
    response = requests.put(
        f"{ZENDESK_BASE}/tickets/{ticket_id}.json",
        json=payload,
        auth=zendesk_auth,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return {"status": "ok", "zendesk_status": response.status_code}


@mcp.tool()
def zendesk_list_recent_tickets(limit: int = 10, ctx: Context = None):
    if ctx is None:
        raise RuntimeError("Context is required")
    _require_key(ctx)
    try:
        limit_value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("limit must be an integer") from exc
    limit_value = max(1, min(limit_value, 100))

    params = {
        "sort_by": "created_at",
        "sort_order": "desc",
        "per_page": limit_value,
        "include": "users",
    }
    response = requests.get(
        f"{ZENDESK_BASE}/tickets.json",
        params=params,
        auth=zendesk_auth,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()

    users = {user.get("id"): user for user in data.get("users", [])}
    tickets = data.get("tickets", [])[:limit_value]
    normalized: List[Dict[str, Any]] = []
    for ticket in tickets:
        requester_id = ticket.get("requester_id")
        requester = users.get(requester_id, {})
        requester_name = (
            requester.get("name")
            or requester.get("email")
            or requester_id
        )
        normalized.append(
            {
                "id": ticket.get("id"),
                "subject": ticket.get("subject"),
                "description": ticket.get("description"),
                "requester": requester_name,
                "created_at": ticket.get("created_at"),
                "tags": ticket.get("tags") or [],
            }
        )

    return normalized


def _get_sse_app():
    sse_attr = getattr(mcp, "sse_app", None)
    if sse_attr is None:
        return None
    if callable(sse_attr):
        try:
            candidate = sse_attr()
            if candidate is not None:
                sse_attr = candidate
        except TypeError:
            pass
    return sse_attr


def _legacy_run(host: str, port: int):
    sse_app = _get_sse_app()
    if sse_app is None:
        raise RuntimeError("FastMCP version does not expose sse_app; update the mcp package.")
    import uvicorn

    uvicorn.run(sse_app, host=host, port=port)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    host = "0.0.0.0"
    try:
        mcp.run(transport="sse", host=host, port=port)
    except TypeError as exc:
        message = str(exc)
        if "unexpected keyword argument" not in message:
            raise
        _legacy_run(host, port)
