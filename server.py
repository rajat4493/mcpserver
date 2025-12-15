import inspect
import json
import logging
import os
import sys
from typing import Any, Callable, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth
from slack_sdk import WebClient

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

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
        logger.error("Missing required environment variables: %s", ", ".join(missing))
        sys.exit(1)
    return {name: os.getenv(name, "") for name in REQUIRED_ENV_VARS}


ENV = _require_env()

mcp = FastMCP(
    "zendesk_slack_tools",
    host="0.0.0.0",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
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


def _wrap_sse_app_accept(app: Callable):
    if getattr(app, "_accept_patch_applied", False):  # type: ignore[attr-defined]
        return app

    async def _wrapped(scope, receive, send):
        if scope.get("type") == "http":
            original_path = scope.get("path") or ""
            normalized_path = original_path.rstrip("/") or "/"
            if normalized_path == "/sse":
                headers = list(scope.get("headers") or [])
                has_accept = False
                for idx, (key, value) in enumerate(headers):
                    if key.lower() == b"accept":
                        has_accept = True
                        if b"text/event-stream" not in value.lower():
                            headers[idx] = (key, value + b",text/event-stream")
                        break
                if not has_accept:
                    headers.append((b"accept", b"text/event-stream"))
                scope = dict(scope)
                scope["headers"] = headers
                if scope.get("path") != "/sse":
                    scope["path"] = "/sse"
        await app(scope, receive, send)

    setattr(_wrapped, "_accept_patch_applied", True)
    return _wrapped


def _resolve_sse_app() -> Optional[Callable]:
    sse_attr = getattr(mcp, "sse_app", None)
    if sse_attr is None:
        return None

    candidate: Optional[Callable] = sse_attr

    if callable(sse_attr):
        try:
            sig = inspect.signature(sse_attr)
        except (TypeError, ValueError):
            sig = None

        should_call = False
        requires_path_arg = False
        if sig is not None:
            params = list(sig.parameters.values())
            if params and params[0].name == "self":
                params = params[1:]
            if not params:
                should_call = True
            else:
                first = params[0]
                if first.name != "scope":
                    should_call = True
                    if (
                        first.default is inspect._empty
                        and first.kind
                        in (
                            inspect.Parameter.POSITIONAL_ONLY,
                            inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        )
                    ):
                        requires_path_arg = True
        if should_call:
            try:
                if requires_path_arg:
                    candidate = sse_attr("/sse")
                else:
                    candidate = sse_attr()
            except TypeError:
                candidate = sse_attr()

    if candidate is None:
        return None
    return _wrap_sse_app_accept(candidate)


async def _send_json(send, status_code: int, payload: Dict[str, Any]):
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _send_text(send, status_code: int, text: str):
    body = text.encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [(b"content-type", b"text/plain; charset=utf-8")],
        }
    )
    await send({"type": "http.response.body", "body": body})


class RootApp:
    def __init__(self, sse_app: Callable):
        self.sse_app = sse_app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.sse_app(scope, receive, send)

        raw_path = scope.get("path") or ""
        normalized_path = raw_path.rstrip("/") or "/"

        if normalized_path == "/health":
            return await _send_json(send, 200, {"status": "ok"})
        if normalized_path == "/":
            return await _send_text(send, 200, "MCP server is running. Use /health or /sse.")
        if normalized_path == "/sse" and raw_path != "/sse":
            sse_scope = dict(scope)
            sse_scope["path"] = "/sse"
            return await self.sse_app(sse_scope, receive, send)
        return await self.sse_app(scope, receive, send)


def main():
    sse_app = _resolve_sse_app()
    if sse_app is None:
        logger.error("FastMCP version does not expose sse_app; please upgrade the mcp package.")
        sys.exit(1)

    host = "0.0.0.0"
    port = int(os.getenv("PORT", "8080"))
    root_app = RootApp(sse_app)

    logger.info("MCP SSE listening on http://%s:%s/sse", host, port)

    try:
        import uvicorn
    except ImportError as exc:
        logger.error("uvicorn is required to run the server: %s", exc)
        sys.exit(1)

    run_kwargs = {
        "host": host,
        "port": port,
        "log_level": "info",
        "reload": False,
        "access_log": True,
    }
    try:
        run_sig = inspect.signature(uvicorn.run)
    except (TypeError, ValueError):
        run_sig = None
    if run_sig and "allowed_hosts" in run_sig.parameters:
        run_kwargs["allowed_hosts"] = ["*"]

    uvicorn.run(root_app, **run_kwargs)


if __name__ == "__main__":
    main()
