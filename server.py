import inspect
import os
import requests
from typing import Any, Callable, Dict, List, Optional

from requests.auth import HTTPBasicAuth
from slack_sdk import WebClient

from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("zendesk_slack")

API_KEY = os.getenv("MCP_API_KEY", "")
slack = WebClient(token=os.getenv("SLACK_BOT_TOKEN", ""))

ZENDESK_BASE = f"https://{os.getenv('ZENDESK_SUBDOMAIN')}.zendesk.com/api/v2"
zendesk_auth = HTTPBasicAuth(
    f"{os.getenv('ZENDESK_EMAIL')}/token",
    os.getenv("ZENDESK_API_TOKEN", "")
)


def require_key(ctx: Context):
    auth = (ctx.request.headers.get("authorization") or "").strip()
    token = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else ""
    if token != API_KEY:
        raise PermissionError("Invalid MCP key")


@mcp.tool()
def slack_post_message(text: str, ctx: Context):
    require_key(ctx)
    channel, message = text.split("|", 1)
    slack.chat_postMessage(channel=channel.strip(), text=message.strip())
    return {"status": "sent"}


@mcp.tool()
def zendesk_add_internal_note(ticket_id: str, note: str, ctx: Context):
    require_key(ctx)
    payload = {"ticket": {"comment": {"body": note, "public": False}}}
    r = requests.put(
        f"{ZENDESK_BASE}/tickets/{ticket_id}.json",
        json=payload,
        auth=zendesk_auth,
        timeout=30,
    )
    return {"status": "ok", "zendesk_status": r.status_code}


@mcp.tool()
def zendesk_list_recent_tickets(limit: int = 10, ctx: Context = None):
    if ctx is None:
        raise RuntimeError("Context is required")
    require_key(ctx)
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
        timeout=30,
    )
    response.raise_for_status()

    data = response.json()
    tickets: List[Dict[str, Any]] = data.get("tickets", [])[:limit_value]
    users = {user.get("id"): user for user in data.get("users", [])}

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
        path = scope.get("path") or ""
        normalized_path = path.rstrip("/") or "/"
        if scope.get("type") == "http" and normalized_path == "/sse":
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

        await app(scope, receive, send)

    setattr(_wrapped, "_accept_patch_applied", True)
    return _wrapped


def _ensure_sse_app() -> Optional[Callable]:
    sse_attr = getattr(mcp, "sse_app", None)
    if sse_attr is None:
        return None

    candidate = sse_attr
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
                candidate = (
                    sse_attr("/sse") if requires_path_arg else sse_attr()
                )
            except TypeError:
                candidate = sse_attr()

    if candidate is None:
        return None

    wrapped = _wrap_sse_app_accept(candidate)
    try:
        setattr(mcp, "sse_app", wrapped)
    except Exception:
        pass
    return wrapped


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    host = "0.0.0.0"
    os.environ["PORT"] = str(port)
    sse_app = _ensure_sse_app()

    run_params = inspect.signature(mcp.run).parameters
    run_kwargs = {"transport": "sse"}
    if "host" in run_params:
        run_kwargs["host"] = host
    if "port" in run_params:
        run_kwargs["port"] = port
    if "path" in run_params:
        run_kwargs["path"] = "/sse"

    supports_direct = any(param in run_params for param in ("host", "port", "path"))
    if supports_direct:
        mcp.run(**run_kwargs)
    else:
        if sse_app is None:
            raise RuntimeError("FastMCP version does not expose `sse_app`; update the package.")
        import uvicorn

        uvicorn_params = {"host": host, "port": port}
        try:
            run_sig = inspect.signature(uvicorn.run)
        except (TypeError, ValueError):
            run_sig = None

        allowed_hosts = os.getenv("UVICORN_ALLOWED_HOSTS", "*")
        allowed_hosts_list = [
            entry.strip()
            for entry in allowed_hosts.split(",")
            if entry.strip()
        ] or ["*"]

        if run_sig and "allowed_hosts" in run_sig.parameters:
            uvicorn_params["allowed_hosts"] = allowed_hosts_list

        uvicorn.run(sse_app, **uvicorn_params)
