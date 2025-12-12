import inspect
import os
import requests
from requests.auth import HTTPBasicAuth
from slack_sdk import WebClient

from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("zendesk_slack")

API_KEY = os.getenv("MCP_API_KEY", "")

# --- Clients ---
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


def _get_asgi_app():
    attr_candidates = [
        "sse_app",
        "streamable_http_app",
        "app",
        "application",
        "fastapi",
        "_app",
        "_application",
        "_fastapi",
        "asgi_app",
        "_asgi_app",
    ]
    for attr in attr_candidates:
        app = getattr(mcp, attr, None)
        if app is not None:
            return app

    router = getattr(mcp, "router", None) or getattr(mcp, "_router", None)
    if router is not None:
        try:
            from fastapi import FastAPI
        except ImportError as exc:  # pragma: no cover - only triggered in minimal envs
            raise RuntimeError("FastAPI is required to build the SSE app dynamically.") from exc

        fastapi_app = FastAPI()
        fastapi_app.include_router(router)
        return fastapi_app

    return None


def _run_server():
    port = int(os.getenv("PORT", "3333"))
    host = "0.0.0.0"
    os.environ["PORT"] = str(port)

    sig = inspect.signature(mcp.run)
    params = sig.parameters

    run_kwargs = {"transport": "sse"}
    if "host" in params:
        run_kwargs["host"] = host
    if "port" in params:
        run_kwargs["port"] = port
    if "path" in params:
        run_kwargs["path"] = "/sse/"

    if any(key in params for key in ("host", "port", "path")):
        mcp.run(**run_kwargs)
        return

    app = _get_asgi_app()
    if app is None:
        available = ", ".join(sorted(dir(mcp)))
        raise RuntimeError(
            f"FastMCP app handle not found; available attrs: {available}"
        )

    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    # IMPORTANT: this serves MCP over SSE (and will expose /sse/)
    _run_server()
