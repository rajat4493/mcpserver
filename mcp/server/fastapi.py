from __future__ import annotations

import inspect
from functools import wraps
from typing import Iterable, Optional

from fastapi import FastAPI
from fastapi.concurrency import run_in_threadpool


class MCPServer:
    """
    Minimal helper that turns regular Python callables into FastAPI tool routes.
    """

    def __init__(self, app: FastAPI, prefix: str = "/tools"):
        self.app = app
        self.prefix = prefix.rstrip("/") or ""

    def tool(
        self,
        name: Optional[str] = None,
        path: Optional[str] = None,
        methods: Iterable[str] = ("POST",),
    ):
        """
        Decorator that registers a tool handler as a FastAPI route.
        """

        def decorator(func):
            endpoint_name = name or func.__name__
            route_path = path or self._default_path(endpoint_name)
            endpoint = func

            if not inspect.iscoroutinefunction(func):
                # Run sync tools in the threadpool so FastAPI remains async-friendly.
                @wraps(func)
                async def endpoint(*args, **kwargs):
                    return await run_in_threadpool(func, *args, **kwargs)

            self.app.add_api_route(route_path, endpoint, methods=list(methods))
            return func

        return decorator

    def _default_path(self, endpoint_name: str) -> str:
        if not self.prefix:
            return f"/{endpoint_name}"
        return f"{self.prefix}/{endpoint_name}"


__all__ = ["MCPServer"]
