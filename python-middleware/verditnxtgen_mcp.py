"""
verditnxtgen-mcp — Python SDK middleware
pip install verditnxtgen-mcp

One-decorator integration for the official Python `mcp` library.
Intercepts every tool call, signs HMAC-SHA256, POSTs asynchronously.
Agent execution is never blocked.

Usage:
    from mcp.server.fastmcp import FastMCP
    from verditnxtgen_mcp import verdit_ledger

    mcp = FastMCP("my-server")

    @mcp.tool()
    @verdit_ledger(api_key=os.environ["VERDIT_API_KEY"])
    async def my_tool(x: int) -> str:
        return str(x * 2)

    # Or wrap the entire server:
    from verditnxtgen_mcp import wrap_server
    wrap_server(mcp, api_key=os.environ["VERDIT_API_KEY"])
"""

from __future__ import annotations
import asyncio, hashlib, hmac, json, os, time, uuid
from functools import wraps
from typing import Any, Callable, Optional
import urllib.request

ENDPOINT = os.getenv(
    "VERDIT_ENDPOINT",
    "https://verditnxtgen.com/api/v1/ingest/gateway-log",
)


def _sign(payload: dict, secret: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def _post_async(body: dict, timeout: float = 5.0) -> None:
    """Fire-and-forget POST in a daemon thread — never blocks the caller."""
    import threading

    def _send():
        try:
            data = json.dumps(body).encode()
            req  = urllib.request.Request(
                ENDPOINT,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=timeout)
        except Exception:
            pass  # silently drop — never affect agent

    t = threading.Thread(target=_send, daemon=True)
    t.start()


def verdit_ledger(
    api_key: str,
    secret: Optional[str] = None,
    endpoint: Optional[str] = None,
):
    """
    Decorator for individual MCP tool functions.

    @mcp.tool()
    @verdit_ledger(api_key="vng-...")
    async def search(query: str) -> str: ...
    """
    _secret   = secret or api_key
    _endpoint = endpoint or ENDPOINT

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            request_id = str(uuid.uuid4())
            ts_start   = time.time()
            success    = False
            error_cls: Optional[str] = None
            try:
                result  = await fn(*args, **kwargs) if asyncio.iscoroutinefunction(fn) else fn(*args, **kwargs)
                success = True
                return result
            except Exception as exc:
                error_cls = type(exc).__name__
                raise
            finally:
                ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                payload = {
                    "api_key":      api_key,
                    "event":        "tool_result" if success else "tool_error",
                    "tool_name":    fn.__name__,
                    "request_id":   request_id,
                    "ts":           ts,
                    "duration_ms":  int((time.time() - ts_start) * 1000),
                    "success":      success,
                    "error_class":  error_cls,
                    "payload_hash": _sign({"fn": fn.__name__, "args": str(args)[:200], "kwargs": str(kwargs)[:200]}, _secret),
                    "signature":    _sign({"tool_name": fn.__name__, "request_id": request_id, "ts": ts, "success": success}, _secret),
                }
                _post_async(payload)

        return wrapper
    return decorator


def wrap_server(server: Any, api_key: str, secret: Optional[str] = None) -> Any:
    """
    Wrap every registered tool on a FastMCP / Server instance.

    from verditnxtgen_mcp import wrap_server
    wrap_server(mcp, api_key=os.environ["VERDIT_API_KEY"])
    """
    _secret = secret or api_key
    tools   = getattr(server, "_tools", {}) or getattr(server, "tools", {})
    for name, tool in tools.items():
        fn = getattr(tool, "fn", None) or getattr(tool, "func", None)
        if fn and callable(fn):
            setattr(tool, "fn" if hasattr(tool, "fn") else "func",
                    verdit_ledger(api_key=api_key, secret=_secret)(fn))
    return server
