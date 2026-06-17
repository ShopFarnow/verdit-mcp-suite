#!/usr/bin/env python3
"""
VerditNxtGen Universal MCP Sidecar Proxy
-----------------------------------------
Sits between ANY third-party gateway (IBM ContextForge, Bifrost, MCPX,
Docker MCP Gateway) and the destination MCP tools. Transparent middleman:
  1. Receives MCP JSON-RPC request from upstream gateway
  2. Signs payload with HMAC-SHA256
  3. Forwards to downstream MCP tool server
  4. Asynchronously POSTs telemetry to /api/v1/ingest/gateway-log
  5. Returns downstream response to upstream — zero latency added to path

Environment variables:
  VERDIT_API_KEY       — required
  VERDIT_HMAC_SECRET   — optional, defaults to api key
  VERDIT_ENDPOINT      — default https://verditnxtgen.com/api/v1/ingest/gateway-log
  DOWNSTREAM_URL       — target MCP server, e.g. http://qdrant-mcp:3000
  PROXY_PORT           — listen port, default 8080
"""
from __future__ import annotations
import asyncio, hashlib, hmac as _hmac, json, logging, os, time, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request, threading

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("verdit-proxy")

API_KEY      = os.environ["VERDIT_API_KEY"]
HMAC_SECRET  = os.getenv("VERDIT_HMAC_SECRET", API_KEY)
ENDPOINT     = os.getenv("VERDIT_ENDPOINT", "https://verditnxtgen.com/api/v1/ingest/gateway-log")
DOWNSTREAM   = os.environ["DOWNSTREAM_URL"].rstrip("/")
PORT         = int(os.getenv("PROXY_PORT", "8080"))


def sign(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return _hmac.new(HMAC_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def post_telemetry(body: dict) -> None:
    def _send():
        try:
            data = json.dumps(body).encode()
            req  = urllib.request.Request(ENDPOINT, data=data,
                       headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log.debug("telemetry post failed (non-fatal): %s", e)
    threading.Thread(target=_send, daemon=True).start()


def forward(method: str, path: str, body: bytes, headers: dict) -> tuple[int, bytes, dict]:
    url = f"{DOWNSTREAM}{path}"
    req = urllib.request.Request(url, data=body or None, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {}
    except Exception as e:
        return 502, json.dumps({"error": str(e)}).encode(), {}


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _proxy(self):
        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length) if length else b""
        req_id  = str(uuid.uuid4())
        ts      = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ts_ms   = time.time()

        # Parse tool name from JSON-RPC body
        tool_name = "unknown"
        rpc_method = "unknown"
        try:
            rpc = json.loads(body)
            rpc_method = rpc.get("method", "unknown")
            if rpc_method == "tools/call":
                tool_name = rpc.get("params", {}).get("name", "unknown")
        except Exception:
            pass

        # Sign the request payload
        sig_payload = {"tool_name": tool_name, "request_id": req_id, "ts": ts}
        signature   = sign(sig_payload)
        payload_hash = sign({"body": body.decode(errors="replace")[:500]})

        # Forward downstream
        fwd_headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "content-length")}
        fwd_headers["X-Verdit-Request-Id"] = req_id
        fwd_headers["X-Verdit-Signature"]  = signature

        status, resp_body, resp_headers = forward(self.command, self.path, body, fwd_headers)
        duration_ms = int((time.time() - ts_ms) * 1000)
        success     = 200 <= status < 300

        # Return response
        self.send_response(status)
        for k, v in resp_headers.items():
            if k.lower() not in ("transfer-encoding", "content-encoding"):
                self.send_header(k, v)
        self.send_header("Content-Length", len(resp_body))
        self.end_headers()
        self.wfile.write(resp_body)

        # Async telemetry — never blocks response
        post_telemetry({
            "api_key":      API_KEY,
            "event":        "tool_result" if success else "tool_error",
            "tool_name":    tool_name,
            "rpc_method":   rpc_method,
            "request_id":   req_id,
            "ts":           ts,
            "duration_ms":  duration_ms,
            "success":      success,
            "http_status":  status,
            "payload_hash": payload_hash,
            "signature":    signature,
            "downstream":   DOWNSTREAM,
        })

    def do_GET(self):  self._proxy()
    def do_POST(self): self._proxy()
    def do_PUT(self):  self._proxy()
    def do_DELETE(self): self._proxy()


if __name__ == "__main__":
    log.info("VerditNxtGen Sidecar Proxy — listening on :%d → %s", PORT, DOWNSTREAM)
    HTTPServer(("0.0.0.0", PORT), ProxyHandler).serve_forever()
