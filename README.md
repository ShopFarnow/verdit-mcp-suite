# VerditNxtGen MCP Suite

**Add cryptographic compliance logging to any MCP server in one line.**

VerditNxtGen runs a daily Ghost Swarm that sandbox-tests 190+ open-source MCP tools in Docker, scores them for deployment reliability, detects OWASP vulnerabilities at runtime, and generates HMAC-SHA256 signed manifests for SOC2 compliance.

This repository contains the client-side SDKs and proxy that connect your MCP infrastructure to the VerditNxtGen compliance ledger.

---

## Packages

| Package | Language | Install |
|---|---|---|
| [verditnxtgen-mcp-middleware](ts-middleware/) | TypeScript | `npm install verditnxtgen-mcp-middleware` |
| [verditnxtgen-mcp](python-middleware/) | Python | `pip install verditnxtgen-mcp` |
| [Sidecar Proxy](sidecar-proxy/) | Docker | `docker pull ghcr.io/shopfarnow/verditnxtgen-sidecar` |

Get an API key at [verditnxtgen.com/connect-mcp](https://verditnxtgen.com/connect-mcp.html) — free tier, no credit card.

---

## TypeScript — one line

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { withVerditLedger } from "verditnxtgen-mcp-middleware";

const server = withVerditLedger(
  new McpServer({ name: "my-server", version: "1.0" }),
  { apiKey: process.env.VERDIT_API_KEY }
);
// Every tool call is now HMAC-signed and logged to the compliance ledger.
// Zero latency impact — telemetry posts fire-and-forget in the background.
```

## Python — one decorator

```python
from mcp.server.fastmcp import FastMCP
from verditnxtgen_mcp import verdit_ledger

mcp = FastMCP("my-server")

@mcp.tool()
@verdit_ledger(api_key="YOUR_VERDIT_API_KEY")
async def query_database(sql: str) -> str:
    ...
```

## Docker Sidecar — zero code changes

```yaml
services:
  verdit-sidecar:
    image: ghcr.io/shopfarnow/verditnxtgen-sidecar:latest
    environment:
      VERDIT_API_KEY: "${VERDIT_API_KEY}"
      DOWNSTREAM_URL: "http://your-mcp-tool:3000"
    ports:
      - "8080:8080"
  # Point your gateway at verdit-sidecar:8080 instead of your tool directly
```

---

## What you get

After logging starts, the [VerditNxtGen Intelligence Dashboard](https://verditnxtgen.com/dashboard) shows:

- **Compliance Ledger**: HMAC-SHA256 signed manifest for every tool — chain-of-custody proof for SOC2 Type II audits
- **OWASP scan results**: LLM01 prompt injection, LLM06 PII boundary, LLM08 vector weakness detection from live sandbox runs
- **pass@k curves**: Statistical deployment reliability (pass@1, pass@3, pass@5) across 700+ sandbox runs
- **Cost intelligence**: Compute cost per run across resource profiles

---

## Links

- [Live platform](https://verditnxtgen.com)
- [Intelligence Dashboard](https://verditnxtgen.com/dashboard)
- [Score Methodology](https://verditnxtgen.com/score-methodology.html)
- [Get API key](https://verditnxtgen.com/connect-mcp.html)
- [Main repo](https://github.com/ShopFarnow/VerditNxtGen) (private — proprietary Ghost Swarm engine)

---

## License

MIT — see individual package directories.
