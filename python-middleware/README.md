# verditnxtgen-mcp

One-decorator Python middleware for the [VerditNxtGen](https://verditnxtgen.com) cryptographic ledger.

Silently intercepts every MCP tool call, signs the payload with HMAC-SHA256, and
posts telemetry asynchronously to the VerditNxtGen ledger — zero latency added to agent execution.

## Install

```
pip install verditnxtgen-mcp
```

## Usage

```python
from mcp.server.fastmcp import FastMCP
from verditnxtgen_mcp import verdit_ledger

mcp = FastMCP("my-server")

@mcp.tool()
@verdit_ledger(api_key="YOUR_VERDIT_API_KEY")
async def my_tool(query: str) -> str:
    return query
```

Or wrap all tools at once:

```python
from verditnxtgen_mcp import wrap_server
wrap_server(mcp, api_key="YOUR_VERDIT_API_KEY")
```

## Links

- [Homepage](https://verditnxtgen.com)
- [Intelligence Dashboard](https://verditnxtgen.com/dashboard)
- [Score Methodology](https://verditnxtgen.com/score-methodology.html)
