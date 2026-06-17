/**
 * @verditnxtgen/mcp-middleware — TypeScript SDK
 * 
 * One-line integration: withVerditLedger(server, { apiKey: "..." })
 * Wraps @modelcontextprotocol/sdk Server, intercepts every tool call,
 * signs the payload HMAC-SHA256, and POSTs asynchronously to the ledger.
 * Agent execution is never blocked — logging happens in the background.
 * 
 * Install: npm install @verditnxtgen/mcp-middleware
 */

import { createHmac } from "crypto";

export interface VerditConfig {
  apiKey:   string;
  endpoint?: string;       // default: https://verditnxtgen.com/api/v1/ingest/gateway-log
  secret?:  string;        // HMAC signing secret — defaults to apiKey
  timeout?: number;        // ms for the async POST, default 5000
  onError?: (err: Error) => void;
}

interface GatewayLogPayload {
  api_key:       string;
  event:         "tool_call" | "tool_result" | "tool_error";
  tool_name:     string;
  slug?:         string;
  request_id:    string;
  ts:            string;
  duration_ms?:  number;
  success:       boolean;
  error_class?:  string;
  payload_hash:  string;
  signature:     string;
}

function sign(payload: object, secret: string): string {
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  return createHmac("sha256", secret).update(canonical).digest("hex");
}

async function postAsync(
  endpoint: string,
  body: GatewayLogPayload,
  timeout: number,
  onError?: (err: Error) => void,
): Promise<void> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    await fetch(endpoint, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
      signal:  ctrl.signal,
    });
  } catch (err) {
    onError?.(err as Error);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Wrap any @modelcontextprotocol/sdk McpServer instance.
 * Returns the same server — no structural change to your code.
 * 
 * @example
 * import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
 * import { withVerditLedger } from "@verditnxtgen/mcp-middleware";
 * 
 * const server = withVerditLedger(new McpServer({ name: "my-server", version: "1.0" }), {
 *   apiKey: process.env.VERDIT_API_KEY!,
 * });
 */
export function withVerditLedger<T extends object>(server: T, config: VerditConfig): T {
  const endpoint = config.endpoint ?? "https://verditnxtgen.com/api/v1/ingest/gateway-log";
  const secret   = config.secret   ?? config.apiKey;
  const timeout  = config.timeout  ?? 5000;

  const handler = server as any;
  const originalCallTool = handler._callTool?.bind(handler) ?? handler.callTool?.bind(handler);
  if (!originalCallTool) {
    console.warn("[verditnxtgen] Could not find callTool method — middleware not attached");
    return server;
  }

  const wrapped = async function (name: string, args: unknown, ...rest: unknown[]) {
    const requestId = crypto.randomUUID();
    const start     = Date.now();
    let success     = false;
    let errorClass: string | undefined;

    try {
      const result = await originalCallTool(name, args, ...rest);
      success = true;
      return result;
    } catch (err: any) {
      errorClass = err?.code ?? err?.name ?? "unknown";
      throw err;
    } finally {
      const duration_ms = Date.now() - start;
      const payloadToSign = { tool_name: name, request_id: requestId, ts: new Date().toISOString(), success };
      const payload: GatewayLogPayload = {
        api_key:      config.apiKey,
        event:        success ? "tool_result" : "tool_error",
        tool_name:    name,
        request_id:   requestId,
        ts:           payloadToSign.ts,
        duration_ms,
        success,
        error_class:  errorClass,
        payload_hash: sign({ tool_name: name, args }, secret),
        signature:    sign(payloadToSign, secret),
      };
      // Non-blocking — agent execution continues immediately
      postAsync(endpoint, payload, timeout, config.onError);
    }
  };

  if (handler._callTool)      handler._callTool      = wrapped;
  else if (handler.callTool)  handler.callTool        = wrapped;

  return server;
}
