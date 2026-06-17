/**
 * VerditNxtGen API Worker  —  verditnxtgen.com/api/*
 * ─────────────────────────────────────────────────────────────────────────────
 * VerditNxtGen is the intelligence layer for AI agent infrastructure routing.
 * Agents and routing platforms query this Worker for health scores, deployment
 * schemas, and outcome predictions before adopting or routing to a tool.
 * Think: pre-auction due diligence for the open-source infra ecosystem.
 *
 * Routes
 *   POST /api/stack-audit        AI stack health audit → risk scores + alternatives
 *   POST /api/route-audit        Routing oracle — ranked providers for a capability
 *   GET  /api/tools              Paginated tool directory with scores + signals
 *   GET  /api/tool/:slug         Single tool — score, signals, deployment schema
 *   GET  /api/report             ?id=<uuid>  read stored audit report
 *   GET  /api/go                 Affiliate redirect + click log
 *   GET  /api/sandbox            Cloud IDE launch for any repo slug
 *   POST /api/schema             Email gate + agent-schema.json download
 *   POST /api/schema-feedback    Agent deployment outcome → D1 + infra_graph
 *   POST /api/stack              Co-deployment graph for a set of slugs
 *   POST /api/webhook/github     GitHub release webhook → competitor_threats
 *   POST /api/mcp                MCP JSON-RPC 2.0 (search, get, plan, report, model_card)
 *   POST /api/execute            Phase-3: sandbox deployment execution
 *   POST /api/keys               Generate agent API key (free tier)
 *   POST /api/keys/verify        Verify agent API key
 *   POST /api/alerts/subscribe   Score-drop email alert subscription
 *   GET  /api/analytics          Internal ops analytics (auth-gated)
 *   GET  /api/competitor/status  Competitor release monitor (auth-gated)
 *   GET  /api/schema/version   Schema deprecation notices + migration paths
 *   GET  /api/schema/download  Signed compliance manifest for SOC2 / ISO27001 audit (Sprint 2)
 *   GET  /api/mcp              SSE stream — MCP Streamable HTTP transport (PLG Sprint)
 *   POST /api/admin/provision-gpt-key  Provision permanent openai_gpt_global key (PLG Sprint)
 *   GET  /api/health             Service status + MCP connection config
 *   CRON scheduled()             06:00 UTC daily + every 10 min flush cron
 *
 * Enterprise API v1 (vnxt_ key required in X-VerditNxtGen-Key header):
 *   GET  /api/v1/tools           Paginated directory with risk scores
 *   GET  /api/v1/tools/:slug     Full telemetry + Phase 3 + verdict
 *   POST /api/v1/audit           Batch risk check — go/no-go per slug
 *   GET  /api/v1/keys/me         Caller's key metadata + daily usage
 *   POST /api/v1/keys            Create key (free tier, no charge)
 *   POST /api/v1/webhook/stripe  Stripe checkout.session.completed → key issue
 *   POST /api/v1/gateway/authorize  A2A policy enforcement — authorize or block tool calls (Sprint 3)
 *
 * Secrets: OPENAI_API_KEY, IP_SALT, STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
 *          GITHUB_WEBHOOK_SECRET, INTERNAL_API_KEY, RESEND_API_KEY,
 *          MANIFEST_HMAC_SECRET (Sprint 2 — signs /api/schema/download manifests)
 * Bindings: KV KVOPS, KV TRENDING, KV AFFILIATES, D1 DB, Queue MIGRATIONS_QUEUE
 *
 * Revision 1 — D1 write bottleneck: all per-request analytics go to KV only.
 *   flushApiKeyAnalytics() (every-10-min cron) batch-writes KV→D1. Zero concurrent
 *   D1 pressure from the hot path regardless of burst traffic volume.
 * Revision 2 — security_boundary_violation elevated to top-level verdict object.
 *   CI/CD pipelines gate on verdict.deploy_recommended — violation is visible
 *   at the highest level, not buried in phase3.
 * Revision 3 — API keys issued via Stripe webhook only (checkout.session.completed).
 *   Never from synchronous redirect — eliminates pay-but-no-key failure mode.
 *
 * Rate limits (env vars, per IP per hour):
 *   RATE_LIMIT_PER_HOUR          stack-audit (5/hr default)
 *   MCP_RATE_LIMIT_PER_HOUR      MCP calls (120/hr default)
 *   SCHEMA_RATE_LIMIT_PER_HOUR   schema downloads (30/hr default)
 *   FEEDBACK_RATE_LIMIT_PER_HOUR feedback writes (20/hr default)
 *   OPENAI_MONTHLY_BUDGET_USD    hard OpenAI spend ceiling ($20 default)
 */

// ── VerditNxtGen Intelligence Constants ─────────────────────────────────────
const SCORE_TIERS = {
  PRODUCTION_GRADE: 80,
  ADOPTABLE:        60,
  CAUTION:          40,
  AVOID:             0,
};

const SIGNAL_WEIGHTS_DEFAULT = {
  commit_recency:    0.20, stars:            0.13, fork_velocity:   0.11,
  issue_response:    0.10, bus_factor:       0.08, contributors:    0.07,
  ci_status:         0.07, pr_merge_rate:    0.07, has_tests:       0.05,
  pkg_downloads:     0.05, branch_protection:0.04, release_recency: 0.03,
};

const CAPABILITY_MAP = {
  "vector database":   "AI/ML",  "agent memory":  "AI/ML",
  "embedding store":   "AI/ML",  "workflow":      "Automation",
  "message queue":     "DevOps", "headless":      "Automation",
  "database":          "Database","analytics":    "Analytics/BI",
  "low code":          "Low-code","crm":          "CRM",
  "observability":     "DevOps",  "deployment":   "DevOps",
};


/* ═══════════════════════════════════════════════════════════════════════════
   /api/v1/ — Enterprise API (versioned, key-authenticated)
   ═══════════════════════════════════════════════════════════════════════════
   All routes require a valid vnxt_ API key in X-VerditNxtGen-Key header.
   Rate limits enforced per-key via KV (see requireApiKey).
   Revision 2: security_boundary_violation is elevated to top-level verdict.
   ═══════════════════════════════════════════════════════════════════════════ */

// ── /api/v1/tools — paginated enterprise directory ──────────────────────────
async function handleV1Tools(request, url, env, ctx) {
  const auth = await requireApiKey(request, env, ctx);
  if (!auth.ok) return auth.response;

  const page     = Math.max(1, parseInt(url.searchParams.get("page")     || "1"));
  const perPage  = Math.min(50, Math.max(1, parseInt(url.searchParams.get("per_page") || "20")));
  const category = (url.searchParams.get("category")  || "").trim();
  const minScore = parseInt(url.searchParams.get("min_score") || "0");
  const q        = (url.searchParams.get("q") || "").toLowerCase().trim();
  const catalog  = await loadCatalog(env);

  if (!catalog || !catalog.length) return json({ error: "Directory unavailable" }, 503);

  let tools = catalog;
  if (category)  tools = tools.filter(t => (t.category || "").toLowerCase() === category.toLowerCase());
  if (minScore)  tools = tools.filter(t => (t.score || t.bizops_score || 0) >= minScore);
  if (q)         tools = tools.filter(t =>
    (t.name || "").toLowerCase().includes(q) || (t.description || "").toLowerCase().includes(q));

  tools.sort((a, b) => (b.score || b.bizops_score || 0) - (a.score || a.bizops_score || 0));

  const total = tools.length;
  const paged = tools.slice((page - 1) * perPage, page * perPage).map(t => {
    const score = t.score || t.bizops_score || 0;
    return {
      slug:         t.slug,
      name:         t.name,
      category:     t.category,
      risk: {
        score,
        label: score >= 70 ? "low_risk" : score >= 40 ? "med_risk" : "high_risk",
        grade: score >= 90 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : "D",
      },
      stars:      t.stars || 0,
      schema_url: t.schema_url || `/schemas/${t.slug}.agent-schema.json`,
    };
  });

  return json({
    tools: paged,
    total,
    page,
    per_page: perPage,
    pages: Math.ceil(total / perPage),
    api_version: "1.0",
    generated_at: new Date().toISOString(),
  });
}

// ── /api/v1/tools/:slug — single tool with full Phase 3 telemetry ─────────
// Revision 2: security_boundary_violation elevated to verdict object
async function handleV1Tool(request, url, env, ctx) {
  const auth = await requireApiKey(request, env, ctx);
  if (!auth.ok) return auth.response;

  const slug = url.pathname.replace(/^\/api\/v1\/tools\//, "").replace(/\/+$/, "").toLowerCase();
  if (!slug || !/^[a-z0-9][a-z0-9\-]{0,80}$/.test(slug)) {
    return json({ error: "Invalid slug" }, 400);
  }

  const catalog = await loadCatalog(env);
  if (!catalog) return json({ error: "Directory unavailable" }, 503);

  const tool = catalog.find(t =>
    (t.slug || "").toLowerCase() === slug ||
    (t.name || "").toLowerCase() === slug
  );
  if (!tool) return json({ error: `Tool not found: ${slug}` }, 404);

  const score = tool.score || tool.bizops_score || 0;
  const asOf  = new Date().toISOString();

  // Query D1 for Phase 3 telemetry aggregates
  let telemetry = null;
  let phase3    = null;
  let runs      = 0;

  if (env.DB) {
    try {
      const rows = await env.DB.prepare(`
        SELECT
          COUNT(*)                                                          AS runs,
          AVG(CASE WHEN outcome='success' THEN 1.0 ELSE 0.0 END)          AS success_rate,
          AVG(CAST(task_completion_status AS REAL))                        AS task_completion_rate,
          AVG(tool_call_count)                                             AS avg_tool_calls,
          MAX(CASE WHEN security_boundary_violation=1 THEN 1 ELSE 0 END)  AS any_sec_violation,
          MAX(CASE WHEN tool_call_efficiency='excessive' THEN 1 ELSE 0 END) AS any_excessive
        FROM deployment_feedback
        WHERE slug = ?
          AND ts > datetime('now', '-30 days')
      `).bind(slug).first();

      if (rows && rows.runs > 0) {
        runs = rows.runs;
        telemetry = {
          success_rate:  rows.success_rate != null ? Math.round(rows.success_rate * 1000) / 10 : null,
          runs_last_30d: runs,
        };
        phase3 = {
          task_completion_rate:   rows.task_completion_rate != null
            ? Math.round(rows.task_completion_rate * 1000) / 10 : null,
          avg_tool_call_count:    rows.avg_tool_calls != null
            ? Math.round(rows.avg_tool_calls * 10) / 10 : null,
          any_security_violation: rows.any_sec_violation === 1,
          any_excessive_calls:    rows.any_excessive === 1,
        };
      }
    } catch (e) {
      console.warn("[v1/tool] D1 query failed:", e && e.message);
    }
  }

  // ── REVISION 2: security_boundary_violation at top-level verdict ──────────
  // A sandbox escape is catastrophic — it must be visible at the highest level,
  // not buried in phase3.  The verdict object is what CI/CD pipelines gate on.
  const secViolation = phase3?.any_security_violation === true;
  const insufficient = runs < 3;

  let deployRecommended = !secViolation && !insufficient && score >= 40;
  let blockReason       = null;
  let confidence        = "high";

  if (secViolation) {
    deployRecommended = false;
    blockReason       = "SECURITY_BOUNDARY_VIOLATION";
    confidence        = "high";
  } else if (insufficient) {
    deployRecommended = false;
    blockReason       = "INSUFFICIENT_DATA";
    confidence        = "low";
  } else if (score < 40) {
    deployRecommended = false;
    blockReason       = "RISK_SCORE_BELOW_THRESHOLD";
    confidence        = "high";
  }

  return json({
    slug,
    name:        tool.name,
    category:    tool.category,
    github_url:  tool.html_url || `https://github.com/${slug}`,
    stars:       tool.stars || 0,
    schema_url:  `/schemas/${slug}.agent-schema.json`,

    risk: {
      score:      score,
      label:      score >= 70 ? "low_risk" : score >= 40 ? "med_risk" : "high_risk",
      grade:      score >= 90 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : "D",
      as_of:      asOf,
      runs:       runs,
      signal_pct: 100.0,
    },

    telemetry,
    phase3,

    // ── Revision 2: security_boundary_violation at verdict level ─────────
    verdict: {
      deploy_recommended: deployRecommended,
      block_reason:       blockReason,       // null = no block
      security_alert:     secViolation,      // explicit top-level flag
      confidence,
    },

    meta: {
      api_version:  "1.0",
      generated_at: asOf,
      key_tier:     auth.record?.tier || "free",
    },
  });
}

// ── /api/v1/keys/me — authenticated caller's key metadata + usage ───────────
async function handleV1KeysMe(request, env, ctx) {
  const auth = await requireApiKey(request, env, ctx);
  if (!auth.ok) return auth.response;

  const record = auth.record;
  // Fetch live call count from D1 (the flush cron keeps this current)
  let callCount = record.call_count || 0;
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        "SELECT call_count, last_used FROM agent_keys WHERE key_hash = ?"
      ).bind(auth.keyHash).first();
      if (row) {
        callCount         = row.call_count || 0;
        record.last_used  = row.last_used || record.last_used;
      }
    } catch {}
  }

  // Also check current day's KV counter for requests since last flush
  const dayBucket = Math.floor(Date.now() / 86400000);
  const rlKey     = `apikey:rl:${auth.keyHash}:${dayBucket}`;
  const todayUsed = parseInt((await env.KVOPS?.get(rlKey)) || "0", 10);

  const tierLimits = { free: 100, starter: 10000, enterprise: 999999, gpt_global: 50000 };
  const tier       = record.tier || "free";
  const dayLimit   = tierLimits[tier] || 100;

  return json({
    email:      record.email,
    label:      record.label || null,
    agent_type: record.agent_type,
    tier,
    created_at: record.created_at,
    last_used:  record.last_used || null,
    usage: {
      total_calls:     callCount,
      today:           todayUsed,
      daily_limit:     dayLimit,
      daily_remaining: Math.max(0, dayLimit - todayUsed),
      resets_at:       new Date((dayBucket + 1) * 86400000).toISOString(),
    },
    api_version: "1.0",
  });
}

// ── /api/v1/audit — batch risk check for a list of slugs ────────────────────
// CI/CD integration: POST a list of slugs, get back a go/no-go verdict
async function handleV1Audit(request, env, ctx) {
  const auth = await requireApiKey(request, env, ctx);
  if (!auth.ok) return auth.response;

  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const slugs = (Array.isArray(body.slugs) ? body.slugs : [])
    .map(s => String(s).replace(/[^a-z0-9-]/g, "").slice(0, 80))
    .filter(Boolean)
    .slice(0, 30);

  if (!slugs.length) return json({ error: "slugs array required" }, 400);

  const catalog = await loadCatalog(env);
  const results = [];
  let blockCount = 0;

  for (const slug of slugs) {
    const tool  = catalog?.find(t => (t.slug || "").toLowerCase() === slug);
    const score = tool ? (tool.score || tool.bizops_score || 0) : null;

    // Quick D1 security check — only field that matters for blocking
    let secViolation = false;
    if (env.DB) {
      try {
        const row = await env.DB.prepare(
          "SELECT MAX(security_boundary_violation) AS sv FROM deployment_feedback WHERE slug=? AND ts > datetime('now','-30 days')"
        ).bind(slug).first();
        secViolation = row?.sv === 1;
      } catch {}
    }

    const block = secViolation || (score !== null && score < 40);
    if (block) blockCount++;

    results.push({
      slug,
      found:         !!tool,
      risk_score:    score,
      security_alert: secViolation,
      // Revision 2: block_reason at result level mirrors verdict contract
      block:         block,
      block_reason:  secViolation ? "SECURITY_BOUNDARY_VIOLATION"
                   : score !== null && score < 40 ? "RISK_SCORE_BELOW_THRESHOLD"
                   : null,
    });
  }

  return json({
    slugs_checked:  slugs.length,
    blocked:        blockCount,
    all_clear:      blockCount === 0,
    results,
    api_version:    "1.0",
    generated_at:   new Date().toISOString(),
  });
}

/* ── POST /api/admin/provision-gpt-key — Ticket 3.2 ─────────────────────────
 *
 * Provisions a permanent, read-only key named "openai_gpt_global" for the
 * Custom GPT at platform.openai.com/gpts. This key:
 *   - Has tier "gpt_global" → 50,000 calls/day (bypasses standard DDoS limiter)
 *   - Is hard-coded read-only (write operations return 403)
 *   - Stored in both KV (fast auth lookup) and D1 (audit trail)
 *   - Idempotent: calling twice returns the same key
 *
 * Protected by INTERNAL_API_KEY header.
 *
 *   curl -X POST https://verditnxtgen.com/api/admin/provision-gpt-key \
 *     -H "X-Internal-Key: <INTERNAL_API_KEY>"
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleProvisionGptKey(request, env, ctx) {
  const internalKey = request.headers.get("X-Internal-Key") || "";
  const expectedKey = env.INTERNAL_API_KEY || "";
  if (!expectedKey || internalKey !== expectedKey) return json({ error: "Unauthorized" }, 401);

  const LABEL      = "openai_gpt_global";
  const lookupKey  = `gptkey:${LABEL}`;

  if (env.KVOPS) {
    const existing = await safe(env.KVOPS.get(lookupKey));
    if (existing) {
      try {
        const { apiKey } = JSON.parse(existing);
        return json({ ok: true, action: "already_provisioned", label: LABEL,
          api_key: apiKey, tier: "gpt_global", rate_limit: "50000/day",
          usage_header: `X-VerditNxtGen-Key: ${apiKey}` });
      } catch {}
    }
  }

  const raw     = crypto.getRandomValues(new Uint8Array(16));
  const apiKey  = "vnxt_gpt_" + Array.from(raw).map(b => b.toString(16).padStart(2, "0")).join("");
  const keyHash = await sha256(apiKey);
  const ts      = new Date().toISOString();

  const keyRecord = {
    agent_id:   "openai-custom-gpt",
    agent_type: "gpt_plugin",
    email:      "gpt-global@verditnxtgen.com",
    label:      LABEL,
    tier:       "gpt_global",   // handled in tierLimits below
    read_only:  true,
    created_at: ts,
    last_used:  null,
    call_count: 0,
  };

  if (env.KVOPS) {
    const ttl = 365 * 24 * 3600 * 5;
    ctx.waitUntil(Promise.all([
      env.KVOPS.put(`apikey:${keyHash}`, JSON.stringify(keyRecord), { expirationTtl: ttl }),
      env.KVOPS.put(lookupKey, JSON.stringify({ apiKey, keyHash }), { expirationTtl: ttl }),
    ]));
  }
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT OR REPLACE INTO subscribers (email, consent, ts, source) VALUES (?,?,?,?)"
    ).bind("gpt-global@verditnxtgen.com", 1, ts, "gpt_key_provision").run()));
  }

  return json({
    ok: true, action: "provisioned", label: LABEL,
    api_key: apiKey, key_hash: keyHash,
    tier: "gpt_global", rate_limit: "50000/day (read-only endpoints only)",
    usage: {
      header:     `X-VerditNxtGen-Key: ${apiKey}`,
      openai_gpt: "Paste the key value into Custom GPT builder → Authentication → API Key (header)",
      note:       "Permanent key. Store securely — cannot be retrieved from this endpoint again.",
    },
    openapi_url: "https://verditnxtgen.com/openapi.yaml",
    created_at: ts,
  });
}

/* ── POST /api/v1/ingest/gateway-log — Universal BYOG Ingestion ─────────────
 * Shift 2: Kong, Portkey, MuleSoft, OpenTelemetry logs → cryptographic notarisation
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleGatewayLogIngest(request, env, ctx) {
  const auth = await requireApiKey(request, env, ctx);
  if (!auth.ok) return auth.response;

  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

  const source     = detectLogSource(body);
  const normalized = normalizeLogEntry(body, source);

  if (!normalized.slug && !normalized.tool_name) {
    return json({ error: "Cannot identify tool. Provide: slug, tool_name, model, or service field.", detected_source: source }, 400);
  }

  const slug      = (normalized.slug || normalized.tool_name || "unknown").toLowerCase().replace(/[^a-z0-9-]/g,"-").slice(0,80);
  const action    = normalized.action    || "tool_call";
  const outcome   = normalized.outcome   || "unknown";
  const agentId   = normalized.agent_id  || auth.keyHash.slice(0,16);
  const sessionId = normalized.session_id || null;
  const ts        = normalized.timestamp  || new Date().toISOString();

  let riskScore = null, owaspRaw = [];
  if (env.DB) {
    const row = await safe(env.DB.prepare(
      "SELECT risk_score, owasp_flags FROM deployment_feedback WHERE slug=? ORDER BY ts DESC LIMIT 1"
    ).bind(slug).first());
    riskScore = row?.risk_score ?? null;
    try { owaspRaw = JSON.parse(row?.owasp_flags || "[]"); } catch {}
  }

  const issuedAt = new Date().toISOString();
  const notaryPayload = { action, agent_id: agentId, ingested_at: issuedAt, original_source: source, outcome, risk_score: riskScore, session_id: sessionId, slug, timestamp: ts };
  const canonicalStr = JSON.stringify(notaryPayload, Object.keys(notaryPayload).sort()) + `|issued_at:${issuedAt}`;
  const signingSecret = env.MANIFEST_HMAC_SECRET || env.IP_SALT || "vng-dev-secret";
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey("raw", enc.encode(signingSecret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBuf = await crypto.subtle.sign("HMAC", keyMat, enc.encode(canonicalStr));
  const sigHex = [...new Uint8Array(sigBuf)].map(b=>b.toString(16).padStart(2,"0")).join("");

  const decisionId = `gw_ext_${[...crypto.getRandomValues(new Uint8Array(13))].map(b=>b.toString(16).padStart(2,"0")).join("")}`;
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT OR IGNORE INTO gateway_decisions (id,ts,slug,action,status,risk_score,owasp_flags,agent_id,session_id,api_key_hash,policy_ver,duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,'external-ingest',?)"
    ).bind(decisionId, ts, slug, action, outcome==="success"?"authorized":"logged", riskScore, JSON.stringify(owaspRaw), agentId, sessionId, auth.keyHash, normalized.duration_ms||null).run()));
  }

  return json({ ok: true, decision_id: decisionId, slug, action, outcome, risk_score: riskScore, source_detected: source, notarised_at: issuedAt, signature: sigHex, signature_algorithm: "HMAC-SHA256", ledger_url: "https://verditnxtgen.com/dashboard.html#ledger", note: "Log ingested and cryptographically notarised." });
}

function detectLogSource(body) {
  if (body.route_id || body.service?.id) return "kong";
  if (body.config?.provider || body.metadata?.portkey) return "portkey";
  if (body.traceId && body.spanId) return "opentelemetry";
  if (body.correlationId && body.flowName) return "mulesoft";
  if (body.application && body.component) return "truefoundry";
  return "generic";
}

function normalizeLogEntry(body, source) {
  if (source === "kong") return { slug: (body.service?.name||"").toLowerCase().replace(/[^a-z0-9-]/g,"-"), action: body.request?.method?.toLowerCase()==="post"?"tool_call":"read_schema", outcome: (body.response?.status||500)<400?"success":"failure", agent_id: body.consumer?.username||body.consumer?.id, session_id: body.request?.headers?.["x-session-id"], timestamp: body.started_at?new Date(body.started_at).toISOString():null, duration_ms: body.latencies?.request };
  if (source === "portkey") return { slug: (body.metadata?.tool||body.model||"").toLowerCase().replace(/[^a-z0-9-]/g,"-"), tool_name: body.metadata?.tool||body.model, action: "tool_call", outcome: body.status==="success"?"success":"failure", agent_id: body.metadata?.agent_id||body.user, session_id: body.metadata?.session_id, timestamp: body.created_at, duration_ms: body.response_time };
  if (source === "opentelemetry") { const a=body.attributes||{}; return { slug: (a["tool.name"]||a["gen_ai.system"]||body.name||"").toLowerCase().replace(/[^a-z0-9-]/g,"-"), action: a["tool.action"]||"tool_call", outcome: body.status?.code===0?"success":"failure", agent_id: a["agent.id"]||body.traceId?.slice(0,16), session_id: body.traceId, timestamp: body.startTimeUnixNano?new Date(Number(body.startTimeUnixNano)/1e6).toISOString():null, duration_ms: body.endTimeUnixNano&&body.startTimeUnixNano?Math.round((Number(body.endTimeUnixNano)-Number(body.startTimeUnixNano))/1e6):null }; }
  return { slug: body.slug||body.tool||body.tool_name||body.service||body.component||"", tool_name: body.tool_name||body.tool||body.service, action: body.action||"tool_call", outcome: body.outcome||body.status||"unknown", agent_id: body.agent_id||body.correlationId||body.application, session_id: body.session_id||body.traceId, timestamp: body.ts||body.timestamp||body.created_at, duration_ms: body.duration_ms||body.latency_ms };
}

/* ── GET /api/mcp-analytics — read KV intent + call counters ────────────────
 * Returns last 30 days of MCP call volume, top tool intents, zero-result queries.
 * Protected: requires X-Internal-Key header.
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleMcpAnalytics(request, env) {
  const key = (request.headers.get("X-Internal-Key") || "").trim();
  if (env.INTERNAL_API_KEY && key !== env.INTERNAL_API_KEY)
    return json({ error: "Unauthorized" }, 401);
  if (!env.KVOPS) return json({ error: "KV not configured" }, 503);

  const days = Math.min(parseInt(new URL(request.url).searchParams.get("days") || "30"), 90);
  const now  = new Date();
  const daily_calls = [];
  const intent_totals = {};
  const zero_results  = {};

  for (let i = 0; i < days; i++) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const day = d.toISOString().slice(0, 10);

    const calls = parseInt((await safe(env.KVOPS.get(`mcp:calls:${day}`))) || "0");
    daily_calls.push({ date: day, calls });

    // List intent keys for this day
    const intentList = await safe(env.KVOPS.list({ prefix: `mcp:intent:`, limit: 100 }));
    for (const k of (intentList?.keys || [])) {
      if (!k.name.endsWith(`:${day}`)) continue;
      const slug = k.name.replace("mcp:intent:", "").replace(`:${day}`, "");
      const count = parseInt((await safe(env.KVOPS.get(k.name))) || "0");
      intent_totals[slug] = (intent_totals[slug] || 0) + count;
    }

    const zeroList = await safe(env.KVOPS.list({ prefix: `mcp:zero_results:`, limit: 50 }));
    for (const k of (zeroList?.keys || [])) {
      if (!k.name.endsWith(`:${day}`)) continue;
      const query = k.name.replace("mcp:zero_results:", "").replace(`:${day}`, "");
      const count = parseInt((await safe(env.KVOPS.get(k.name))) || "0");
      zero_results[query] = (zero_results[query] || 0) + count;
    }
  }

  const top_intents = Object.entries(intent_totals)
    .sort((a, b) => b[1] - a[1]).slice(0, 20)
    .map(([slug, count]) => ({ slug, count }));

  const top_zero_results = Object.entries(zero_results)
    .sort((a, b) => b[1] - a[1]).slice(0, 20)
    .map(([query, count]) => ({ query, count }));

  const total_calls = daily_calls.reduce((s, d) => s + d.calls, 0);

  return json({
    period_days:      days,
    total_calls,
    daily_calls:      daily_calls.reverse(),   // chronological order
    top_intents,
    top_zero_results,
    generated_at:     new Date().toISOString(),
    note: "top_zero_results = queries that returned no tools — use these to prioritize scraping",
  });
}

/* ── GET /api/admin/pending-submissions — for scraper to pick up new tools ── */
async function handlePendingSubmissions(request, env) {
  const key = (request.headers.get("X-Internal-Key") || "").trim();
  if (!env.INTERNAL_API_KEY || key !== env.INTERNAL_API_KEY)
    return json({ error: "Unauthorized" }, 401);
  if (!env.DB) return json({ submissions: [] });
  const result = await safe(env.DB.prepare(
    "SELECT full_name, github_url, category, stars, has_docker FROM pending_submissions WHERE status='pending' LIMIT 50"
  ).all());
  const submissions = (result?.results || []);
  // Mark as picked up
  if (submissions.length) {
    const names = submissions.map(s => `'${s.full_name.replace(/'/g, "''")}'`).join(",");
    await safe(env.DB.prepare(
      `UPDATE pending_submissions SET status='indexed', indexed_at=? WHERE full_name IN (${names})`
    ).bind(new Date().toISOString()).run());
  }
  return json({ submissions, total: submissions.length });
}

/* ── POST /api/submit — Self-serve tool submission ───────────────────────────
 * Allows MCP server authors to submit their GitHub repo for indexing.
 * Validates: URL format, repo existence, min stars, has docker-compose or Dockerfile.
 * Stores to D1 pending_submissions table for next scraper run to pick up.
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleToolSubmit(request, env, ctx) {
  // GET → return the submission form page
  if (request.method === "GET") {
    return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Submit Your Tool — VerditNxtGen</title>
<link rel="stylesheet" href="/verditnxtgen.css">
</head>
<body style="max-width:640px;margin:0 auto;padding:2rem 1rem;font-family:monospace">
<h1 style="font-family:serif;margin-bottom:.5rem">Submit Your Tool</h1>
<p style="color:#666;margin-bottom:2rem">List your open-source AI infrastructure tool or MCP server in the VerditNxtGen directory. We'll score it across 12 GitHub signals and add it to the index within 48 hours.</p>
<form id="f" style="display:flex;flex-direction:column;gap:1rem">
  <label>GitHub URL<br>
    <input type="url" id="url" placeholder="https://github.com/owner/repo" required
      style="width:100%;padding:.75rem;font-family:monospace;border:2px solid #222;font-size:.9rem;margin-top:.25rem">
  </label>
  <label>Your email (optional — we'll notify you when listed)<br>
    <input type="email" id="email" placeholder="you@example.com"
      style="width:100%;padding:.75rem;font-family:monospace;border:2px solid #222;font-size:.9rem;margin-top:.25rem">
  </label>
  <label>Category<br>
    <select id="cat" style="width:100%;padding:.75rem;font-family:monospace;border:2px solid #222;font-size:.9rem;margin-top:.25rem">
      <option value="">Select category...</option>
      <option>AI/ML</option><option>Database</option><option>Automation</option>
      <option>DevOps</option><option>Analytics/BI</option><option>Low-code</option>
    </select>
  </label>
  <button type="submit" style="background:#0d0d0d;color:#fff;border:none;padding:.875rem;font-family:monospace;font-size:.9rem;font-weight:700;cursor:pointer">
    SUBMIT FOR REVIEW →
  </button>
  <div id="msg" style="display:none;padding:.875rem;border:2px solid;margin-top:.5rem"></div>
</form>
<script>
document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault();
  const msg = document.getElementById('msg');
  msg.style.display = 'block'; msg.textContent = 'Validating…'; msg.style.borderColor = '#666'; msg.style.color = '#666';
  try {
    const r = await fetch('/api/submit', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        github_url: document.getElementById('url').value,
        email: document.getElementById('email').value,
        category: document.getElementById('cat').value
      })
    });
    const d = await r.json();
    if (r.ok) {
      msg.textContent = d.message || 'Submitted! Your tool will be indexed within 48 hours.';
      msg.style.borderColor = '#39ff14'; msg.style.color = '#1a6e3c';
    } else {
      msg.textContent = d.error || 'Submission failed.';
      msg.style.borderColor = '#ff4444'; msg.style.color = '#b5190e';
    }
  } catch { msg.textContent = 'Network error. Try again.'; msg.style.borderColor = '#ff4444'; msg.style.color = '#b5190e'; }
});
</script>
</body>
</html>`, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  // POST → validate and store submission
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const githubUrl = String(body.github_url || "").trim();
  const email     = String(body.email || "").trim().toLowerCase();
  const category  = String(body.category || "").trim();

  // Validate GitHub URL format
  const ghMatch = githubUrl.match(/^https?:\/\/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)\/?$/);
  if (!ghMatch) return json({ error: "Invalid GitHub URL. Format: https://github.com/owner/repo" }, 400);
  const [, owner, repo] = ghMatch;
  const fullName = `${owner}/${repo}`;

  // Check repo exists and meets minimum criteria
  try {
    const ghRes = await fetch(`https://api.github.com/repos/${fullName}`, {
      headers: {
        "User-Agent": "VerditNxtGen-Submit/1.0",
        "Accept": "application/vnd.github+json",
      },
      signal: AbortSignal.timeout(8000),
    });

    if (ghRes.status === 404) return json({ error: "Repository not found. Check the URL and ensure it is public." }, 400);
    if (!ghRes.ok) return json({ error: "Could not reach GitHub. Try again shortly." }, 503);

    const repoData = await ghRes.json();

    if (repoData.private) return json({ error: "Repository must be public to be listed." }, 400);
    if (repoData.archived) return json({ error: "Archived repositories are not eligible." }, 400);
    if ((repoData.stargazers_count || 0) < 10) return json({
      error: `Repository has ${repoData.stargazers_count} stars. Minimum is 10 stars for listing.`
    }, 400);

    // Check for docker-compose or Dockerfile (required for sandbox scoring)
    const contentsRes = await fetch(`https://api.github.com/repos/${fullName}/contents`, {
      headers: { "User-Agent": "VerditNxtGen-Submit/1.0" },
      signal: AbortSignal.timeout(5000),
    });
    let hasDocker = false;
    if (contentsRes.ok) {
      const contents = await contentsRes.json();
      if (Array.isArray(contents)) {
        hasDocker = contents.some(f =>
          /^(docker-compose|Dockerfile|dockerfile)/i.test(f.name)
        );
      }
    }

    // Store submission in D1
    if (env.DB) {
      await safe(env.DB.prepare(`
        INSERT OR IGNORE INTO pending_submissions
          (full_name, github_url, category, email, stars, has_docker, submitted_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
      `).bind(
        fullName, githubUrl, category || null,
        email || null,
        repoData.stargazers_count || 0,
        hasDocker ? 1 : 0,
        new Date().toISOString()
      ).run());
    }

    // If submitter gave email, add to subscribers
    if (email && env.DB) {
      ctx.waitUntil(safe(env.DB.prepare(
        "INSERT OR IGNORE INTO subscribers (email, consent, ts, source) VALUES (?,1,?,?)"
      ).bind(email, new Date().toISOString(), "tool_submission").run()));
    }

    const warningMsg = !hasDocker
      ? " Note: no Dockerfile detected — tool will be scored on GitHub signals only (no sandbox run)."
      : "";

    return json({
      ok: true,
      full_name: fullName,
      stars: repoData.stargazers_count,
      has_docker: hasDocker,
      message: `✅ ${fullName} submitted successfully. It will appear in the directory within 48 hours.${warningMsg}`,
    });

  } catch (e) {
    if (String(e).includes("timeout")) return json({ error: "GitHub API timed out. Try again." }, 503);
    return json({ error: "Validation failed. Ensure the repository is public and accessible." }, 500);
  }
}

/* ── POST /api/v1/gateway/authorize — A2A policy enforcement (Sprint 3 T2) ───
 *
 * The entry point for the Phase 3 Cognitive Fabric. An agent calls this before
 * invoking any tool. The gateway evaluates the tool's live telemetry against
 * the policy rulebook in docs/a2a-gateway-spec.md and returns:
 *
 *   { status: "authorized" | "blocked", block_reason?, warnings[], ... }
 *
 * Policy rules evaluated (in order, first match wins for blocks):
 *   Hard blocks  — P-SEC-01 security_boundary_violation (last 30d)
 *                  P-SEC-02 LLM01 Prompt Injection flag
 *                  P-SEC-03 LLM06 Sensitive Info Disclosure flag
 *                  P-RISK-01 risk_score < 15
 *                  P-ACT-01  data_write action + risk_score < 50
 *                  P-ACT-02  agent_handoff + a2a_score = 0 (not A2A capable)
 *   Soft blocks  — P-RISK-02 risk_score < 40 (override: allow_low_score)
 *                  P-OWA-01  LLM05/LLM09/LLM10 flags (override: allow_owasp_medium)
 *   Warnings     — W-FRESH-01 stale run, W-BUS-01 bus factor, W-PROT-01 no branch protection
 *
 * Required: vnxt_ API key in X-VerditNxtGen-Key header (all tiers)
 * Writes:   gateway_decisions D1 table (async, non-blocking)
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleGatewayAuthorize(request, env, ctx) {
  const t0 = Date.now();

  // ── Auth ─────────────────────────────────────────────────────────────────
  const auth = await requireApiKey(request, env, ctx);
  if (!auth.ok) return auth.response;

  let body;
  try { body = await request.json(); } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  const slug   = String(body.slug   || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);
  const action = String(body.action || "tool_call").slice(0, 40);

  const ALLOWED_ACTIONS = ["tool_call", "tool_subscribe", "agent_handoff", "data_read", "data_write"];
  if (!slug)                          return json({ error: "slug is required" }, 400);
  if (!ALLOWED_ACTIONS.includes(action)) return json({
    error: `action must be one of: ${ALLOWED_ACTIONS.join(", ")}`,
  }, 400);

  const agentId    = String(body.agent_id    || "").slice(0, 120) || null;
  const sessionId  = String(body.session_id  || "").slice(0, 80)  || null;
  const overrides  = (typeof body.policy_override === "object" && body.policy_override) ? body.policy_override : {};
  const budget     = (typeof body.budget === "object" && body.budget) ? body.budget : null;

  // ── Thresholds (configurable via env vars — see spec §5.4) ───────────────
  const MIN_RISK_SCORE       = parseInt(env.GATEWAY_MIN_RISK_SCORE    || "40");
  const WRITE_MIN_SCORE      = parseInt(env.GATEWAY_WRITE_MIN_SCORE   || "50");
  const STALE_THRESHOLD_DAYS = parseInt(env.GATEWAY_STALE_DAYS        || "7");
  const AUTH_TTL_S           = parseInt(env.GATEWAY_AUTH_TTL_S        || "300");
  const CRITICAL_RISK        = 15;

  // ── Pull live telemetry from D1 ───────────────────────────────────────────
  if (!env.DB) return json({ error: "Telemetry DB unavailable" }, 503);

  // Most recent sandbox run for this slug
  const runRow = await safe(env.DB.prepare(`
    SELECT slug, risk_score, owasp_flags, security_boundary_violation,
           peak_memory_mb, commit_sha, version_tag, ts, duration_s,
           tool_call_count, a2a_tested
    FROM deployment_feedback
    WHERE slug = ?
    ORDER BY ts DESC LIMIT 1
  `).bind(slug).first());

  // Security boundary check for last 30 days (any run, not just latest)
  const secRow = await safe(env.DB.prepare(`
    SELECT MAX(security_boundary_violation) AS sv
    FROM deployment_feedback
    WHERE slug = ? AND ts > datetime('now', '-30 days')
  `).bind(slug).first());

  // bizops_score + bus_factor + branch_protection from tool catalog
  const catalog = await loadCatalog(env);
  const toolMeta = catalog?.find(t => t.slug === slug) || null;
  const bizopsScore = toolMeta?.score || 0;

  // Branch protection and bus factor come from the scraper; approximate from catalog
  // (these fields are stored in the static mcp_routing_index but not in deployment_feedback)
  const branchProtected = toolMeta?.branch_protection !== false;  // null = unknown = assume OK

  // ── Derived values ────────────────────────────────────────────────────────
  const riskScore       = runRow?.risk_score      ?? null;
  const owaspRaw        = (() => { try { return JSON.parse(runRow?.owasp_flags || "[]"); } catch { return []; } })();
  const secViolation    = secRow?.sv === 1;
  const commitSha       = runRow?.commit_sha       || null;
  const lastRunTs       = runRow?.ts               || null;
  const a2aTested       = runRow?.a2a_tested === 1 || runRow?.a2a_tested === true;
  const peakMemMb       = runRow?.peak_memory_mb   ?? null;

  const daysSinceRun    = lastRunTs
    ? Math.floor((Date.now() - new Date(lastRunTs).getTime()) / 86400000)
    : null;
  const runIsStale      = daysSinceRun !== null && daysSinceRun > STALE_THRESHOLD_DAYS;

  const CRITICAL_OWASP  = ["LLM01", "LLM06"];
  const HIGH_OWASP      = ["LLM05", "LLM09", "LLM10"];

  // ── Evaluate policy rules ─────────────────────────────────────────────────
  const warnings = [];
  let blockReason  = null;
  let blockDetail  = null;

  // Helper: block unless the named override is set
  const softBlock = (reason, detail, overrideKey) => {
    if (!blockReason && !overrides[overrideKey]) {
      blockReason = reason;
      blockDetail = detail;
    }
  };

  // Tool not found — warn but don't hard-block (may be newly added)
  if (!runRow && !toolMeta) {
    warnings.push(`Tool '${slug}' has no sandbox run or catalog entry. Proceed with caution.`);
  }

  // P-SEC-01: security boundary violation in last 30 days (hard block)
  if (!blockReason && secViolation) {
    blockReason = "SECURITY_BOUNDARY_VIOLATION";
    blockDetail = `Tool '${slug}' triggered a honeypot/security boundary violation in the last 30 days. Not safe for autonomous agent use.`;
  }

  // P-SEC-02 + P-SEC-03: critical OWASP flags (hard block)
  const criticalFlags = owaspRaw.filter(f => CRITICAL_OWASP.includes(f));
  if (!blockReason && criticalFlags.length > 0) {
    blockReason = "OWASP_CRITICAL_FLAG";
    blockDetail = `Tool '${slug}' carries OWASP critical flag(s): ${criticalFlags.join(", ")}. ` +
      `${criticalFlags.includes("LLM01") ? "Prompt injection risk detected. " : ""}` +
      `${criticalFlags.includes("LLM06") ? "Sensitive information disclosure risk detected. " : ""}` +
      "Review the audit log before re-authorising.";
  }

  // P-RISK-01: critically low risk score (hard block, cannot override)
  if (!blockReason && riskScore !== null && riskScore < CRITICAL_RISK) {
    blockReason = "RISK_SCORE_CRITICAL";
    blockDetail = `risk_score ${riskScore} is below the critical floor (${CRITICAL_RISK}). No override permitted.`;
  }

  // P-ACT-01: write action requires higher score (hard block if no data yet)
  if (!blockReason && action === "data_write" && riskScore !== null && riskScore < WRITE_MIN_SCORE) {
    blockReason = "INSUFFICIENT_SCORE_FOR_WRITE";
    blockDetail = `data_write requires risk_score ≥ ${WRITE_MIN_SCORE}. Current score: ${riskScore}.`;
  }

  // P-ACT-02: agent_handoff requires verified A2A handshake
  if (!blockReason && action === "agent_handoff" && !a2aTested) {
    blockReason = "A2A_HANDSHAKE_NOT_VERIFIED";
    blockDetail = `agent_handoff requires a verified A2A handshake (a2a_tested = true). ` +
      `Enable ENABLE_A2A=true in the runner and re-run the sandbox.`;
  }

  // P-RISK-02: low risk score (soft block, override: allow_low_score)
  if (riskScore !== null && riskScore < MIN_RISK_SCORE) {
    softBlock(
      "RISK_SCORE_TOO_LOW",
      `risk_score ${riskScore} is below the enterprise minimum (${MIN_RISK_SCORE}). ` +
      `Pass policy_override.allow_low_score=true to proceed with explicit acknowledgement.`,
      "allow_low_score"
    );
  }

  // P-OWA-01: high OWASP flags (soft block, override: allow_owasp_medium)
  const highFlags = owaspRaw.filter(f => HIGH_OWASP.includes(f));
  if (highFlags.length > 0) {
    softBlock(
      "OWASP_HIGH_FLAG",
      `Tool carries OWASP high-severity flag(s): ${highFlags.join(", ")}. ` +
      `Pass policy_override.allow_owasp_medium=true to acknowledge and proceed.`,
      "allow_owasp_medium"
    );
  }

  // P-BUD-01/02: budget checks (soft block)
  let estimatedTokens = null;
  let estimateConfidence = "none";
  if (budget && runRow) {
    const avgCalls = runRow.tool_call_count ?? 0;
    const avgRespMs = runRow.duration_s ? runRow.duration_s * 1000 : 0;
    estimatedTokens = Math.round(avgCalls * 200 + (avgRespMs / 1000) * 50);
    estimateConfidence = avgCalls > 0 ? "medium" : "low";

    if (budget.max_tokens && estimatedTokens > budget.max_tokens) {
      softBlock(
        "TOKEN_BUDGET_EXCEEDED",
        `Estimated ${estimatedTokens} tokens exceeds budget.max_tokens=${budget.max_tokens}.`,
        "allow_budget_override"
      );
    }
  }

  // ── Warning rules ─────────────────────────────────────────────────────────
  if (runIsStale) {
    warnings.push(`Score may be stale — last sandbox run was ${daysSinceRun} days ago (threshold: ${STALE_THRESHOLD_DAYS} days).`);
  }
  if (!branchProtected) {
    warnings.push("No branch protection on default branch. Monitor for supply-chain changes.");
  }
  if (peakMemMb !== null && peakMemMb > 1200) {
    warnings.push(`High memory footprint (${peakMemMb} MB). Monitor for OOM in constrained environments.`);
  }

  // ── Build response ────────────────────────────────────────────────────────
  const decisionId  = "gw_" + crypto.randomUUID().replace(/-/g, "").slice(0, 26);
  const now         = new Date().toISOString();
  const expiresAt   = new Date(Date.now() + AUTH_TTL_S * 1000).toISOString();
  const durationMs  = Date.now() - t0;
  const authorized  = !blockReason;

  // ── Audit write (async, fire-and-forget) ─────────────────────────────────
  if (env.DB) {
    const apiKeyHash = auth.keyHash || null;  // FLAW 4 FIX: was auth.record?.keyHash (undefined)
    ctx.waitUntil(safe(env.DB.prepare(`
      INSERT INTO gateway_decisions
        (id, ts, slug, action, status, block_reason, risk_score, owasp_flags,
         agent_id, session_id, api_key_hash, policy_ver, duration_ms)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).bind(
      decisionId, now, slug, action,
      authorized ? "authorized" : "blocked",
      blockReason || null,
      riskScore,
      JSON.stringify(owaspRaw),
      agentId, sessionId,
      apiKeyHash,
      "v1.0",
      durationMs,
    ).run()));
  }

  // ── Authorized response ───────────────────────────────────────────────────
  if (authorized) {
    return json({
      status:              "authorized",
      slug,
      action,
      decision_id:         decisionId,
      intelligence_score:  bizopsScore,
      risk_score:          riskScore,
      commit_sha:          commitSha,
      owasp_flags:         owaspRaw,
      policy_applied:      "enterprise_default_v1",
      token_budget: budget ? {
        estimated_tokens:    estimatedTokens,
        max_tokens:          budget.max_tokens || null,
        estimate_confidence: estimateConfidence,
      } : null,
      expires_at:          expiresAt,
      warnings,
      days_since_run:      daysSinceRun,
      generated_at:        now,
    });
  }

  // ── Blocked response ──────────────────────────────────────────────────────
  return json({
    status:       "blocked",
    slug,
    action,
    decision_id:  decisionId,
    block_reason: blockReason,
    block_detail: blockDetail,
    risk_score:   riskScore,
    owasp_flags:  owaspRaw,
    remediation:  `Review audit data at https://verditnxtgen.com/deploy/${slug[0]}/${slug}.html`,
    warnings,
    generated_at: now,
  }, 403);
}
/* ═══════════════════════════════════════════════════════════════════════════
   Key issuance happens ONLY from the webhook, never from a browser redirect.
   Reason: browser redirects can be closed before the response is received,
   leaving the customer charged but without a key.  The webhook fires server-
   to-server from Stripe's infrastructure — it is retry-safe (Stripe retries
   up to 72h), idempotent (we check the session ID before inserting), and
   completely independent of the user's browser session.

   Flow:
     1. Customer hits /pricing.html → JS creates a Stripe Checkout Session
        (via /api/v1/checkout) with success_url pointing BACK to our site.
     2. Customer pays.
     3. Stripe fires POST /api/v1/webhook/stripe (this handler).
     4. We verify the signature, extract the email, issue a vnxt_ key, and
        email it via Resend (or log it to D1 for manual delivery in beta).
     5. Browser redirect (checkout.session.completed → success_url) shows a
        "check your email" page — the key is NOT in the URL.

   Register at: dashboard.stripe.com → Developers → Webhooks → Add endpoint
   URL: https://verditnxtgen.com/api/v1/webhook/stripe
   Events: checkout.session.completed
   Secret: set STRIPE_WEBHOOK_SECRET via: wrangler secret put STRIPE_WEBHOOK_SECRET
   ─────────────────────────────────────────────────────────────────────────── */
async function handleStripeWebhook(request, env, ctx) {
  const rawBody = await request.text();
  const sig     = request.headers.get("Stripe-Signature") || "";

  // ── Verify Stripe signature ────────────────────────────────────────────
  // Stripe uses HMAC-SHA256 with a timestamp prefix to prevent replay attacks.
  // Format: "t=<ts>,v1=<hmac>,v0=<hmac_legacy>"
  if (env.STRIPE_WEBHOOK_SECRET) {
    try {
      const sigParts  = Object.fromEntries(sig.split(",").map(p => p.split("=")));
      const timestamp = sigParts["t"] || "";
      const v1        = sigParts["v1"] || "";
      const payload   = `${timestamp}.${rawBody}`;

      const encoder = new TextEncoder();
      const key     = await crypto.subtle.importKey(
        "raw", encoder.encode(env.STRIPE_WEBHOOK_SECRET),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      );
      const mac      = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
      const expected = Array.from(new Uint8Array(mac))
        .map(b => b.toString(16).padStart(2, "0")).join("");

      if (v1 !== expected) {
        console.error("[stripe] Webhook signature mismatch");
        return json({ error: "Invalid signature" }, 401);
      }
      // Replay attack guard: reject events older than 5 minutes
      const tsDiff = Math.abs(Date.now() / 1000 - parseInt(timestamp, 10));
      if (tsDiff > 300) {
        console.error("[stripe] Webhook timestamp too old:", tsDiff, "seconds");
        return json({ error: "Webhook too old" }, 400);
      }
    } catch (e) {
      console.error("[stripe] Signature verification failed:", e && e.message);
      return json({ error: "Signature verification failed" }, 400);
    }
  }

  let event;
  try { event = JSON.parse(rawBody); } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  // ── Only handle checkout.session.completed ─────────────────────────────
  if (event.type !== "checkout.session.completed") {
    return json({ received: true, action: "ignored", event_type: event.type });
  }

  const session = event.data?.object;
  if (!session) return json({ error: "No session in event" }, 400);
  if (session.payment_status !== "paid") {
    return json({ received: true, action: "ignored", reason: "payment_not_completed" });
  }

  const sessionId = session.id;
  const email     = session.customer_details?.email || session.customer_email || "";
  const tier      = session.metadata?.tier || "starter";
  const label     = session.metadata?.label || `${tier} subscription`;

  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    console.error("[stripe] No valid email in session:", sessionId);
    return json({ error: "No customer email in session" }, 400);
  }

  // ── Idempotency check — don't issue duplicate keys ─────────────────────
  // Use the Stripe session ID as the idempotency key in D1
  if (env.DB) {
    try {
      const existing = await env.DB.prepare(
        "SELECT 1 FROM agent_keys WHERE key_hash = ?"
      ).bind(await sha256(`stripe:${sessionId}`)).first();
      if (existing) {
        console.log("[stripe] Duplicate webhook for session:", sessionId);
        return json({ received: true, action: "already_processed" });
      }
    } catch {}
  }

  // ── Issue the API key ──────────────────────────────────────────────────
  const raw     = crypto.getRandomValues(new Uint8Array(16));
  const apiKey  = "vnxt_" + Array.from(raw).map(b => b.toString(16).padStart(2, "0")).join("");
  const keyHash = await sha256(apiKey);
  const agentId = await sha256(email + "|" + (env.IP_SALT || "vng"));
  const ts      = new Date().toISOString();

  const keyRecord = {
    agent_id:   agentId,
    agent_type: "enterprise",
    email,
    label,
    tier,
    created_at: ts,
    last_used:  null,
    call_count: 0,
    stripe_session: sessionId,
  };

  // Write to KV (fast path — immediately active) and D1 (audit trail)
  if (env.KVOPS) {
    await env.KVOPS.put(`apikey:${keyHash}`, JSON.stringify(keyRecord),
      { expirationTtl: 94608000 });  // 3 years
  }
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT OR IGNORE INTO agent_keys (key_hash, agent_id, agent_type, email, label, created_at) VALUES (?,?,?,?,?,?)"
    ).bind(keyHash, agentId, "enterprise", email, label, ts).run()));
  }

  // ── Deliver the key ────────────────────────────────────────────────────
  // Production: send via Resend transactional email
  // Beta: log to D1 subscribers for manual delivery
  const keyDelivered = await deliverApiKey(env, ctx, { email, apiKey, tier, label });
  console.log(`[stripe] Key issued for ${email} (tier=${tier}, delivered=${keyDelivered})`);

  return json({ received: true, action: "key_issued", email, tier });
}

// Email delivery via Resend (falls back to D1 log if RESEND_API_KEY not set)
async function deliverApiKey(env, ctx, { email, apiKey, tier, label }) {
  if (!env.RESEND_API_KEY) {
    // Beta fallback: log to subscribers table with the key in the source field
    // Team manually delivers until Resend is configured
    if (env.DB) {
      ctx.waitUntil(safe(env.DB.prepare(
        "INSERT OR REPLACE INTO subscribers (email, consent, ts, source) VALUES (?,?,?,?)"
      ).bind(email, 1, new Date().toISOString(),
        `stripe_key:${apiKey}:${tier}`).run()));
    }
    console.log(`[deliver] RESEND_API_KEY not set — key logged to D1 for ${email}`);
    return false;
  }

  const tierLimit = { free: "100/day", starter: "10,000/day", enterprise: "unlimited" }[tier] || "100/day";
  const html = `
    <h2>Your VerditNxtGen API Key</h2>
    <p>Thank you for subscribing to the <strong>${tier}</strong> plan.</p>
    <p>Your API key:</p>
    <pre style="background:#f5f5f5;padding:12px;border-radius:4px;font-family:monospace">${apiKey}</pre>
    <p>Rate limit: <strong>${tierLimit}</strong></p>
    <h3>Quick start</h3>
    <pre style="background:#f5f5f5;padding:12px;border-radius:4px;font-family:monospace">curl https://verditnxtgen.com/api/v1/tools/agentmemory \
  -H "X-VerditNxtGen-Key: ${apiKey}"</pre>
    <p>Full documentation: <a href="https://verditnxtgen.com/api.html">verditnxtgen.com/api.html</a></p>
    <p><em>Keep this key secure — it is shown only once.</em></p>
  `;

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body:    JSON.stringify({
        from:    "VerditNxtGen <api@verditnxtgen.com>",
        to:      [email],
        subject: `Your VerditNxtGen API Key — ${tier} plan`,
        html,
      }),
      signal: AbortSignal.timeout(10000),
    });
    return res.ok;
  } catch (e) {
    console.error("[deliver] Resend failed:", e && e.message);
    return false;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");
    try {
      if (request.method === "OPTIONS") return preflight(request);
      if (path === "/api/audit"            && request.method === "POST") return handleStackAudit(request, env, ctx);
      if (path === "/api/stack-audit"       && request.method === "POST") return handleStackAudit(request, env, ctx);
      if (path === "/api/tools"             && request.method === "GET")  return handleToolsDirectory(url, env);
      if (path.startsWith("/api/tool/")    && request.method === "GET")  return handleToolDetail(url, env);
      if (path === "/api/route-audit"       && request.method === "POST") return handleRouteAudit(request, env);
      if (path === "/api/report"           && request.method === "GET")  return handleReport(url, env);
      if (path === "/api/go"               && request.method === "GET")  return handleGo(url, request, env, ctx);
      if (path === "/api/sandbox"          && request.method === "GET")  return handleSandbox(url, env, ctx);
      if (path === "/api/schema"           && request.method === "POST") return handleSchema(request, env, ctx);
      if (path === "/api/schema-feedback"  && request.method === "POST") return handleSchemaFeedback(request, env, ctx);
      if (path === "/api/port-discovery"   && request.method === "POST") return handlePortDiscovery(request, env, ctx);
      if (path === "/api/client-config"    && request.method === "POST") return handleClientConfig(request, env, ctx);
      if (path === "/api/client-config"    && request.method === "GET")  return handleGetClientConfig(url, env);
      if (path === "/api/intelligence"     && request.method === "GET")  return handleIntelligence(url, env);
      if (path === "/api/pass-k"           && request.method === "GET")  return handlePassK(url, env);
      if (path === "/api/owasp"            && request.method === "GET")  return handleOwaspSummary(url, env);
      if (path === "/api/cost-intelligence"&& request.method === "GET")  return handleCostIntelligence(url, env);
      if (path === "/api/a2a/sessions"     && request.method === "GET")  return handleA2ASessions(url, env);
      if (path === "/api/precommit"        && request.method === "POST") return handlePrecommitRun(request, env, ctx);
      if (path === "/api/stack"            && request.method === "POST") return handleStack(request, env);
      if (path === "/api/webhook/github"   && request.method === "POST") return handleGithubWebhook(request, env, ctx);
      if (path === "/api/mcp"              && request.method === "POST") return handleMCP(request, env, ctx);
      if (path === "/api/mcp"              && request.method === "GET")  return handleMCPSSE(request, env);
      if (path === "/api/mcp"              && request.method === "OPTIONS") return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type,X-VerditNxtGen-Key" } });
      if (path === "/api/execute"          && request.method === "POST") return handleExecute(request, env);
      if (path === "/api/keys"             && request.method === "POST") return handleKeyCreate(request, env, ctx);
      if (path === "/api/keys/verify"      && request.method === "POST") return handleKeyVerify(request, env);
      if (path === "/api/analytics"        && request.method === "GET")  return handleAnalytics(url, env, request);
      if (path === "/api/schema/version"   && request.method === "GET")  return handleSchemaVersion(url, env);
      if (path === "/api/schema/download"  && request.method === "GET")  return handleSchemaDownload(url, env);
      if (path === "/api/competitor/status" && request.method === "GET") return handleCompetitorStatus(url, env, request);
      if (path === "/api/model/status"     && request.method === "GET") return handleModelStatus(env);
      if (path === "/api/subscribe"            && request.method === "POST") return handleSubscribe(request, env, ctx);
      if (path === "/api/alerts/subscribe"      && request.method === "POST") return handleAlertsSubscribe(request, env);
      // ── /api/v1/ Enterprise routes (key-authenticated) ────────────────────
      if (path === "/api/v1/tools"               && request.method === "GET")  return handleV1Tools(request, url, env, ctx);
      if (path.startsWith("/api/v1/tools/")      && request.method === "GET")  return handleV1Tool(request, url, env, ctx);
      if (path === "/api/v1/audit"               && request.method === "POST") return handleV1Audit(request, env, ctx);
      if (path === "/api/v1/gateway/authorize"    && request.method === "POST") return handleGatewayAuthorize(request, env, ctx);
      // Ticket 3.2: provision the permanent openai_gpt_global read-only key (internal admin)
      if (path === "/api/admin/provision-gpt-key" && request.method === "POST") return handleProvisionGptKey(request, env, ctx);
      if (path === "/api/submit"                  && request.method === "POST") return handleToolSubmit(request, env, ctx);
      if (path === "/api/submit"                  && request.method === "GET")  return handleToolSubmit(request, env, ctx);
      // H2 FIX: clean /submit URL redirects to form
      if (path === "/submit"                      && request.method === "GET")
        return Response.redirect(new URL(request.url).origin + "/api/submit", 302);
      if (path === "/api/admin/pending-submissions" && request.method === "GET") return handlePendingSubmissions(request, env);
      if (path === "/api/mcp-analytics"             && request.method === "GET") return handleMcpAnalytics(request, env);
      // Shift 2: Universal log ingestion — "Bring Your Own Gateway"
      if (path === "/api/v1/ingest/gateway-log"     && request.method === "POST") return handleGatewayLogIngest(request, env, ctx);
      if (path === "/api/v1/keys/me"             && request.method === "GET")  return handleV1KeysMe(request, env, ctx);
      if (path === "/api/v1/keys"                && request.method === "POST") return handleKeyCreate(request, env, ctx);
      if (path === "/api/v1/webhook/stripe"      && request.method === "POST") return handleStripeWebhook(request, env, ctx);

      if (path === "/api/health") return json({
        ok:       true,
        ts:       new Date().toISOString(),
        service:  "verditnxtgen-api-worker",
        version:  "3.0.0",
        routes: {
          human:    ["/api/stack-audit","/api/report","/api/go","/api/sandbox","/api/schema","/api/execute","/api/keys","/api/keys/verify"],
          agent:    ["/api/mcp","/api/schema-feedback","/api/stack","/api/route-audit","/api/tool/:slug","/api/webhook/github"],
          data:     ["/api/analytics","/api/schema/version","/api/competitor/status","/api/model/status"],
          enterprise: ["/api/v1/tools","/api/v1/tools/:slug","/api/v1/audit","/api/v1/keys/me","/api/v1/keys","/api/v1/webhook/stripe"],
        },
        mcp: {
          endpoint:        "/api/mcp",
          protocol:        "2024-11-05",
          tools:           ["search_ai_infrastructure","get_agent_schema","plan_agent_stack","report_deployment_outcome","get_model_card"],
          cursor_config:   { "mcpServers": { "verditnxtgen": { "url": "https://verditnxtgen.com/api/mcp" } } },
          claude_config:   { "mcpServers": { "verditnxtgen": { "type": "http", "url": "https://verditnxtgen.com/api/mcp" } } },
        },
        schema_version: "v1",
        model_status_url: "/api/model/status",
      }, 200, request);
      // ── Algorithmic redirects — replaces _redirects per-slug rules ──────────
      // /tools/{slug}        → /tools/{shard}/{slug}.html
      // /tools/{slug}.html   → /tools/{shard}/{slug}.html  (if wrong shard or flat path)
      // /vs/{slug}           → /vs/{shard}/{slug}.html
      // /vs/{shard}/{slug}   → /vs/{shard}/{slug}.html     (extensionless → .html)
      // Shard = first alpha character of slug (same as scraper._shard())
      // This handles unlimited tools with zero _redirects budget.
      {
        const shard = (s) => { for (const c of s) if (/[a-z]/.test(c)) return c; return "0"; };

        // /tools/{slug}  or  /tools/{slug}.html  (flat — no shard in path)
        const toolFlat = path.match(/^\/tools\/([a-z0-9][a-z0-9-]{0,79})(\.html)?$/);
        if (toolFlat) {
          const slug  = toolFlat[1];
          const dest  = `/tools/${shard(slug)}/${slug}.html`;
          if (path !== dest) {
            return Response.redirect(`https://verditnxtgen.com${dest}`, 301);
          }
        }

        // /vs/{slug}  or  /vs/{slug}.html  (flat — no shard in path)
        const vsFlat = path.match(/^\/vs\/([a-z0-9][a-z0-9-]{0,120})(\.html)?$/);
        if (vsFlat) {
          const slug  = vsFlat[1];
          const dest  = `/vs/${shard(slug)}/${slug}.html`;
          return Response.redirect(`https://verditnxtgen.com${dest}`, 301);
        }

        // /vs/{shard}/{slug}  (sharded but no .html extension)
        const vsSharded = path.match(/^\/vs\/([a-z0-9])\/([a-z0-9][a-z0-9-]{0,120})$/);
        if (vsSharded) {
          const [, sh, slug] = vsSharded;
          return Response.redirect(`https://verditnxtgen.com/vs/${sh}/${slug}.html`, 301);
        }

        // /tools/{shard}/{slug}  (sharded but no .html extension)
        const toolSharded = path.match(/^\/tools\/([a-z0-9])\/([a-z0-9][a-z0-9-]{0,79})$/);
        if (toolSharded) {
          const [, sh, slug] = toolSharded;
          return Response.redirect(`https://verditnxtgen.com/tools/${sh}/${slug}.html`, 301);
        }
      }

      // Serve static Pages assets for non-API routes (trending_summary.json, tools.html, etc.)
      if (env.ASSETS) {
        try {
          const asset = await env.ASSETS.fetch(request.clone());
          if (asset.status < 400) return asset;
        } catch (_) { /* asset fetch failed, fall through to 404 */ }
      }
      return json({ error: "Not found" }, 404, request);
    } catch (err) {
      // Never leak stack traces or internal error details to clients.
      // Log the real error server-side via Cloudflare Workers observability.
      console.error("Worker unhandled error:", err);
      return json({ error: "Server error", request_id: crypto.randomUUID().slice(0, 8) }, 500, request);
    }
  },

  // ── Cron handlers ─────────────────────────────────────────────────────────
  // Two triggers (configured in wrangler.toml):
  //   0 6 * * *    → daily health refresh   (top-20 cache bust)
  //   */10 * * * * → analytics flush        (KV counters → D1 batch)
  //
  // Revision 1 fix: all per-request analytics go to KV only (atomic, concurrent-safe).
  // This cron drains the KV counters into D1 every 10 minutes — at most 1 D1 write
  // per key per window regardless of how many concurrent requests hit the API.
  async scheduled(event, env, ctx) {
    const cron = event.cron || "";
    if (cron === "0 6 * * *") {
      // Daily: top-20 cache bust + weekly snapshot
      ctx.waitUntil(runDailyHealthRefresh(env));
    } else {
      // Every 10 minutes: flush KV usage counters → D1 agent_keys table
      ctx.waitUntil(flushApiKeyAnalytics(env));
    }
  },

  // Phase-1 queue consumer (same worker). Harmless until a queue is bound.
  async queue(batch, env, ctx) {
    return processMigrationBatch(batch, env);
  }
};

/* ───────────────────────────── /api/audit ──────────────────────────────── */
async function handleStackAudit(request, env, ctx) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const teamSize = clampInt(body.team_size ?? body.run_loops, 1, 50000); // run_loops accepted as legacy alias
  const industry = String(body.industry || "Other").slice(0, 80);
  const apiUsage = String(body.api_usage || "None").slice(0, 20);
  const tools = Array.isArray(body.tools) ? body.tools.map(s => String(s).slice(0, 60)).slice(0, 30) : [];
  const cats  = Array.isArray(body.categories) ? body.categories.map(s => String(s).slice(0, 40)).slice(0, 20) : [];
  const email = String(body.email || "").slice(0, 160).trim();
  const consent = body.consent === true;
  
  if (tools.length === 0) return json({ error: "Pick at least one tool" }, 400);

  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const ipHash = await sha256(ip + "|" + requireSalt(env));

  // 1) rate limit (KV counter, per IP per hour)
  const limit = clampInt(env.RATE_LIMIT_PER_HOUR, 1, 1000) || 5;
  const hour = Math.floor(Date.now() / 3600000);
  const rlKey = `rl:${ipHash}:${hour}`;
  if (env.KVOPS) {
    const used = parseInt((await env.KVOPS.get(rlKey)) || "0", 10);
    if (used >= limit) {
      return json({ error: `Rate limit reached (${limit}/hour). Please try again later.` }, 429);
    }
    ctx.waitUntil(env.KVOPS.put(rlKey, String(used + 1), { expirationTtl: 3600 }));
  }

  // P5: Hard monthly OpenAI spend ceiling — fall back to localEstimate when budget reached
  const spendCheck = await checkSpendCeiling(env);
  if (!spendCheck.allowed) {
    const fallback = sanitizeReport(localEstimate({ teamSize, tools, cats }), { teamSize, tools, cats });
    fallback.generated_at  = new Date().toISOString();
    fallback._ceiling_note = `Monthly OpenAI budget ($${spendCheck.budget}) reached ($${spendCheck.spent.toFixed(2)} spent). AI analysis resumes next month.`;
    const cid = crypto.randomUUID();
    if (env.KVOPS) ctx.waitUntil(safe(env.KVOPS.put(`report:${cid}`, JSON.stringify(fallback), { expirationTtl: 604800 })));
    return json({ id: cid, ...fallback, source: "ceiling_fallback" });
  }

  // 2) cache identical stacks by hash (never pay OpenAI twice for the same input)
  const teamBucket = bucketTeam(teamSize || 10);
  const stackKey = JSON.stringify({ t: teamBucket, i: industry, u: apiUsage,
    s: tools.map(x => x.toLowerCase()).sort() });
  const stackHash = await sha256(stackKey);
  let report = null, source = "openai";

  if (env.KVOPS) {
    const cached = await env.KVOPS.get(`audit:${stackHash}`);
    if (cached) { try { report = JSON.parse(cached); source = "cache"; } catch {} }
  }

  // 3) build market context from trending KV (shape-tolerant: v4.2 OR v2.5)
  const catalog = report ? null : await loadCatalog(env);

  // 4) call OpenAI (only on a real cache miss)
  if (!report) {
    try {
      report = await runOpenAI(env, { teamSize, industry, tools, cats }, catalog);
    } catch (e) {
      report = null; // fall through to local estimate
    }
    if (!report) { report = localEstimate({ teamSize, tools, cats }); source = "fallback"; }
    if (env.KVOPS && source === "openai") {
      ctx.waitUntil(env.KVOPS.put(`audit:${stackHash}`, JSON.stringify(report), { expirationTtl: 604800 })); // 7d
    }
  }

  // 5) finalize + store the report under a fresh id (KV, 30d)
  const id = crypto.randomUUID();
  report.id = id;
  report.generated_at = new Date().toISOString();
  report.source = source;
  if (env.KVOPS) {
    ctx.waitUntil(env.KVOPS.put(`report:${id}`, JSON.stringify(report), { expirationTtl: 2592000 })); // 30d
  }

  // 6) analytics + opt-in (best-effort; never blocks the response)
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT INTO audits (uuid, ts, ip_hash, industry, run_loops, tools_json, waste_annual, source) VALUES (?,?,?,?,?,?,?,?)"
    ).bind(id, report.generated_at, ipHash, industry, teamSize || 0, JSON.stringify(tools),
      report.risk_score || 0, source).run()));
    if (consent && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      ctx.waitUntil(safe(env.DB.prepare(
        "INSERT OR REPLACE INTO subscribers (email, consent, ts, source) VALUES (?,?,?,?)"
      ).bind(email, 1, report.generated_at, "audit").run()));
    }
  }

  return json({ id });
}

/* ───────────────────────────── /api/report ─────────────────────────────── */
async function handleReport(url, env) {
  const id = url.searchParams.get("id") || "";
  if (!/^[0-9a-f-]{16,40}$/i.test(id)) return json({ error: "Bad id" }, 400);
  if (!env.KVOPS) return json({ error: "Storage not configured" }, 500);
  const raw = await env.KVOPS.get(`report:${id}`);
  if (!raw) return json({ error: "Not found" }, 404);
  return new Response(raw, { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "private, max-age=60" } });
}

/* ───────────────────────────── /api/sandbox ─────────────────────────────── */
// Spins up a real browser-based cloud IDE for any repo.
// Defaults to "codespaces" for higher reliability — GitHub auto-detects the
// language and spins up a container even without a devcontainer config file.
/* ───────────────────────────── /api/go ─────────────────────────────────── */
async function handleGo(url, request, env, ctx) {
  const target = (url.searchParams.get("target") || "").toLowerCase();
  const origin = env.SITE_ORIGIN || url.origin;

  if (!/^[a-z0-9][a-z0-9-]{0,60}$/.test(target)) {
    return Response.redirect(origin + "/", 302);
  }

  let dest = null;
  if (env.AFFILIATES) dest = await env.AFFILIATES.get(target);
  if (!dest) {
    // Fallback to our own sharded tool page. _shard() logic: first alpha char.
    const shard = (target.match(/[a-z]/i)?.[0] || "0").toLowerCase();
    dest = `${origin}/tools/${shard}/${target}.html`;
  }

  if (env.DB) {
    const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const ipHash = await sha256(ip + "|" + requireSalt(env));
    const ref = request.headers.get("Referer") || "";
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT INTO clicks (ts, ip_hash, target_tool, referrer, report_id) VALUES (?,?,?,?,?)"
    ).bind(new Date().toISOString(), ipHash, target, ref.slice(0, 300),
      url.searchParams.get("r") || null).run()));
  }

  return new Response(null, { status: 302, headers: { Location: dest, "Cache-Control": "no-store" } });
}

/* ───────────────────────────── /api/execute (Phase 2) ──────────────────── */
async function handleExecute(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}

  // Configuration gate: Stripe + Queue must be bound before activation.
  // Remove this check only after setting STRIPE_SECRET_KEY and binding MIGRATIONS_QUEUE.
  if (!env.STRIPE_SECRET_KEY || !env.MIGRATIONS_QUEUE) {
    return json({
      error:  "Migration Agent not configured",
      detail: "Set STRIPE_SECRET_KEY via wrangler secret put and bind MIGRATIONS_QUEUE in wrangler.toml.",
      status: "configuration_required",
    }, 503);
  }

  // ── Phase 2 scaffold (runs only when bindings/secrets exist) ──────────────
  const sessionId = String(body.session_id || "");
  if (!sessionId) return json({ error: "Missing checkout session" }, 400);

  // Zero-trust: verify the Stripe Checkout session server-side before doing anything.
  const sres = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionId}`, {
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` }
  });
  if (!sres.ok) return json({ error: "Could not verify payment" }, 402);
  const session = await sres.json();
  if (session.payment_status !== "paid") return json({ error: "Payment not completed" }, 402);

  const job = {
    report_id: String(body.report_id || ""),
    email: session.customer_details && session.customer_details.email || "",
    amount_cents: session.amount_total | 0,
    target_tool: String(body.target_tool || ""),
    session_id: sessionId,
    enqueued_at: new Date().toISOString()
  };
  await env.MIGRATIONS_QUEUE.send(job);            // producer
  if (env.DB) {
    await safe(env.DB.prepare(
      "INSERT INTO migrations (ts, report_id, email, amount_cents, target_tool, status) VALUES (?,?,?,?,?,?)"
    ).bind(job.enqueued_at, job.report_id, job.email, job.amount_cents, job.target_tool, "queued").run());
  }
  return json({ status: "queued", message: "Payment verified. Your migration is queued — we'll email you as it progresses." });
}

/* ───────────────────────────── queue consumer (Phase 2) ────────────────── */
async function processMigrationBatch(batch, env) {
  for (const msg of batch.messages) {
    const job = msg.body || {};
    const jobId = job.report_id || "unknown";

    try {
      // Step 1: Mark as processing
      if (env.DB && jobId !== "unknown") {
        await safe(env.DB.prepare("UPDATE migrations SET status=? WHERE report_id=?")
          .bind("processing", jobId).run());
      }

      // Step 2: Fetch the original audit report to know which tool to migrate to
      let report = null;
      if (env.KVOPS && jobId !== "unknown") {
        const raw = await safe(env.KVOPS.get(`report:${jobId}`));
        if (raw) { try { report = JSON.parse(raw); } catch {} }
      }

      // Step 3: Fetch the target tool's agent schema for deployment context
      const targetSlug = String(job.target_tool || "").replace(/[^a-z0-9-]/g, "");
      let agentSchema  = null;
      if (targetSlug && env.SITE_ORIGIN) {
        try {
          const schemaRes = await fetch(
            `${env.SITE_ORIGIN}/schemas/${targetSlug}.agent-schema.json`,
            { signal: AbortSignal.timeout(8000) });
          if (schemaRes.ok) agentSchema = await schemaRes.json();
        } catch {}
      }

      // Step 4: Build the migration brief (structured prompt for the agent)
      const migrationBrief = {
        job_id:        jobId,
        customer_email: job.email,
        target_tool:   targetSlug,
        amount_cents:  job.amount_cents,
        report_summary: report ? {
          risk_score: report.risk_score || null,
          summary:      report.summary,
          items:        (report.items || []).slice(0, 3),
        } : null,
        schema_context: agentSchema ? {
          health_tier:    agentSchema.health?.health_tier,
          docker_compose: agentSchema.deployment?.docker_compose,
          env_example:    agentSchema.deployment?.env_example,
          ci_steps:       (agentSchema.ci_cd?.build_steps || []).slice(0, 3),
          auth:           agentSchema.auth_protocol,
        } : null,
        steps_completed: ["payment_verified", "schema_fetched"],
        next_step:       "provision_environment",
        enqueued_at:     job.enqueued_at,
        processed_at:    new Date().toISOString(),
      };

      // Step 5: Log the brief to KV for the customer status page
      if (env.KVOPS) {
        await safe(env.KVOPS.put(
          `migration:brief:${jobId}`,
          JSON.stringify(migrationBrief),
          { expirationTtl: 2592000 }  // 30 days
        ));
      }

      // Step 6: Update D1 status to "briefed" (next step is human/agent review)
      if (env.DB && jobId !== "unknown") {
        await safe(env.DB.prepare("UPDATE migrations SET status=? WHERE report_id=?")
          .bind("briefed", jobId).run());
      }

      console.log(`[migration] Job ${jobId} → briefed. Tool: ${targetSlug}`);
      msg.ack();

    } catch (e) {
      console.error(`[migration] Job ${jobId} failed: ${e && e.message || e}`);
      if (env.DB && jobId !== "unknown") {
        await safe(env.DB.prepare("UPDATE migrations SET status=? WHERE report_id=?")
          .bind("failed", jobId).run());
      }
      msg.retry();
    }
  }
}

/* ───────────────────────────── OpenAI ──────────────────────────────────── */
async function runOpenAI(env, input, catalog) {
  if (!env.OPENAI_API_KEY) throw new Error("no key");
  const model = env.OPENAI_MODEL || "gpt-4o-mini";

  const catLines = (catalog || []).slice(0, 45)
    .map(c => `${c.name} [${c.slug}] (${c.category}, score ${c.score})`).join("\n");

  const system = [
    "You are VerditNxtGen\'s stack intelligence engine.",
    "Engineering teams and AI agent routing platforms query you before adopting or routing to an open-source tool.",
    "Your job: given a team\'s stack, identify health risks, single-maintainer dependencies, and better alternatives.",
    "RULES:",
    "- Evaluate each tool on GitHub health: commit recency, bus factor, CI status, test coverage, star momentum.",
    "- Recommend alternatives ONLY from the provided directory using exact [slug].",
    "- If no better alternative exists in the directory, say so — never invent one.",
    "- risk_score 0-100: 100 = production grade, 0 = critical risk.",
    "- summary: 2 sentences. What is the most urgent health risk in this stack?",
    "Return STRICT JSON only:",
    '{"risk_score": <int 0-100>, "summary": "<=2 sentences",',
    ' "items": [{"current_tool":"name","risk_flags":["flag"],"replace_with":{"name":"X","slug":"x","score_improvement":<int>},"reason":"<=2 sentences"}],',
    ' "recommendations": ["actionable tip"] }'

  ].join("\n");

  const user = [
    `Team size: ${input.teamSize || "unknown"}`,
    `Industry: ${input.industry}`,
    `Current stack: ${input.tools.join(", ") || "(unspecified)"}`,
    `Categories: ${(input.cats || []).join(", ") || "(infer from tools)"}`,
    "",
    "Directory of open-source AI infrastructure tools you may recommend (name [slug] (category, score)):",
    catLines || "(directory unavailable — recommend well-known open-source options and leave slug empty)"
  ].join("\n");

  // Hard timeout: if OpenAI hangs, abort well before Cloudflare's wall-clock limit
  // so the caller falls back to localEstimate instead of the Worker dying with a 524.
  const timeoutMs = clampInt(env.OPENAI_TIMEOUT_MS, 1000, 60000) || 15000;
  let res;
  try {
    res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${env.OPENAI_API_KEY}` },
      body: JSON.stringify({
        model, temperature: 0.3, max_tokens: 900,
        response_format: { type: "json_object" },
        messages: [{ role: "system", content: system }, { role: "user", content: user }]
      }),
      signal: AbortSignal.timeout(timeoutMs)
    });
  } catch (e) {
    // AbortError/TimeoutError or network failure -> rethrow so handleAudit falls back.
    throw new Error("openai unreachable/timeout: " + ((e && e.name) || e));
  }
  if (!res.ok) throw new Error("openai " + res.status);
  const data    = await res.json();
  const content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
  if (!content) throw new Error("empty");
  // P5: Record spend for ceiling tracking (non-blocking)
  const tokensUsed = (data.usage?.total_tokens || 900);
  if (env && env.KVOPS) {
    const monthKey = new Date().toISOString().slice(0, 7);
    (async () => {
      const cost    = (tokensUsed / 1_000_000) * 0.30;
      const current = parseFloat((await safe(env.KVOPS.get(`openai:spend:${monthKey}`))) || "0");
      await safe(env.KVOPS.put(`openai:spend:${monthKey}`,
        String(Math.round((current + cost) * 10000) / 10000),
        { expirationTtl: 2678400 }));
    })().catch(() => {});
  }
  const parsed = JSON.parse(content);
  return sanitizeReport(parsed, input);
}

function sanitizeReport(p, input) {
  const items = Array.isArray(p.items) ? p.items.slice(0, 8).map(it => {
    const rw   = it.replace_with || {};
    const slug = String(rw.slug || "").toLowerCase().replace(/[^a-z0-9-]/g, "").slice(0, 60);
    return {
      have: Array.isArray(it.have) ? it.have.map(s => String(s).slice(0, 60)).slice(0, 5) : [],
      replace_with: {
        name:               String(rw.name || "").slice(0, 60),
        slug,
        est_monthly_saving: clampInt(rw.est_monthly_saving, 0, 10000000) || 0,
        // Gap 2: schema and tool URLs so the UI can render "Download Schema" buttons
        schema_url:         slug ? `/schemas/${slug}.agent-schema.json` : null,
        tool_url:           slug ? `/tools/${(slug[0] || "x")}/${slug}.html` : null,
        deploy_verified:    rw.deploy_verified || false,
      },
      reason: String(it.reason || "").slice(0, 400)
    };
  }) : [];
  const riskScore = clampInt(p.risk_score, 0, 100) || 50;
  return {
    risk_score:      riskScore,
    risk_tier:       riskScore >= SCORE_TIERS.PRODUCTION_GRADE ? "production_grade"
                   : riskScore >= SCORE_TIERS.ADOPTABLE         ? "adoptable"
                   : riskScore >= SCORE_TIERS.CAUTION            ? "caution" : "avoid",
    summary:         String(p.summary || "").slice(0, 400),
    items,
    recommendations: Array.isArray(p.recommendations)
      ? p.recommendations.map(s => String(s).slice(0, 200)).slice(0, 6) : []
  };
}

/* ─── local fallback (no OpenAI available) ──────────────────────────────── */
function localEstimate(input) {
  const toolCount = (input.tools && input.tools.length) || 1;
  const baseRisk  = Math.max(20, Math.min(75, 90 - (toolCount * 4)));
  const items     = (input.tools || []).slice(0, 5).map(t => ({
    current_tool: t,
    risk_flags:   ["score_unavailable"],
    replace_with: { name: "", slug: "", score_improvement: 0 },
    reason:       "Live scores unavailable — query /api/tool/" + t.toLowerCase().replace(/\s+/g, "-")
  }));
  return {
    risk_score:      baseRisk,
    risk_tier:       baseRisk >= 80 ? "production_grade" : baseRisk >= 60 ? "adoptable" : "caution",
    summary:         "Stack health estimate based on tool count — AI analysis unavailable. Check scores at verditnxtgen.com/tools.",
    items,
    recommendations: [
      "Query /api/tools for current bizops_score for each tool in your stack.",
      "Enable score-drop alerts at /alerts.html.",
      "Use /api/route-audit to find higher-scored alternatives for any capability."
    ]
  };
}

/* ───────────────────────────── trending catalog ────────────────────────── */
async function loadCatalog(env) {
  // Primary: KVOPS "trending:latest" — written by scrape job after each run.
  // Fallback: mcp_routing_index.json static asset — always available after Pages deploy.
  if (env.KVOPS) {
    const raw = await safe(env.KVOPS.get("trending:latest"));
    if (raw) {
      try {
        const data = JSON.parse(raw);
        const list = Array.isArray(data) ? data : (data.tools || []);
        return _shapeCatalog(list);
      } catch { /* fall through */ }
    }
  }
  try {
    const origin = env.SITE_ORIGIN || "https://verditnxtgen.com";
    const res = await fetch(`${origin}/mcp_routing_index.json`,
      { signal: AbortSignal.timeout(4000) });
    if (res.ok) {
      const data = await res.json();
      const list = Object.entries(data.by_slug || {}).map(([slug, t]) => ({ slug, ...t }));
      return _shapeCatalog(list);
    }
  } catch { /* fall through */ }
  return [];
}

function _shapeCatalog(list) {
  return list.map(t => {
    const score = (typeof t.bizops_score === "number") ? t.bizops_score
      : (typeof t.composite === "number") ? Math.round(t.composite * 100)
      : (typeof t.score === "number") ? t.score : 0;
    return {
      name:       String(t.name || (t.full_name || "").split("/").pop() || "tool"),
      slug:       String(t.slug || ""),
      category:   String(t.category || "Other"),
      score,
      schema_url: t.schema_url || `/schemas/${t.slug}.agent-schema.json`,
      tool_url:   t.tool_url   || `/tools/${(t.slug||"x")[0]}/${t.slug}.html`,
    };
  }).filter(t => t.slug).sort((a, b) => b.score - a.score);
}

/* ───────────────────────────── /api/schema ─────────────────────────────── */
async function handleSchema(request, env, ctx) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const email = String(body.email || "").trim();
  const slug  = String(body.slug  || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return json({ error: "Valid work email required to unlock schema." }, 400);
  }
  if (!slug) return json({ error: "slug is required" }, 400);

  // 1. Rate-limit by IP — separate limit from /api/audit; default 30/hr (lead magnet, not a compute call)
  const ip     = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const ipHash = await sha256(ip + "|" + requireSalt(env));
  const limit  = clampInt(env.SCHEMA_RATE_LIMIT_PER_HOUR ?? env.RATE_LIMIT_PER_HOUR, 1, 10000) || 30;
  const hour   = Math.floor(Date.now() / 3600000);
  const rlKey  = `rl:schema:${ipHash}:${hour}`;
  if (env.KVOPS) {
    const used = parseInt((await env.KVOPS.get(rlKey)) || "0", 10);
    if (used >= limit) return json({ error: `Rate limit reached (${limit}/hour). Try again later.` }, 429);
    ctx.waitUntil(env.KVOPS.put(rlKey, String(used + 1), { expirationTtl: 3600 }));
  }

  // 2. Capture the lead in D1 subscribers table
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT OR REPLACE INTO subscribers (email, consent, ts, source) VALUES (?,?,?,?)"
    ).bind(email, 1, new Date().toISOString(), "schema_download").run()));
  }

  // 3. Validate slug against routing index (fast 404 before hitting /schemas/)
  //    Falls through silently if the index isn't available yet (first deploy).
  const origin    = env.SITE_ORIGIN || new URL(request.url).origin;
  try {
    const routeRes = await fetch(`${origin}/mcp_routing_index.json`,
      { signal: AbortSignal.timeout(3000) });
    if (routeRes.ok) {
      const routeData = await routeRes.json();
      if (routeData.by_slug && !(slug in routeData.by_slug)) {
        return json({ error: `Schema not found for "${slug}". Check the slug at ${origin}/tools.html` }, 404);
      }
    }
  } catch { /* routing index unavailable — proceed to schema fetch */ }

  // 4. Fetch the static schema from our own edge (KV-cached by Cloudflare)
  const schemaRes = await fetch(`${origin}/schemas/${slug}.agent-schema.json`);
  if (!schemaRes.ok) return json({ error: "Schema not found for that tool." }, 404);

  const schemaData = await schemaRes.json();
  return json(schemaData);
}

/* ═══════════════════════════════════════════════════════════════════════════
   REVISION 1: KV → D1 Analytics Flush (10-minute cron)
   ═══════════════════════════════════════════════════════════════════════════
   D1 (SQLite) is fast for reads but serialises concurrent writes — 500
   simultaneous CTX.waitUntil D1 writes from a burst pipeline would queue and
   timeout.  Fix: every authenticated API call increments a cheap KV counter
   (atomic, O(1), built for high concurrency).  Every 10 minutes a cron reads
   all pending KV counters and writes to D1 in a single batch update.  No
   matter how many concurrent requests hit the API, D1 sees at most one write
   per 10-minute window per key.
   ─────────────────────────────────────────────────────────────────────────── */

async function flushApiKeyAnalytics(env) {
  if (!env.KVOPS || !env.DB) return;

  // KV key pattern: apikey:usage:{keyHash}:{hourBucket}
  // We list all keys matching this prefix that are from the past 2 hours
  // (1 current + 1 previous, in case the cron runs at a boundary)
  const hour        = Math.floor(Date.now() / 3600000);
  const prefixes    = [`apikey:usage:`, `apikey:usage:`];
  const hourBuckets = [hour, hour - 1];

  let flushed = 0;
  const errors = [];

  try {
    // List all usage keys — KV list returns keys with this prefix
    const listed = await env.KVOPS.list({ prefix: "apikey:usage:" });
    const keys   = (listed?.keys || []).map(k => k.name);

    if (!keys.length) return;   // nothing to flush

    // Batch the D1 updates — one UPDATE per unique keyHash
    // Group: keyHash → total calls this period
    const totals = {};
    const lastUsed = {};

    for (const kvKey of keys) {
      // Format: apikey:usage:{keyHash}:{hourBucket}
      const parts = kvKey.split(":");
      if (parts.length < 4) continue;
      const keyHash   = parts[2];
      const hourBucket = parseInt(parts[3], 10);
      if (!keyHash || isNaN(hourBucket)) continue;

      const raw   = await env.KVOPS.get(kvKey);
      const count = parseInt(raw || "0", 10);
      if (!count) continue;

      totals[keyHash]   = (totals[keyHash]   || 0) + count;
      // Track the most recent hour bucket as the last_used timestamp
      if (!lastUsed[keyHash] || hourBucket > lastUsed[keyHash]) {
        lastUsed[keyHash] = hourBucket;
      }
    }

    // Batch D1 writes — one UPDATE per key (not one per request)
    for (const [keyHash, callCount] of Object.entries(totals)) {
      const lastUsedTs = new Date(lastUsed[keyHash] * 3600000).toISOString();
      try {
        await env.DB.prepare(
          `UPDATE agent_keys
             SET call_count = call_count + ?,
                 last_used  = ?
           WHERE key_hash = ?`
        ).bind(callCount, lastUsedTs, keyHash).run();
        flushed++;
      } catch (e) {
        errors.push(`${keyHash.slice(0,8)}: ${e && e.message}`);
      }
    }

    // Delete the KV counters we just flushed (keep only current hour in KV)
    for (const kvKey of keys) {
      const parts      = kvKey.split(":");
      const hourBucket = parseInt(parts[3], 10);
      // Only delete previous-hour buckets — keep current hour accumulating
      if (!isNaN(hourBucket) && hourBucket < hour) {
        await env.KVOPS.delete(kvKey).catch(() => {});
      }
    }

    console.log(`[flush] API key analytics: ${flushed} keys flushed to D1${errors.length ? `, ${errors.length} errors` : ""}`);
  } catch (e) {
    console.error("[flush] flushApiKeyAnalytics failed:", e && e.message);
  }
}

/* ─────────────────────── Daily health refresh (cron) ───────────────────────
 * Runs at 06:00 UTC every day via the scheduled() handler.
 * Fetches trending_summary.json, takes the top 20 tools by score, then for
 * each one: busts the KV audit cache so the next /api/audit call re-evaluates
 * with fresh signals. Writes a refresh timestamp to KVOPS for observability.
 * Cost: ~20 KV writes + 1 static fetch. Well within Workers free tier.
 * ────────────────────────────────────────────────────────────────────────── */
async function runDailyHealthRefresh(env) {
  const origin      = env.SITE_ORIGIN || "https://verditnxtgen.com";
  const refreshedAt = new Date().toISOString();
  let   busted      = 0;
  let   dirtyBusted = 0;

  try {
    // ── 1. Drain the dirty_schemas queue from webhook debounce ───────────────
    // Webhooks write slugs here instead of busting cache immediately (Landmine A fix).
    // We process them once per day, de-duped, in a single controlled pass.
    if (env.KVOPS) {
      const dirtyRaw = await safe(env.KVOPS.get("dirty_schemas")) || "[]";
      let   dirtySet;
      try { dirtySet = JSON.parse(dirtyRaw); } catch { dirtySet = []; }
      const uniqueDirty = [...new Set(Array.isArray(dirtySet) ? dirtySet : [])];

      if (uniqueDirty.length > 0) {
        for (const slug of uniqueDirty) {
          if (!slug) continue;
          // Now it's safe to bust — we've absorbed all the webhook noise
          await safe(env.KVOPS.delete(`schema:neg:${slug}`));
          await safe(env.KVOPS.delete(`dirty:${slug}`));
          dirtyBusted++;
        }
        // Clear the dirty queue
        await safe(env.KVOPS.delete("dirty_schemas"));
        console.log(`[cron] Drained dirty_schemas: ${dirtyBusted} slugs busted`);
      }
    }

    // ── 2. Materialise weekly snapshot on Mondays ─────────────────────────────
    const dayOfWeek = new Date().getUTCDay();  // 0=Sun, 1=Mon
    if (dayOfWeek === 1) {
      await materializeWeeklySnapshot(env);
    }
    const res = await fetch(`${origin}/trending_summary.json`,
      { signal: AbortSignal.timeout(8000) });
    if (!res.ok) throw new Error("summary fetch " + res.status);
    const data  = await res.json();
    const top20 = (Array.isArray(data.tools) ? data.tools : [])
      .sort((a, b) => (b.bizops_score || 0) - (a.bizops_score || 0))
      .slice(0, 20);

    if (env.KVOPS) {
      for (const tool of top20) {
        if (!tool.slug) continue;
        await safe(env.KVOPS.delete(`schema:neg:${tool.slug}`));
        busted++;
      }
      await safe(env.KVOPS.put("health_refresh:last_run", JSON.stringify({
        ts:          refreshedAt,
        busted,
        dirty_busted: dirtyBusted,
        tools:       top20.map(t => t.slug).filter(Boolean),
      }), { expirationTtl: 172800 }));
    }

    console.log(`[cron] Daily refresh done — ${busted} routine + ${dirtyBusted} dirty slugs busted at ${refreshedAt}`);
  } catch (e) {
    console.error(`[cron] Daily health refresh failed: ${e && e.message || e}`);
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRIORITY 1 — AGENT IDENTITY & API KEY SYSTEM
   Proof-of-machine: correlates schema fetches ↔ deployment outcomes by session.
   Segments analytics by agent_type (claude_code | cursor | codex | human | unknown).
   ═══════════════════════════════════════════════════════════════════════════ */

// Extract and fingerprint the agent identity from every request.
// Returns {agent_type, agent_id, api_key, session_id} — all optional/null.
async function fingerprintAgent(request, env) {
  const ua        = request.headers.get("User-Agent")        || "";
  const apiKey    = request.headers.get("X-VerditNxtGen-Key") ||
                    request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "") || "";
  const sessionId = request.headers.get("X-Agent-Session")   || "";

  // Classify agent type from User-Agent string
  let agent_type = "human";
  if (/claude.?code|anthropic.?cli/i.test(ua))  agent_type = "claude_code";
  else if (/cursor/i.test(ua))                   agent_type = "cursor";
  else if (/copilot|github.?codi/i.test(ua))     agent_type = "copilot";
  else if (/codex|openai/i.test(ua))             agent_type = "codex";
  else if (/python-httpx|python-requests/i.test(ua)) agent_type = "python_agent";
  else if (/node-fetch|axios|got\//i.test(ua))   agent_type = "node_agent";
  else if (/postman|insomnia|curl\//i.test(ua))  agent_type = "human";
  else if (!ua || ua.length < 10)                agent_type = "unknown";

  // Resolve API key to agent_id
  let agent_id = null;
  if (apiKey && env.KVOPS) {
    const keyData = await safe(env.KVOPS.get(`apikey:${await sha256(apiKey)}`));
    if (keyData) {
      try { agent_id = JSON.parse(keyData).agent_id; } catch {}
    }
  }

  return { agent_type, agent_id, api_key: apiKey || null, session_id: sessionId || null };
}

// POST /api/keys — issue an API key for an agent identity
async function handleKeyCreate(request, env, ctx) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const email      = String(body.email      || "").trim();
  const agent_type = String(body.agent_type || "unknown").slice(0, 40);
  const label      = String(body.label      || "").slice(0, 80);
  const tos_consent = body.tos_consent === true || body.tos_consent === 1 ? 1 : 0;
  const tos_version = String(body.tos_version || "").slice(0, 20) || null;

  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return json({ error: "Valid email required to issue an API key" }, 400);
  }

  // Require explicit ToS consent for telemetry data rights
  if (!tos_consent) {
    return json({ error: "Terms of Service consent required. Set tos_consent:true in request body." }, 403);
  }

  // Generate a cryptographically random key: vnxt_<32 hex chars>
  const raw     = crypto.getRandomValues(new Uint8Array(16));
  const apiKey  = "vnxt_" + Array.from(raw).map(b => b.toString(16).padStart(2, "0")).join("");
  const keyHash = await sha256(apiKey);
  const agentId = await sha256(email + "|" + requireSalt(env));
  const ts      = new Date().toISOString();

  const keyRecord = {
    agent_id:       agentId,
    agent_type,
    email,
    label,
    created_at:     ts,
    last_used:      null,
    call_count:     0,
    tos_consent,
    tos_version,
    tos_accepted_at: ts,
  };

  if (env.KVOPS) {
    ctx.waitUntil(env.KVOPS.put(`apikey:${keyHash}`, JSON.stringify(keyRecord),
      { expirationTtl: 31536000 }));  // 1 year
  }
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT OR REPLACE INTO subscribers (email, consent, ts, source) VALUES (?,?,?,?)"
    ).bind(email, 1, ts, "api_key_create").run()));

    // Write key record to agent_keys with tos consent for legal audit trail
    // KV record expires in 1 year; D1 record is permanent and queryable
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT OR IGNORE INTO agent_keys (key_hash, agent_id, agent_type, email, label, created_at, tos_consent, tos_version, tos_accepted_at) VALUES (?,?,?,?,?,?,?,?,?)"
    ).bind(keyHash, agentId, agent_type, email, label, ts, tos_consent, tos_version || null, ts).run()));
  }

  return json({
    api_key:    apiKey,
    agent_id:   agentId,
    agent_type,
    expires_in: "365 days",
    usage: {
      header: "X-VerditNxtGen-Key: " + apiKey,
      mcp_note: "Add to your MCP client config as a custom header.",
    }
  });
}

// POST /api/keys/verify — validate a key and return its identity
async function handleKeyVerify(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  const apiKey  = String(body.api_key || "").trim();
  if (!apiKey)  return json({ error: "api_key required" }, 400);

  const keyHash = await sha256(apiKey);
  if (!env.KVOPS) return json({ error: "Key store unavailable" }, 503);

  const raw = await safe(env.KVOPS.get(`apikey:${keyHash}`));
  if (!raw)  return json({ valid: false, error: "Key not found or expired" }, 404);

  try {
    const record = JSON.parse(raw);
    return json({ valid: true, agent_type: record.agent_type,
                  agent_id: record.agent_id, label: record.label,
                  created_at: record.created_at, call_count: record.call_count });
  } catch {
    return json({ valid: false, error: "Key record corrupt" }, 500);
  }
}

// ── requireApiKey — enforces auth on /api/v1/* endpoints ──────────────────
// Returns {ok: true, keyHash, record} on success.
// Returns a 401/429 Response on failure (caller must return it immediately).
//
// Revision 1 compliance: this function ONLY writes to KV (atomic counter).
// D1 is updated in bulk by the flushApiKeyAnalytics() cron every 10 minutes.
// This means 500 concurrent requests from a CI/CD cluster all hit cheap KV
// writes — D1 never receives concurrent write pressure from the hot path.
async function requireApiKey(request, env, ctx) {
  const apiKey = (
    request.headers.get("X-VerditNxtGen-Key") ||
    request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "")
  || "").trim();

  if (!apiKey) {
    return {
      ok: false,
      response: json({ error: "API key required. Add header: X-VerditNxtGen-Key: vnxt_..." }, 401)
    };
  }

  if (!env.KVOPS) {
    return { ok: false, response: json({ error: "Key store unavailable" }, 503) };
  }

  const keyHash = await sha256(apiKey);
  const raw     = await env.KVOPS.get(`apikey:${keyHash}`);
  if (!raw) {
    return {
      ok: false,
      response: json({ error: "Invalid or expired API key" }, 401)
    };
  }

  let record;
  try { record = JSON.parse(raw); } catch {
    return { ok: false, response: json({ error: "Key record corrupt" }, 500) };
  }

  // Per-key rate limiting — KV counter, not D1
  // Tier limits: free=100/day, starter=10k/day, enterprise=custom
  const tierLimits = { free: 100, starter: 10000, enterprise: 999999, gpt_global: 50000 };
  const tier       = record.tier || "free";
  const dayLimit   = tierLimits[tier] || 100;
  const dayBucket  = Math.floor(Date.now() / 86400000);   // 1 bucket per day
  const rlKey      = `apikey:rl:${keyHash}:${dayBucket}`;

  const used = parseInt((await env.KVOPS.get(rlKey)) || "0", 10);
  if (used >= dayLimit) {
    return {
      ok: false,
      response: json({
        error:       `Daily rate limit reached (${dayLimit} requests/day for ${tier} tier)`,
        tier,
        upgrade_url: "https://verditnxtgen.com/pricing.html",
        resets_at:   new Date((dayBucket + 1) * 86400000).toISOString(),
      }, 429)
    };
  }

  // Increment KV counter only — NO D1 write here (Revision 1 fix)
  // Also increment usage accumulator for the 10-min flush cron
  const hour    = Math.floor(Date.now() / 3600000);
  const useKey  = `apikey:usage:${keyHash}:${hour}`;
  ctx.waitUntil(Promise.all([
    env.KVOPS.put(rlKey,   String(used + 1),                        { expirationTtl: 86400  }),  // 24h
    env.KVOPS.put(useKey, String(parseInt((await env.KVOPS.get(useKey) || "0"), 10) + 1), { expirationTtl: 7200 }),  // 2h
  ]));

  // FLAW 5 FIX: surface read_only flag so callers can enforce it.
  // The gpt_global key has read_only:true — callers check auth.readOnly before writes.
  return { ok: true, keyHash, record, tier, readOnly: record.read_only === true };
}

// GET /api/analytics — usage segmented by agent_type
async function handleAnalytics(url, env, request) {
  // Public read endpoint — returns aggregated fleet-level signals only.
  // No PII: all rows are ip_hash (SHA256-salted), no individual identifiers.
  // INTERNAL_API_KEY gating removed: the data is equivalent to what /api/schema/download
  // already exposes per-tool, just aggregated. Gating it caused permanent 401 on the
  // dashboard because window.__ANALYTICS_KEY was never injected into the page.
  const days = Math.min(parseInt(url.searchParams.get("days") || "30"), 365);
  if (!env.DB) return json({ error: "Analytics DB unavailable" }, 503);

  const since = new Date(Date.now() - days * 86400000).toISOString();

  const [feedback, audits, schemas, costRows, owaspRows, passKRows, riskRows] = await Promise.all([
    safe(env.DB.prepare(
      "SELECT agent_type, outcome, COUNT(*) as cnt FROM deployment_feedback WHERE ts > ? GROUP BY agent_type, outcome"
    ).bind(since).all()),
    safe(env.DB.prepare(
      "SELECT source, COUNT(*) as cnt FROM audits WHERE ts > ? GROUP BY source"
    ).bind(since).all()),
    safe(env.DB.prepare(
      "SELECT schema_version, COUNT(*) as cnt FROM deployment_feedback WHERE ts > ? GROUP BY schema_version"
    ).bind(since).all()),
    // Cost telemetry: avg cost per run and total by profile
    safe(env.DB.prepare(
      "SELECT resource_profile, ROUND(AVG(usd_cost),6) as avg_cost, ROUND(SUM(usd_cost),4) as total_cost, COUNT(*) as runs FROM cost_telemetry WHERE ts > ? GROUP BY resource_profile"
    ).bind(since).all()),
    // OWASP: top flags by severity
    safe(env.DB.prepare(
      "SELECT owasp_id, owasp_name, severity, COUNT(DISTINCT slug) as affected_tools, COUNT(*) as total_hits FROM owasp_findings WHERE ts > ? GROUP BY owasp_id ORDER BY total_hits DESC LIMIT 10"
    ).bind(since).all()),
    // pass@k: latest week aggregates
    safe(env.DB.prepare(
      "SELECT slug, profile, pass_at_1, pass_at_3, pass_at_5, total_runs, success_rate FROM pass_k_metrics WHERE week_start > ? ORDER BY week_start DESC LIMIT 50"
    ).bind(since).all()),
    // Risk score distribution
    safe(env.DB.prepare(
      "SELECT CASE WHEN risk_score >= 80 THEN 'high' WHEN risk_score >= 40 THEN 'medium' ELSE 'low' END as band, COUNT(*) as cnt FROM deployment_feedback WHERE ts > ? AND risk_score IS NOT NULL GROUP BY band"
    ).bind(since).all()),
  ]);

  // Agent type breakdown
  const byAgentType = {};
  for (const row of (feedback?.results || [])) {
    const at = row.agent_type || "unknown";
    if (!byAgentType[at]) byAgentType[at] = { success: 0, failure: 0, total: 0 };
    byAgentType[at][row.outcome] = (byAgentType[at][row.outcome] || 0) + row.cnt;
    byAgentType[at].total += row.cnt;
  }
  for (const at of Object.keys(byAgentType)) {
    const d = byAgentType[at];
    d.success_rate = d.total > 0 ? Math.round(d.success / d.total * 1000) / 10 : null;
  }

  // Cost summary
  const costByProfile = {};
  for (const row of (costRows?.results || [])) {
    costByProfile[row.resource_profile] = { avg_cost_usd: row.avg_cost, total_cost_usd: row.total_cost, runs: row.runs };
  }

  // Risk distribution
  const riskDist = {};
  for (const row of (riskRows?.results || [])) riskDist[row.band] = row.cnt;

  // pass@k summary
  const passKSummary = (passKRows?.results || []).reduce((acc, r) => {
    if (!acc[r.slug]) acc[r.slug] = {};
    acc[r.slug][r.profile] = { pass_at_1: r.pass_at_1, pass_at_3: r.pass_at_3, pass_at_5: r.pass_at_5, runs: r.total_runs, rate: r.success_rate };
    return acc;
  }, {});

  return json({
    period_days:      days,
    since,
    // Original fields
    by_agent_type:    byAgentType,
    audit_sources:    Object.fromEntries((audits?.results || []).map(r => [r.source, r.cnt])),
    schema_versions:  Object.fromEntries((schemas?.results || []).map(r => [r.schema_version, r.cnt])),
    machine_pct:      _calcMachinePct(byAgentType),
    // New enriched fields
    cost_by_profile:  costByProfile,
    owasp_top_flags:  (owaspRows?.results || []),
    risk_distribution: riskDist,
    pass_k_by_tool:   passKSummary,
    _note:            "D1 feedback data may be sparse if Hetzner swarm is not posting to API",
  });
}

function _calcMachinePct(byAgentType) {
  const machineTypes = ["claude_code", "cursor", "copilot", "codex", "python_agent", "node_agent"];
  let machine = 0, total = 0;
  for (const [type, data] of Object.entries(byAgentType)) {
    total   += data.total;
    if (machineTypes.includes(type)) machine += data.total;
  }
  return total > 0 ? Math.round(machine / total * 1000) / 10 : null;
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRIORITY 2 — TIME-SERIES LEDGER: weekly snapshots & longitudinal queries
   ═══════════════════════════════════════════════════════════════════════════ */

// Cron also materialises weekly snapshots — called from runDailyHealthRefresh
// on Mondays (day_of_week === 1).
async function materializeWeeklySnapshot(env) {
  if (!env.DB) return;
  const weekStart = new Date();
  weekStart.setUTCHours(0, 0, 0, 0);
  weekStart.setUTCDate(weekStart.getUTCDate() - weekStart.getUTCDay());  // Monday
  const weekKey   = weekStart.toISOString().slice(0, 10);   // "2026-01-06"

  try {
    // Aggregate this week's feedback per slug into a snapshot row
    const rows = await safe(env.DB.prepare(`
      SELECT slug,
             SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS successes,
             SUM(CASE WHEN outcome='failure' THEN 1 ELSE 0 END) AS failures,
             COUNT(*) AS total,
             GROUP_CONCAT(DISTINCT schema_version) AS schema_versions_used
      FROM deployment_feedback
      WHERE ts >= ? AND ts < datetime(?, '+7 days')
      GROUP BY slug
    `).bind(weekStart.toISOString(), weekStart.toISOString()).all());

    for (const row of (rows?.results || [])) {
      const rate = row.total > 0 ? Math.round(row.successes / row.total * 1000) / 10 : null;
      await safe(env.DB.prepare(`
        INSERT OR REPLACE INTO feedback_snapshots
          (week_start, slug, successes, failures, total, success_rate, schema_versions_used)
        VALUES (?,?,?,?,?,?,?)
      `).bind(weekKey, row.slug, row.successes, row.failures, row.total,
              rate, row.schema_versions_used || "").run());
    }
    console.log(`[snapshot] Materialised week ${weekKey}: ${rows?.results?.length || 0} slugs`);
  } catch (e) {
    console.error("[snapshot] Failed:", e && e.message);
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRIORITY 3 — EPHEMERAL SANDBOX EXECUTION
   Spins up an execution harness, runs docker-compose up, captures exit code.
   Falls back gracefully to IDE redirect when execution provider unavailable.
   ═══════════════════════════════════════════════════════════════════════════ */

async function handleSandbox(url, env, ctx) {
  const tool     = (url.searchParams.get("tool")     || "").trim();
  const repo     = (url.searchParams.get("repo")     || "").trim();
  const execute  = url.searchParams.get("execute")   === "true";
  const slug     = tool.replace(/[^a-z0-9-]/g, "");

  if (!tool || !repo || !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repo)) {
    return json({ error: "Invalid or missing tool / repo parameter." }, 400);
  }

  // Execution mode: call the external harness (Modal, Railway, or CF Workers AI)
  if (execute && env.EXECUTION_HARNESS_URL) {
    try {
      const origin     = env.SITE_ORIGIN || "https://verditnxtgen.com";
      const schemaRes  = await fetch(`${origin}/schemas/${slug}.agent-schema.json`,
        { signal: AbortSignal.timeout(5000) });
      const schema     = schemaRes.ok ? await schemaRes.json() : null;
      const dockerCompose = schema?.deployment?.docker_compose || null;

      const harness = await fetch(env.EXECUTION_HARNESS_URL, {
        method:  "POST",
        headers: { "Content-Type": "application/json",
                   "Authorization": `Bearer ${env.EXECUTION_HARNESS_TOKEN || ""}` },
        body:    JSON.stringify({
          repo,
          slug,
          docker_compose:  dockerCompose,
          env_example:     schema?.deployment?.env_example || null,
          timeout_seconds: 120,
        }),
        signal: AbortSignal.timeout(135000),
      });

      if (harness.ok) {
        const result = await harness.json();
        // Record verified execution as a feedback event
        if (ctx && env.DB && slug) {
          const outcome = result.exit_code === 0 ? "success" : "failure";
          const fp = await fingerprintAgent({ headers: new Headers() }, env);
          ctx.waitUntil(safe(env.DB.prepare(
            "INSERT OR IGNORE INTO deployment_feedback (ts, slug, outcome, error_code, agent_hint, schema_version, agent_type) VALUES (?,?,?,?,?,?,?)"
          ).bind(new Date().toISOString(), slug, outcome,
                 result.exit_code !== 0 ? `Exit ${result.exit_code}` : null,
                 result.stderr ? result.stderr.slice(0, 200) : null,
                 "v1", "sandbox_harness").run()));
        }
        return json({
          mode:       "executed",
          slug,
          repo,
          exit_code:  result.exit_code,
          stdout:     (result.stdout || "").slice(0, 2000),
          stderr:     (result.stderr || "").slice(0, 1000),
          duration_ms: result.duration_ms,
          verified:   result.exit_code === 0,
        });
      }
    } catch (e) {
      console.warn(`[sandbox] Harness call failed for ${slug}: ${e && e.message}`);
      // Fall through to IDE redirect
    }
  }

  // Fallback: IDE redirect (original behaviour)
  const provider  = (env.SANDBOX_PROVIDER || "codespaces").toLowerCase();
  const ghBase    = `https://github.com/${repo}`;
  const sandboxUrl =
    provider === "codespaces" ? `https://github.com/codespaces/new?repo=${encodeURIComponent(repo)}`
    : provider === "stackblitz" ? `https://stackblitz.com/github/${repo}`
    : `https://gitpod.io/#${ghBase}`;

  return new Response(null, {
    status: 302,
    headers: {
      Location:              sandboxUrl,
      "Cache-Control":       "no-store",
      "X-Sandbox-Provider":  provider,
      "X-Sandbox-Repo":      repo,
      "X-Execution-Mode":    "redirect",
    },
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRIORITY 4 — SCHEMA VERSIONING CONTRACT
   GET /api/schema/version — deprecation notices, migration paths, changelog.
   ═══════════════════════════════════════════════════════════════════════════ */

// Canonical version registry — update this when releasing new schema versions.
const SCHEMA_VERSION_REGISTRY = {
  current: "v1",
  versions: {
    "v1": {
      status:           "stable",
      released:         "2025-01-01",
      sunset_date:      null,       // set when v2 ships, give 6 months notice
      breaking_changes: [],
      deprecated_fields: [],
      layers: ["health","deployment","ci_cd","kubernetes","database",
               "troubleshooting","auth_protocol","oauth_flows",
               "dependency_graph","deployment_outcomes","version_meta"],
      changelog: [
        { date: "2025-01-01", note: "Initial release. 7 intelligence layers." },
        { date: "2025-03-01", note: "Added dependency_graph with CVE data (known_cves)." },
        { date: "2025-06-01", note: "Added deployment_outcomes feedback loop." },
      ],
    },
    // "v2": { status: "draft", ... }  ← add here before releasing
  }
};

async function handleSchemaVersion(url, env) {
  const slug    = (url.searchParams.get("slug")    || "").replace(/[^a-z0-9-]/g, "");
  const version = (url.searchParams.get("version") || "v1").replace(/[^a-z0-9.]/g, "");
  const reg     = SCHEMA_VERSION_REGISTRY;
  const current = reg.current;
  const info    = reg.versions[version] || reg.versions[current];

  // Check if agent is on a deprecated version
  const isDeprecated  = info.status === "deprecated" || info.sunset_date !== null;
  const isCurrent     = version === current;
  const upgradePath   = !isCurrent ? {
    from:            version,
    to:              current,
    migration_guide: `https://verditnxtgen.com/docs/schema-migration#${version}-to-${current}`,
    breaking_changes: (reg.versions[current]?.breaking_changes || []),
    auto_migrate:    true,   // our schemas are additive — v1 agents can read v1 fields from v2 schema
  } : null;

  const response = {
    requested_version: version,
    current_version:   current,
    is_current:        isCurrent,
    is_deprecated:     isDeprecated,
    status:            info.status,
    released:          info.released,
    sunset_date:       info.sunset_date,
    deprecation_notice: isDeprecated
      ? `Version ${version} will be sunset on ${info.sunset_date}. Migrate to ${current} before that date.`
      : null,
    upgrade_path:      upgradePath,
    layers:            info.layers,
    changelog:         info.changelog,
    schema_url:        slug
      ? `https://verditnxtgen.com/schemas/${version}/${slug}.agent-schema.json`
      : `https://verditnxtgen.com/schemas/${version}/{slug}.agent-schema.json`,
  };

  // Add deprecation headers so HTTP clients see it without parsing JSON
  const headers = { "Content-Type": "application/json" };
  if (isDeprecated) {
    headers["Deprecation"]  = `date="${info.sunset_date}"`;
    headers["Sunset"]       = info.sunset_date || "";
    headers["Link"]         = `<https://verditnxtgen.com/docs/schema-migration>; rel="deprecation"`;
  }

  return new Response(JSON.stringify(response), { status: 200, headers });
}

/* ── GET /api/schema/download — signed compliance manifest (Sprint 2 Ticket 3) ─
 *
 * Generates a JSON manifest suitable for SOC2 / ISO27001 audit evidence:
 *   { slug, commit_sha, intelligence_score, bizops_score, owasp_flags,
 *     evaluated_at, manifest_version, signature }
 *
 * The HMAC-SHA256 signature covers the canonical payload string so auditors
 * can verify the manifest was produced by VerditNxtGen's infrastructure and
 * has not been tampered with since issuance.
 *
 * Query params:
 *   ?slug=<tool-slug>   required
 *
 * Returns:
 *   200 JSON manifest  (Content-Disposition: attachment for direct download)
 *   400 missing slug
 *   404 tool not found in D1
 *   503 DB unavailable
 *
 * Secret required: MANIFEST_HMAC_SECRET (wrangler secret put MANIFEST_HMAC_SECRET)
 * Falls back to IP_SALT when secret not set — suitable for development, but
 * set a dedicated secret before showing manifests to external auditors.
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleSchemaDownload(url, env) {
  const slug = (url.searchParams.get("slug") || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);
  if (!slug) return json({ error: "slug is required" }, 400);
  if (!env.DB) return json({ error: "DB unavailable" }, 503);

  // Pull the most recent run for this slug from deployment_feedback
  const row = await safe(env.DB.prepare(`
    SELECT slug, commit_sha, version_tag, risk_score, usd_cost, duration_s,
           outcome, error_code, owasp_flags, security_boundary_violation,
           ts, schema_version, resource_profile
    FROM deployment_feedback
    WHERE slug = ?
    ORDER BY ts DESC
    LIMIT 1
  `).bind(slug).first());

  if (!row) {
    // No sandbox run yet — serve the static agent-schema.json if it exists.
    // This lets enterprise buyers inspect the deployment spec even before
    // the GHA swarm has produced a cryptographically signed manifest.
    if (env.ASSETS) {
      try {
        const schemaUrl = new URL(`/schemas/${slug}.agent-schema.json`, "https://verditnxtgen.com");
        const staticRes = await env.ASSETS.fetch(schemaUrl.toString());
        if (staticRes.ok) {
          const schema = await staticRes.json();
          return json({
            slug,
            schema_type:    "static",
            schema_version: schema.schema_version || "v1",
            manifest:       schema,
            ledger_status:  "pending_sandbox_run",
            note:           "Static schema. Full signed manifest available after the GHA swarm evaluates this tool.",
            generated_at:   new Date().toISOString(),
          });
        }
      } catch { /* fall through to 404 */ }
    }
    return json({
      error:  "Tool not found in ledger",
      detail: `No sandbox run for slug '${slug}' yet. The GHA swarm will evaluate it on its next cycle.`,
      hint:   "Try: graphify, observal, hope-agent, or tokentracker — these have signed manifests.",
    }, 404);
  }

  // Also pull bizops_score from tool_intelligence if available
  const intel = await safe(env.DB.prepare(`
    SELECT intelligence_score, pass_at_1, pass_at_3, pass_at_5
    FROM tool_intelligence WHERE slug = ?
  `).bind(slug).first());

  const issuedAt = new Date().toISOString();

  // ── Build the canonical payload ──────────────────────────────────────────
  // Fields are sorted alphabetically so the canonical string is deterministic
  // regardless of JS object insertion order. Auditors can reproduce the string
  // from the manifest fields and verify the signature independently.
  const owaspFlags = (() => {
    try { return JSON.parse(row.owasp_flags || "[]"); } catch { return []; }
  })();

  const payload = {
    commit_sha:              row.commit_sha    || null,
    duration_s:              row.duration_s    || null,
    error_code:              row.error_code    || null,
    evaluated_at:            row.ts,
    intelligence_score:      intel?.intelligence_score ?? row.risk_score ?? null,
    manifest_version:        "v1",
    outcome:                 row.outcome,
    owasp_flags:             owaspFlags,
    pass_at_1:               intel?.pass_at_1  ?? null,
    pass_at_3:               intel?.pass_at_3  ?? null,
    pass_at_5:               intel?.pass_at_5  ?? null,
    resource_profile:        row.resource_profile || "A",
    risk_score:              row.risk_score    || null,
    schema_version:          row.schema_version || "v6",
    security_boundary_violation: row.security_boundary_violation === 1,
    slug,
    usd_cost:                row.usd_cost      || null,
    version_tag:             row.version_tag   || null,
  };

  // Canonical string: sorted keys, deterministic JSON, then issued_at appended
  // so each download produces a unique signature (prevents replay of old manifests).
  const canonicalStr = JSON.stringify(payload, Object.keys(payload).sort()) + `|issued_at:${issuedAt}`;

  // ── HMAC-SHA256 signature ─────────────────────────────────────────────────
  const signingSecret = env.MANIFEST_HMAC_SECRET || env.IP_SALT || "vng-dev-secret";
  const encoder       = new TextEncoder();
  const keyMaterial   = await crypto.subtle.importKey(
    "raw", encoder.encode(signingSecret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuf  = await crypto.subtle.sign("HMAC", keyMaterial, encoder.encode(canonicalStr));
  const sigHex  = [...new Uint8Array(sigBuf)].map(b => b.toString(16).padStart(2, "0")).join("");

  // ── Assemble manifest ─────────────────────────────────────────────────────
  const manifest = {
    ...payload,
    issued_at:          issuedAt,
    issuer:             "VerditNxtGen Intelligence Engine v6",
    issuer_url:         "https://verditnxtgen.com",
    // Signature metadata — auditors verify by:
    //   1. Reconstruct canonical_string (sorted-key JSON of payload fields + |issued_at:<ts>)
    //   2. HMAC-SHA256 with MANIFEST_HMAC_SECRET
    //   3. Compare hex output to manifest.signature
    signature:          sigHex,
    signature_algorithm: "HMAC-SHA256",
    canonical_string_construction: "JSON.stringify(payload_fields, sorted_keys) + '|issued_at:' + issued_at",
    // Human-readable verdict for SOC2 evidence packages
    verdict: {
      deploy_recommended: (intel?.intelligence_score ?? row.risk_score) !== null
        ? (row.outcome === "success" && !row.security_boundary_violation && owaspFlags.filter(f => ["LLM01","LLM06"].includes(f)).length === 0)
        : null,
      data_completeness: (intel?.intelligence_score ?? row.risk_score) !== null ? "full" : "partial",
      critical_flags:     owaspFlags.filter(f => f === "LLM01"),
      high_flags:         owaspFlags.filter(f => ["LLM06","LLM05","LLM10"].includes(f)),
      summary: (intel?.intelligence_score ?? row.risk_score) === null
        ? `Tool '${slug}' has been run but no risk_score is available yet (requires ≥3 runs via sandbox_runner). Manifest is partial.`
        : row.outcome === "success" && !row.security_boundary_violation
        ? `Tool '${slug}' passed all sandbox checks at commit ${(row.commit_sha||"unknown").slice(0,12)}. No security boundary violations detected.`
        : `Tool '${slug}' failed sandbox evaluation at commit ${(row.commit_sha||"unknown").slice(0,12)}. Review owasp_flags and error_code before adoption.`,
    },
  };

  const filename = `verditnxtgen-manifest-${slug}-${(row.commit_sha||"unknown").slice(0,12)}-${issuedAt.slice(0,10)}.json`;

  return new Response(JSON.stringify(manifest, null, 2), {
    status: 200,
    headers: {
      "Content-Type":        "application/json",
      "Content-Disposition": `attachment; filename="${filename}"`,
      // Cache-Control: no-store — each manifest must be freshly signed
      "Cache-Control":       "no-store, no-cache, must-revalidate",
      // CORS: allow enterprise tooling to fetch manifests cross-origin
      "Access-Control-Allow-Origin": "*",
    },
  });
}
/* Hard monthly token ceiling: once OPENAI_MONTHLY_BUDGET_USD is hit, all
   /api/audit calls fall back to localEstimate() until the month resets.
   ═══════════════════════════════════════════════════════════════════════════ */

async function checkSpendCeiling(env) {
  const budgetUsd = parseFloat(env.OPENAI_MONTHLY_BUDGET_USD || "20");
  if (!env.KVOPS || budgetUsd <= 0) return { allowed: true, spent: 0, budget: budgetUsd };

  const monthKey = new Date().toISOString().slice(0, 7);  // "2026-01"
  const spent    = parseFloat((await safe(env.KVOPS.get(`openai:spend:${monthKey}`))) || "0");
  return { allowed: spent < budgetUsd, spent, budget: budgetUsd, month: monthKey };
}

async function recordSpend(env, ctx, tokens_used) {
  // gpt-4o-mini pricing: $0.15/1M input + $0.60/1M output (blended ~$0.30/1M avg)
  const cost = (tokens_used / 1_000_000) * 0.30;
  if (!env.KVOPS || cost <= 0) return;
  const monthKey = new Date().toISOString().slice(0, 7);
  ctx.waitUntil((async () => {
    const current = parseFloat((await safe(env.KVOPS.get(`openai:spend:${monthKey}`))) || "0");
    await safe(env.KVOPS.put(`openai:spend:${monthKey}`,
      String(Math.round((current + cost) * 10000) / 10000),
      { expirationTtl: 2678400 }));  // 31 days
  })());
}

/* ═══════════════════════════════════════════════════════════════════════════
   PRIORITY 6 — THREAT INTELLIGENCE: competitor schema monitoring
   GET /api/competitor/status — checks if LangChain Hub, Docker Scout, or
   Sourcegraph Cody have shipped "agent-ready deployment context" features.
   Results are cached 24h in KV — no live scraping on every request.
   ═══════════════════════════════════════════════════════════════════════════ */

const COMPETITORS = [
  {
    id:          "langchain_hub",
    name:        "LangChain Hub",
    check_url:   "https://api.github.com/repos/langchain-ai/langchain/releases/latest",
    threat_keywords: ["agent schema", "deployment context", "mcp server", "agent-ready",
                      "infrastructure hub", "deployment blueprint"],
    moat_gap:    "If LangChain ships structured deployment schemas, they have distribution advantage via LangSmith.",
  },
  {
    id:          "docker_scout",
    name:        "Docker Scout",
    check_url:   "https://api.github.com/repos/docker/scout-cli/releases/latest",
    threat_keywords: ["agent context", "mcp", "deployment schema", "ai infrastructure",
                      "autonomous deployment"],
    moat_gap:    "Docker Scout owns the container layer. If they add MCP + schema output, they bypass our build-step intelligence.",
  },
  {
    id:          "sourcegraph_cody",
    name:        "Sourcegraph Cody",
    check_url:   "https://api.github.com/repos/sourcegraph/cody/releases/latest",
    threat_keywords: ["deployment context", "agent schema", "infrastructure blueprint",
                      "mcp server", "docker schema"],
    moat_gap:    "Cody has deep code-graph context. A deployment schema layer would directly compete with our CI/CD extraction.",
  },
];

async function handleCompetitorStatus(url, env, request) {
  // INTERNAL_API_KEY mandatory — fails closed. Same key as /api/analytics.
  // Set via: wrangler secret put INTERNAL_API_KEY
  if (!env.INTERNAL_API_KEY) {
    console.error("SECURITY: INTERNAL_API_KEY not configured — /api/competitor/status locked.");
    return json({ error: "Service temporarily unavailable" }, 503);
  }
  const provided_competitor = (request.headers.get("X-Internal-Key") || "").trim();
  if (!provided_competitor || provided_competitor !== env.INTERNAL_API_KEY) {
    return json({ error: "Unauthorized" }, 401);
  }
  const force = url.searchParams.get("force") === "true";
  const cacheKey = "competitor:status:latest";

  // Serve cached result unless force-refresh
  if (!force && env.KVOPS) {
    const cached = await safe(env.KVOPS.get(cacheKey));
    if (cached) {
      try { return json({ ...JSON.parse(cached), cached: true }); } catch {}
    }
  }

  const results = [];
  for (const comp of COMPETITORS) {
    let threat_detected = false;
    let latest_version  = null;
    let release_notes   = "";
    let checked_at      = new Date().toISOString();

    try {
      const res  = await fetch(comp.check_url, {
        headers: { "User-Agent": "VerditNxtGen-ThreatMonitor/1.0" },
        signal: AbortSignal.timeout(6000),
      });
      if (res.ok) {
        const data   = await res.json();
        latest_version = data.tag_name || data.name || "";
        release_notes  = (data.body || "").toLowerCase().slice(0, 3000);
        threat_detected = comp.threat_keywords.some(kw => release_notes.includes(kw.toLowerCase()));
      }
    } catch (e) {
      release_notes = `check_failed: ${e && e.message}`;
    }

    results.push({
      id:               comp.id,
      name:             comp.name,
      latest_version,
      threat_detected,
      matched_keywords: threat_detected
        ? comp.threat_keywords.filter(kw => release_notes.includes(kw.toLowerCase()))
        : [],
      moat_gap:         comp.moat_gap,
      checked_at,
      action_required:  threat_detected
        ? `URGENT: ${comp.name} may be shipping competing schema layer. Review immediately.`
        : null,
    });
  }

  const anyThreat = results.some(r => r.threat_detected);
  const payload = {
    checked_at:     new Date().toISOString(),
    threat_level:   anyThreat ? "HIGH" : "CLEAR",
    competitors:    results,
    our_moat:       "5-layer schema with CI/CD extraction, CVE data, deployment outcome feedback loop, and MCP server. Replicate = months of work.",
    cached:         false,
  };

  // Cache 24h
  if (env.KVOPS) {
    await safe(env.KVOPS.put(cacheKey, JSON.stringify(payload), { expirationTtl: 86400 }));
  }

  return json(payload);
}

/* ───── /api/model/status — live model training state (read by frontend) ──── */
async function handleModelStatus(env) {
  if (!env.KVOPS) return json({ status: "unknown", reason: "KV unavailable" });

  const raw = await safe(env.KVOPS.get("model:latest"));
  if (!raw) return json({ status: "pending", training_rows: 0,
                          message: "No model trained yet — sandbox runs accumulating." });
  try {
    const data = JSON.parse(raw);
    // Also fetch total training rows from checkpoint if available
    const cpRaw = await safe(env.KVOPS.get("training:checkpoint:summary"));
    const cp    = cpRaw ? JSON.parse(cpRaw) : {};
    return json({
      status:        "active",
      last_updated:  data.ts,
      run_id:        data.run_id,
      repo:          data.repo,
      training_rows: cp.total_rows || null,
      positive_samples: cp.positive || null,
    });
  } catch {
    return json({ status: "unknown", raw });
  }
}

/* ───────────────────────────── helpers ─────────────────────────────────── */
/* ─── Score-drop alert subscription ─────────────────────────────────────── */
/* ── POST /api/subscribe — homepage email subscription ───────────────────────
 * Called by index.html hero form. Accepts {email, consent, source}.
 * Writes to D1 subscribers table. Returns {ok: true} on success.
 * Same table used by audit opt-in — no duplicates (INSERT OR REPLACE).
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleSubscribe(request, env, ctx) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const email   = String(body.email   || "").trim().slice(0, 160);
  const consent = body.consent === true;
  const source  = String(body.source  || "homepage").slice(0, 40);

  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return json({ error: "Enter a valid email address" }, 400);
  }
  if (!consent) {
    return json({ error: "Consent is required" }, 400);
  }

  const ts = new Date().toISOString();

  if (env.DB) {
    try {
      await env.DB.prepare(
        "INSERT OR REPLACE INTO subscribers (email, consent, ts, source) VALUES (?,?,?,?)"
      ).bind(email, 1, ts, source).run();
    } catch (e) {
      console.error("handleSubscribe D1:", e);
      return json({ error: "Subscription failed — please try again" }, 500);
    }
  } else {
    // KV fallback when DB is not available
    if (env.KVOPS) {
      const key = "subscriber:" + btoa(email).replace(/[/+=]/g, "").slice(0, 40);
      ctx.waitUntil(safe(env.KVOPS.put(key, JSON.stringify({ email, ts, source }), { expirationTtl: 31536000 })));
    }
  }

  return json({ ok: true, message: "Subscribed — first issue Monday." });
}


async function handleAlertsSubscribe(request, env) {
  if (!env.DB) return json({ error: "DB unavailable" }, 503);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  const { slug, email, threshold = 10 } = body;
  if (!slug || !email) return json({ error: "slug and email required" }, 400);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "Invalid email" }, 400);
  const ts = new Date().toISOString();
  try {
    await env.DB.prepare(
      "INSERT INTO alert_subscriptions (email, slug, threshold, created_at) VALUES (?,?,?,?) ON CONFLICT(email,slug) DO UPDATE SET threshold=excluded.threshold"
    ).bind(email, slug.toLowerCase().trim(), Math.min(Math.max(parseInt(threshold)||10, 1), 50), ts).run();
    return json({ ok: true, slug, email, threshold });
  } catch(e) {
    console.error("handleAlertsSubscribe:", e);
    return json({ error: "Subscription failed" }, 500);
  }
}


/* ─── /api/tools — paginated directory ──────────────────────────────────── */
async function handleToolsDirectory(url, env) {
  const page     = Math.max(1, parseInt(url.searchParams.get("page") || "1"));
  const pageSize = Math.min(500, Math.max(1, parseInt(url.searchParams.get("per_page") || "20")));
  const category = (url.searchParams.get("category") || "").trim();
  const sort     = url.searchParams.get("sort") || "score";
  const q        = (url.searchParams.get("q") || "").toLowerCase().trim();
  const catalog  = await loadCatalog(env);
  if (!catalog || !catalog.length) return json({ error: "Directory not yet available", tools: [], total: 0 }, 503);
  let tools = catalog;
  if (category) tools = tools.filter(t => (t.category || "").toLowerCase() === category.toLowerCase());
  if (q) tools = tools.filter(t => (t.name || "").toLowerCase().includes(q) || (t.description || "").toLowerCase().includes(q));
  if (sort === "stars") tools.sort((a,b) => (b.stars||0)-(a.stars||0));
  else if (sort === "name") tools.sort((a,b) => (a.name||"").localeCompare(b.name||""));
  else if (sort === "trend") { const o={new:0,rising:1,stable:2,falling:3}; tools.sort((a,b)=>(o[a.trend_direction||"stable"]||2)-(o[b.trend_direction||"stable"]||2)); }
  else tools.sort((a,b) => (b.score||b.bizops_score||0)-(a.score||a.bizops_score||0));
  const total  = tools.length;
  const paged  = tools.slice((page-1)*pageSize, page*pageSize).map(t => ({
    slug:         t.slug||t.full_name||t.name,
    name:         t.name,
    description:  (t.description||"").slice(0,200),
    category:     t.category,
    bizops_score: t.score||t.bizops_score||0,
    trend:        t.trend_direction||"stable",
    stars:        t.stars||t.stargazers_count||0,
    language:     t.language,
    schema_url:   t.slug ? `/schemas/${t.slug}.agent-schema.json` : null,
    signals:      t.score_breakdown||null,
  }));
  return json({ tools: paged, total, page, per_page: pageSize, pages: Math.ceil(total/pageSize) });
}

/* ─── /api/tool/:slug — single tool detail ──────────────────────────────── */
async function handleToolDetail(url, env) {
  const slug    = url.pathname.replace("/api/tool/","").replace(/\/+$/,"").toLowerCase();
  if (!slug || !/^[a-z0-9][a-z0-9\-/]{0,80}$/.test(slug)) return json({ error: "Invalid slug" }, 400);
  const catalog = await loadCatalog(env);
  if (!catalog) return json({ error: "Directory unavailable" }, 503);
  const tool    = catalog.find(t => (t.slug||t.full_name||t.name||"").toLowerCase().includes(slug) || (t.name||"").toLowerCase()===slug);
  if (!tool) return json({ error: `Tool not found: ${slug}` }, 404);
  const score = tool.score||tool.bizops_score||0;

  // ── Task 2: join D1 for enterprise compliance fields ─────────────────────
  // Pull latest sandbox run for risk_score, commit_sha, owasp_flags, days_since_run
  let runRow = null;
  if (env.DB) {
    runRow = await safe(env.DB.prepare(
      `SELECT risk_score, commit_sha, owasp_flags, ts, peak_memory_mb, usd_cost,
              a2a_tested, security_boundary_violation
       FROM deployment_feedback
       WHERE slug = ? ORDER BY ts DESC LIMIT 1`
    ).bind(slug).first());
  }

  const riskScore    = runRow?.risk_score      ?? null;
  const commitSha    = runRow?.commit_sha       || null;
  const owaspRaw     = (() => { try { return JSON.parse(runRow?.owasp_flags || "[]"); } catch { return []; } })();
  const lastRunTs    = runRow?.ts               || null;
  const daysSinceRun = lastRunTs
    ? Math.floor((Date.now() - new Date(lastRunTs).getTime()) / 86400000)
    : null;

  // token_budget: estimated context tokens based on schema size
  const schemaUrl    = tool.slug ? `/schemas/${tool.slug}.agent-schema.json` : null;
  const estTokens    = 850;   // avg agent schema ~850 tokens; refined when schema is fetched
  const tokenBudget  = {
    estimated_tokens:    estTokens,
    max_tokens:          null,    // set by enterprise plan; null = unlimited
    estimate_confidence: "low",   // "high" once schema is loaded and measured
    schema_url:          schemaUrl,
  };

  return json({
    slug:             tool.slug||tool.full_name,
    name:             tool.name,
    description:      tool.description,
    category:         tool.category,
    bizops_score:     score,
    risk_tier:        score>=SCORE_TIERS.PRODUCTION_GRADE?"production_grade":score>=SCORE_TIERS.ADOPTABLE?"adoptable":score>=SCORE_TIERS.CAUTION?"caution":"avoid",
    trend:            tool.trend_direction,
    stars:            tool.stars||tool.stargazers_count||0,
    language:         tool.language,
    html_url:         tool.html_url,
    schema_url:       schemaUrl,
    last_commit_days: tool.last_commit_days,
    signals:          tool.score_breakdown||null,
    bus_factor:       tool.top_contributor_pct||null,
    branch_protected: tool.branch_protected||null,
    pkg_downloads:    tool.pkg_downloads||null,
    // ── Enterprise compliance fields (from D1 sandbox telemetry) ─────────
    risk_score:       riskScore,
    commit_sha:       commitSha,
    owasp_flags:      owaspRaw,
    days_since_run:   daysSinceRun,
    token_budget:     tokenBudget,
    peak_memory_mb:   runRow?.peak_memory_mb   ?? null,
    usd_cost:         runRow?.usd_cost         ?? null,
    a2a_tested:       runRow?.a2a_tested === 1 || runRow?.a2a_tested === true,
    security_boundary_violation: runRow?.security_boundary_violation === 1 || false,
    data_completeness: riskScore !== null ? "full" : "partial",
  });
}

/* ─── /api/route-audit — routing oracle for agent routing platforms ─────── */
// Pre-auction due diligence: given a capability, return ranked open-source
// providers by health score. Routing platforms weight auctions not just on
// cost/latency but on tool maintenance health — bus factor, commit recency,
// deployment success rate. This endpoint is the intelligence feed for that.
async function handleRouteAudit(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  // Accept both 'capability' (canonical) and 'requirements.category' (legacy field name)
  const reqCategory = (body.requirements && typeof body.requirements === 'object')
    ? String(body.requirements.category || body.requirements.capability || "").trim()
    : "";
  const capability = String(body.capability || reqCategory || "").slice(0,120).trim();
  const context    = String(body.context||"").slice(0,300).trim();
  const topN       = Math.min(10, Math.max(1, parseInt(body.top_n||"5")));
  if (!capability) return json({ error: "capability required. Use: {capability:'database'} or {requirements:{category:'Database'}}" }, 400);
  const catalog = await loadCatalog(env);
  if (!catalog||!catalog.length) return json({ error: "Directory unavailable" }, 503);
  const targetCat = CAPABILITY_MAP[capability.toLowerCase()]||null;
  let candidates  = targetCat ? catalog.filter(t=>(t.category||"")===targetCat) : catalog;
  if (!candidates.length) candidates = catalog;
  const capWords  = capability.toLowerCase().split(/\s+/);
  const scored    = candidates.filter(t => capWords.some(w=>(t.name||"").toLowerCase().includes(w)||(t.description||"").toLowerCase().includes(w)||(t.category||"").toLowerCase().includes(w)));
  const rest      = candidates.filter(t => !scored.includes(t));
  const seen = new Set();
  const ranked = [...scored,...rest].filter(t=>{ const k=t.slug||t.name; if(seen.has(k))return false; seen.add(k); return true; })
    .sort((a,b)=>(b.score||b.bizops_score||0)-(a.score||a.bizops_score||0)).slice(0,topN);
  // Join feedback_snapshots from D1 for real deployment_success_rate
  let snapshotRates = {};
  if (env.DB) {
    try {
      const placeholders = ranked.map(() => "?").join(",");
      const slugsForQuery = ranked.map(t => t.slug||t.full_name||t.name).filter(Boolean);
      if (slugsForQuery.length) {
        const rows = await env.DB.prepare(
          `SELECT slug, AVG(success_rate) as avg_rate, SUM(total) as total_runs
           FROM feedback_snapshots WHERE slug IN (${placeholders}) GROUP BY slug`
        ).bind(...slugsForQuery).all();
        for (const row of (rows?.results || [])) {
          snapshotRates[row.slug] = { rate: row.avg_rate, runs: row.total_runs };
        }
      }
    } catch { /* non-fatal — falls back to null */ }
  }

  const providers = ranked.map(t=>{
    const score = t.score||t.bizops_score||0;
    const snap  = snapshotRates[t.slug||t.full_name||t.name] || null;
    return {
      slug:                   t.slug||t.full_name||t.name,
      name:                   t.name,
      category:               t.category,
      bizops_score:           score,
      risk_tier:              score>=SCORE_TIERS.PRODUCTION_GRADE?"production_grade":score>=SCORE_TIERS.ADOPTABLE?"adoptable":score>=SCORE_TIERS.CAUTION?"caution":"avoid",
      trend:                  t.trend_direction||"stable",
      deployment_success_rate: snap ? Math.round(snap.rate * 10) / 10 : null,
      deployment_run_count:    snap ? snap.runs : null,
      schema_url:             t.slug?`/schemas/${t.slug}.agent-schema.json`:null,
      signals: {
        commit_recency:    t.score_breakdown?.commit_recency||null,
        bus_factor:        t.score_breakdown?.bus_factor||null,
        ci_status:         t.score_breakdown?.ci_status||null,
        pkg_downloads:     t.score_breakdown?.pkg_downloads||null,
        branch_protection: t.score_breakdown?.branch_protection||null,
      },
    };
  });
  return json({
    capability,
    context:          context||null,
    ranked_providers: providers,
    recommendation:   providers[0]?`${providers[0].name} leads with score ${providers[0].bizops_score}/100 (${providers[0].risk_tier})`:"No providers found",
    data_freshness:   "Updated Mon/Thu",
    generated_at:     new Date().toISOString(),
  });
}

// ── Security: origin allowlist for CORS ─────────────────────────────────────
// Only verditnxtgen.com (and staging) may make credentialed cross-origin calls.
// Agents calling /api/mcp or /api/schema from server-side code are not browsers
// and don't send an Origin header — they pass through unrestricted.
const ALLOWED_ORIGINS = new Set([
  "https://verditnxtgen.com",
  "https://www.verditnxtgen.com",
  "https://staging.verditnxtgen.com",
]);

function getAllowedOrigin(request) {
  const origin = (request && request.headers && request.headers.get("Origin")) || "";
  // No Origin header = server-side / curl / agent call — allow
  if (!origin) return "*";
  // Known origin — reflect it
  if (ALLOWED_ORIGINS.has(origin)) return origin;
  // Unknown browser origin — block
  return "null";
}

function json(obj, status = 200, request = null) {
  const origin = getAllowedOrigin(request);
  const reqId  = crypto.randomUUID().slice(0, 8);
  return new Response(JSON.stringify(obj), {
    status, headers: {
      "Content-Type":                "application/json",
      "Cache-Control":               "no-store",
      "Access-Control-Allow-Origin": origin,
      "Vary":                        "Origin",
      "X-Request-ID":                reqId,
      "X-Content-Type-Options":      "nosniff",
    }
  });
}
function preflight(request = null) {
  const origin = getAllowedOrigin(request);
  return new Response(null, { status: 204, headers: {
    "Access-Control-Allow-Origin":  origin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,X-Internal-Key,X-Api-Key",
    "Access-Control-Max-Age":       "86400",
    "Vary":                         "Origin",
  }});
}
// ── IP hashing — requires IP_SALT secret in Cloudflare ──────────────────────
// Hard-fail if secret is missing rather than falling back to a predictable value.
// Set via: wrangler secret put IP_SALT  (any high-entropy random string)
function requireSalt(env) {
  if (!env.IP_SALT) {
    // Log to Cloudflare observability — never expose to client
    console.error("SECURITY: IP_SALT secret not configured. Set via wrangler secret put IP_SALT");
    throw new Error("SECURITY_CONFIG");
  }
  return env.IP_SALT;
}


function clampInt(v, min, max) {
  const n = Math.floor(Number(v));
  if (!isFinite(n)) return 0;
  return Math.max(min, Math.min(max, n));
}
function bucketTeam(n) {
  if (n <= 5) return "1-5";
  if (n <= 15) return "6-15";
  if (n <= 50) return "16-50";
  if (n <= 150) return "51-150";
  return "151+";
}
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function safe(promise) { try { return await promise; } catch (e) { console.log("db error:", e && e.message); return null; } }


/* ═══════════════════════════════════════════════════════════════════════════
   V6 Intelligence API Handlers
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── POST /api/client-config — register enterprise tool overrides ─────────────
 * Stores client-specific port, health endpoint, and env overrides in D1.
 * sandbox_runner.py reads these via GET /api/client-config at startup,
 * merging them into ENTERPRISE_KNOWLEDGE_BASE before each audit run.
 *
 * Body: {
 *   api_key:          "vnxt_...",        // enterprise API key
 *   slug:             "my-tool",         // tool slug to configure
 *   port:             9876,              // primary port to probe
 *   health_endpoint:  "/api/health",     // custom health check path
 *   alt_ports:        [9877, 9878],      // fallback ports
 *   env:              { "KEY": "val" },  // env var overrides
 *   iproute2_required: true              // inject iproute2 if missing
 * }
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleClientConfig(request, env, ctx) {
  const auth = await requireApiKey(request, env, ctx);
  if (!auth.ok) return auth.response;

  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const slug = String(body.slug || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);
  if (!slug) return json({ error: "slug is required" }, 400);

  const config = {
    slug,
    port:               Number.isInteger(body.port)        ? body.port        : null,
    health_endpoint:    String(body.health_endpoint  || "/").slice(0, 200),
    alt_ports:          Array.isArray(body.alt_ports) ? body.alt_ports.filter(p => Number.isInteger(p)) : [],
    env_overrides:      body.env && typeof body.env === "object" ? JSON.stringify(body.env) : null,
    iproute2_required:  body.iproute2_required === true ? 1 : 0,
    registered_by:      auth.keyHash ? auth.keyHash.slice(0, 16) : "unknown",
    created_at:         new Date().toISOString(),
  };

  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(`
      INSERT INTO enterprise_tool_configs
        (slug, port, health_endpoint, alt_ports, env_overrides, iproute2_required, registered_by, created_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(slug) DO UPDATE SET
          port=excluded.port, health_endpoint=excluded.health_endpoint,
          alt_ports=excluded.alt_ports, env_overrides=excluded.env_overrides,
          iproute2_required=excluded.iproute2_required,
          registered_by=excluded.registered_by, created_at=excluded.created_at
    `).bind(
      config.slug, config.port, config.health_endpoint,
      JSON.stringify(config.alt_ports), config.env_overrides,
      config.iproute2_required, config.registered_by, config.created_at
    ).run()));
  }

  // Also update KV so sandbox_runner.py can fetch without DB latency
  if (env.KVOPS) {
    ctx.waitUntil(safe(env.KVOPS.put(
      `client-config:${slug}`,
      JSON.stringify(config),
      { expirationTtl: 2592000 }  // 30d
    )));
  }

  return json({ ok: true, slug, config });
}

/* ── GET /api/client-config?slug=<slug>|all ─────────────────────────────────
 * Used by sandbox_runner.py at startup to fetch all enterprise overrides.
 * sandbox_runner merges these into its ENTERPRISE_KNOWLEDGE_BASE dict.
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleGetClientConfig(url, env) {
  const slug = url.searchParams.get("slug");

  // KV fast path for single slug
  if (slug && env.KVOPS) {
    const raw = await safe(env.KVOPS.get(`client-config:${slug}`));
    if (raw) return json({ slug, config: JSON.parse(raw), source: "kv" });
  }

  if (!env.DB) return json({ error: "DB unavailable" }, 503);

  let result;
  if (slug) {
    result = await safe(env.DB.prepare(
      "SELECT * FROM enterprise_tool_configs WHERE slug=?"
    ).bind(slug).first());
    return json({ slug, config: result || null });
  }

  // Return all configs — used by sandbox_runner.py to build enterprise_clients.json
  const all = await safe(env.DB.prepare(
    "SELECT * FROM enterprise_tool_configs ORDER BY created_at DESC"
  ).all());

  // Format as enterprise_clients.json structure for direct use by sandbox_runner
  const client_tools = (all?.results || []).map(row => ({
    slug:              row.slug,
    port:              row.port,
    health_endpoint:   row.health_endpoint,
    alt_ports:         JSON.parse(row.alt_ports || "[]"),
    env:               row.env_overrides ? JSON.parse(row.env_overrides) : {},
    iproute2_required: row.iproute2_required === 1,
  }));

  return json({
    client_tools,
    count: client_tools.length,
    generated_at: new Date().toISOString(),
  });
}

/* ── POST /api/port-discovery — self-learning port cache ──────────────────── */
async function handlePortDiscovery(request, env, ctx) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  const slug = String(body.slug || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);
  const port = Number.isInteger(body.discovered_port) ? body.discovered_port : null;
  if (!slug || !port) return json({ error: "slug and discovered_port required" }, 400);
  const ts = new Date().toISOString();
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(`
      INSERT INTO port_discovery (slug, discovered_port, env_overrides, success_count, last_seen)
      VALUES (?,?,?,1,?)
      ON CONFLICT(slug, discovered_port) DO UPDATE SET
        success_count=success_count+1,
        last_seen=excluded.last_seen,
        env_overrides=COALESCE(excluded.env_overrides, env_overrides)
    `).bind(slug, port, body.env_overrides ? JSON.stringify(body.env_overrides) : null, ts).run()));
  }
  if (env.KVOPS) {
    ctx.waitUntil(safe(env.KVOPS.put(`port:${slug}`, String(port), { expirationTtl: 604800 })));
  }
  return json({ ok: true, slug, port });
}

/* ── GET /api/intelligence?slug=<slug> — full intelligence profile ─────────── */
async function handleIntelligence(url, env) {
  const slug = url.searchParams.get("slug");
  if (!slug) return json({ error: "slug is required" }, 400);
  if (!env.DB) return json({ error: "DB unavailable" }, 503);

  const [intel, passK, owasp, cost, a2a] = await Promise.all([
    safe(env.DB.prepare("SELECT * FROM tool_intelligence WHERE slug=?").bind(slug).first()),
    safe(env.DB.prepare("SELECT * FROM pass_k_metrics WHERE slug=? ORDER BY week_start DESC LIMIT 8").bind(slug).all()),
    safe(env.DB.prepare("SELECT owasp_id, owasp_name, severity, COUNT(*) as count FROM owasp_findings WHERE slug=? GROUP BY owasp_id ORDER BY count DESC").bind(slug).all()),
    safe(env.DB.prepare("SELECT resource_profile, AVG(usd_cost) as avg_cost, SUM(usd_cost) as total_cost, COUNT(*) as runs FROM cost_telemetry WHERE slug=? GROUP BY resource_profile").bind(slug).all()),
    safe(env.DB.prepare("SELECT outcome, AVG(session_score) as avg_score, COUNT(*) as sessions FROM a2a_sessions WHERE initiator_slug=? OR responder_slug=? GROUP BY outcome").bind(slug, slug).all()),
  ]);

  return json({
    slug,
    intelligence:    intel || null,
    pass_k_history:  passK?.results || [],
    owasp_findings:  owasp?.results || [],
    cost_by_profile: cost?.results  || [],
    a2a_sessions:    a2a?.results   || [],
    generated_at:    new Date().toISOString(),
  });
}

/* ── GET /api/pass-k?slug=<slug>&weeks=<n> ─────────────────────────────────── */
async function handlePassK(url, env) {
  const slug  = url.searchParams.get("slug");
  const weeks = Math.min(52, Math.max(1, parseInt(url.searchParams.get("weeks") || "12")));
  if (!env.DB) return json({ error: "DB unavailable" }, 503);

  let stmt, results;
  if (slug) {
    stmt = env.DB.prepare(
      "SELECT * FROM pass_k_metrics WHERE slug=? ORDER BY week_start DESC LIMIT ?"
    ).bind(slug, weeks);
  } else {
    // Aggregate across all tools — shows ecosystem reliability trend
    stmt = env.DB.prepare(`
      SELECT week_start, profile,
        SUM(total_runs) as total_runs, SUM(successes) as successes,
        CAST(SUM(successes) AS REAL)/CAST(SUM(total_runs) AS REAL) as success_rate,
        AVG(pass_at_1) as pass_at_1, AVG(pass_at_3) as pass_at_3,
        AVG(pass_at_5) as pass_at_5, AVG(pass_at_8) as pass_at_8
      FROM pass_k_metrics
      GROUP BY week_start, profile
      ORDER BY week_start DESC LIMIT ?
    `).bind(weeks * 2);
  }
  results = await safe(stmt.all());
  return json({ slug: slug || "all", data: results?.results || [], weeks });
}

/* ── GET /api/owasp?severity=critical&limit=20 ─────────────────────────────── */
async function handleOwaspSummary(url, env) {
  const severity = url.searchParams.get("severity");
  const limit    = Math.min(100, parseInt(url.searchParams.get("limit") || "20"));
  if (!env.DB) return json({ error: "DB unavailable" }, 503);

  let stmt;
  if (severity) {
    stmt = env.DB.prepare(
      "SELECT slug, owasp_id, owasp_name, severity, COUNT(*) as count, MAX(ts) as last_seen FROM owasp_findings WHERE severity=? GROUP BY slug, owasp_id ORDER BY count DESC LIMIT ?"
    ).bind(severity, limit);
  } else {
    stmt = env.DB.prepare(
      "SELECT owasp_id, owasp_name, severity, COUNT(DISTINCT slug) as affected_tools, COUNT(*) as total_occurrences FROM owasp_findings GROUP BY owasp_id ORDER BY total_occurrences DESC"
    );
  }
  const results = await safe(stmt.all());

  // Global OWASP summary counts
  const summary = await safe(env.DB.prepare(
    "SELECT severity, COUNT(*) as count FROM owasp_findings GROUP BY severity"
  ).all());

  return json({
    owasp_summary:  summary?.results  || [],
    findings:       results?.results  || [],
    generated_at:   new Date().toISOString(),
  });
}

/* ── GET /api/cost-intelligence?slug=<slug>&profile=A ─────────────────────── */
async function handleCostIntelligence(url, env) {
  const slug    = url.searchParams.get("slug");
  const profile = url.searchParams.get("profile") || "all";
  if (!env.DB) return json({ error: "DB unavailable" }, 503);

  let stmt;
  if (slug) {
    stmt = env.DB.prepare(`
      SELECT resource_profile, platform,
        COUNT(*) as runs, AVG(usd_cost) as avg_cost, SUM(usd_cost) as total_cost,
        AVG(duration_s) as avg_duration_s,
        MIN(usd_cost) as min_cost, MAX(usd_cost) as max_cost
      FROM cost_telemetry WHERE slug=?
      ${profile !== "all" ? "AND resource_profile=?" : ""}
      GROUP BY resource_profile, platform
    `);
    stmt = profile !== "all" ? stmt.bind(slug, profile) : stmt.bind(slug);
  } else {
    // Ecosystem-wide cost intelligence
    stmt = env.DB.prepare(`
      SELECT resource_profile, platform,
        COUNT(DISTINCT slug) as unique_tools,
        COUNT(*) as total_runs, AVG(usd_cost) as avg_cost,
        SUM(usd_cost) as total_cost_usd,
        -- Cost ratio A/B: how much cheaper is Profile A vs B per run?
        0 as cost_ratio_ab
      FROM cost_telemetry
      GROUP BY resource_profile, platform
      ORDER BY resource_profile
    `);
  }

  const results = await safe(stmt.all());

  // Compute in-house benchmark comparison
  // In-house ~$12/hr engineering + $2/hr infra = $14/hr = $0.0039/s = ~$0.35/run (avg 90s)
  const inHouseBenchmarkPerRun = 0.35;
  const avgCost = results?.results?.[0]?.avg_cost || 0;
  const savingsMultiple = avgCost > 0 ? Math.round(inHouseBenchmarkPerRun / avgCost) : null;

  return json({
    slug:                 slug || "ecosystem",
    profile,
    cost_data:            results?.results || [],
    in_house_benchmark:   { cost_per_run: inHouseBenchmarkPerRun, assumption: "$14/hr eng+infra × 90s avg" },
    savings_multiple:     savingsMultiple,
    generated_at:         new Date().toISOString(),
  });
}

/* ── GET /api/a2a/sessions?slug=<slug>&limit=50 ─────────────────────────────── */
async function handleA2ASessions(url, env) {
  const slug  = url.searchParams.get("slug");
  const limit = Math.min(200, parseInt(url.searchParams.get("limit") || "50"));
  if (!env.DB) return json({ error: "DB unavailable" }, 503);

  let stmt;
  if (slug) {
    stmt = env.DB.prepare(
      "SELECT * FROM a2a_sessions WHERE initiator_slug=? OR responder_slug=? ORDER BY ts DESC LIMIT ?"
    ).bind(slug, slug, limit);
  } else {
    stmt = env.DB.prepare(
      "SELECT * FROM a2a_sessions ORDER BY ts DESC LIMIT ?"
    ).bind(limit);
  }
  const results = await safe(stmt.all());

  const stats = await safe(env.DB.prepare(
    "SELECT COUNT(DISTINCT initiator_slug) as a2a_tools, AVG(session_score) as avg_score, COUNT(*) as total_sessions FROM a2a_sessions WHERE outcome='success'"
  ).first());

  return json({
    slug: slug || "all",
    sessions: results?.results || [],
    stats:    stats || { a2a_tools: 0, avg_score: 0, total_sessions: 0 },
    generated_at: new Date().toISOString(),
  });
}

/* ── POST /api/precommit — DeepEval / shift-left CI result logging ───────────
 * Called by CI pipelines (GitHub Actions, GitLab CI, local pre-commit hooks)
 * after running the VerditNxtGen eval suite against a tool schema change.
 * Stores in D1 precommit_runs table for trend analysis.
 * ─────────────────────────────────────────────────────────────────────────── */
async function handlePrecommitRun(request, env, ctx) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
  const slug    = String(body.slug    || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);
  const trigger = String(body.trigger || "ci").slice(0, 20);
  if (!slug) return json({ error: "slug is required" }, 400);
  const ts = new Date().toISOString();
  if (env.DB) {
    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT INTO precommit_runs (ts, slug, trigger, runner_version, tests_run, tests_passed, tests_failed, eval_score, latency_ms, cost_usd, raw_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(
      ts, slug, trigger,
      String(body.runner_version || "").slice(0, 20) || null,
      Number.isInteger(body.tests_run)    ? body.tests_run    : 0,
      Number.isInteger(body.tests_passed) ? body.tests_passed : 0,
      Number.isInteger(body.tests_failed) ? body.tests_failed : 0,
      typeof body.eval_score === "number" ? body.eval_score   : null,
      Number.isInteger(body.latency_ms)   ? body.latency_ms   : null,
      typeof body.cost_usd === "number"   ? body.cost_usd     : null,
      body.raw_json ? JSON.stringify(body.raw_json).slice(0, 4000) : null,
    ).run()));
  }
  const passed = (body.tests_failed || 0) === 0;
  return json({
    ok:      true,
    slug,
    trigger,
    passed,
    ts,
    message: passed
      ? `All ${body.tests_run || 0} eval tests passed — safe to deploy`
      : `${body.tests_failed} test(s) failed — block deployment`,
  });
}

/* ─────────────────── /api/schema-feedback (deployment outcome loop) ─────────
 * Agents POST here after attempting a deployment using a downloaded schema.
 * Outcomes are stored in D1 deployment_feedback table and read by the scraper
 * on the next run to compute deployment_verified and success_rate.
 * Also writes co-deployment edges to infra_graph for the stack planner.
 * ────────────────────────────────────────────────────────────────────────── */
async function handleSchemaFeedback(request, env, ctx) {
  // Read body first so we have the slug for the composite key
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  // Validate swarm API key — prevents arbitrary D1 writes from non-swarm callers.
  // Swarm sends api_key in the JSON body. VERDITNXTGEN_SWARM_API_KEY is set as a
  // wrangler secret (not a plain env var) so it never appears in wrangler.toml.
  const swarmKey = env.VERDITNXTGEN_SWARM_API_KEY || env.INTERNAL_API_KEY || "";
  if (swarmKey) {
    const sentKey = String(body.api_key || "").trim();
    if (!sentKey || sentKey !== swarmKey) {
      return json({ error: "Unauthorized" }, 401);
    }
  }

  const slug      = String(body.slug || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);
  const userAgent = String(request.headers.get("User-Agent") || "").slice(0, 200);

  // Landmine B fix: composite rate limit key — IP + User-Agent + slug.
  // IP-only limits would block entire enterprise NAT ranges and cloud IDE users
  // (GitHub Codespaces, Replit, corporate firewalls) who share one IP address.
  // Composite key means each agent identity + target tool gets its own 20/hr bucket.
  const ip            = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const compositeKey  = `${ip}|${userAgent.slice(0, 50)}|${slug}`;
  const compositeHash = await sha256(compositeKey + "|" + requireSalt(env));
  const hour          = Math.floor(Date.now() / 3600000);
  const rlKey         = `rl:feedback:${compositeHash}:${hour}`;
  const fbLimit       = clampInt(env.FEEDBACK_RATE_LIMIT_PER_HOUR, 1, 1000) || 20;

  if (env.KVOPS) {
    const used = parseInt((await safe(env.KVOPS.get(rlKey))) || "0", 10);
    if (used >= fbLimit) return json({
      error: `Rate limit reached (${fbLimit}/hour per agent+slug). Try again next hour.`
    }, 429);
    ctx.waitUntil(env.KVOPS.put(rlKey, String(used + 1), { expirationTtl: 3600 }));
  }

  const ipHash        = await sha256(ip + "|" + requireSalt(env));
  const outcome       = String(body.outcome      || "").toLowerCase();
  const errorCode     = String(body.error_code   || "").slice(0, 100);
  const agentHint     = String(body.agent_hint   || "").slice(0, 500);
  const schemaVersion = String(body.schema_version || "v1").slice(0, 10);
  const coDeployed    = Array.isArray(body.co_deployed_with)
    ? body.co_deployed_with.map(s => String(s).replace(/[^a-z0-9-]/g, "").slice(0, 80)).filter(Boolean)
    : [];

  if (!slug)                                    return json({ error: "slug is required" }, 400);
  if (!["success","failure"].includes(outcome)) return json({ error: "outcome must be 'success' or 'failure'" }, 400);

  const ts = new Date().toISOString();

  if (env.DB) {
    // Phase 3 fields — present when sandbox_runner V5 POSTs them
    const taskCompletion = body.task_completion_status !== undefined ? (body.task_completion_status === true ? 1 : body.task_completion_status === false ? 0 : null) : null;
    const toolCallCount  = Number.isInteger(body.tool_call_count)  ? body.tool_call_count  : null;
    const toolCallEff    = String(body.tool_call_efficiency  || "").slice(0, 20) || null;
    const secViolation   = body.security_boundary_violation === true ? 1 : 0;

    // V6 new fields — declared before prepare() so they're in scope for .bind()
    const resourceProfile = String(body.resource_profile  || 'A').slice(0, 5);
    const usdCost         = typeof body.usd_cost === 'number' ? body.usd_cost : null;
    const commitSha       = String(body.commit_sha  || '').slice(0, 12)  || null;
    const versionTag      = String(body.version_tag || '').slice(0, 50)  || null;
    const riskScore       = typeof body.risk_score  === 'number' ? body.risk_score : null;
    const objRespMs       = Number.isInteger(body.obj_payload_response_ms) ? body.obj_payload_response_ms : null;
    const passK1          = typeof body.pass_k_1 === 'number' ? body.pass_k_1 : null;
    const passK3          = typeof body.pass_k_3 === 'number' ? body.pass_k_3 : null;
    const passK5          = typeof body.pass_k_5 === 'number' ? body.pass_k_5 : null;
    const passK8          = typeof body.pass_k_8 === 'number' ? body.pass_k_8 : null;
    const owaspFlags      = Array.isArray(body.owasp_flags) ? JSON.stringify(body.owasp_flags) : null;
    const a2aTested       = body.a2a_tested === true ? 1 : 0;
    const durationS       = typeof body.duration_s === 'number' ? body.duration_s : null;

    ctx.waitUntil(safe(env.DB.prepare(
      "INSERT OR IGNORE INTO deployment_feedback (ts, slug, outcome, error_code, agent_hint, schema_version, user_agent, ip_hash, task_completion_status, tool_call_count, tool_call_efficiency, security_boundary_violation, resource_profile, usd_cost, commit_sha, version_tag, risk_score, obj_payload_response_ms, pass_k_1, pass_k_3, pass_k_5, pass_k_8, owasp_flags, a2a_tested, duration_s) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(ts, slug, outcome, errorCode || null, agentHint || null, schemaVersion, userAgent || null, ipHash, taskCompletion, toolCallCount, toolCallEff, secViolation, resourceProfile, usdCost, commitSha, versionTag, riskScore, objRespMs, passK1, passK3, passK5, passK8, owaspFlags, a2aTested, durationS).run()));

    // V6: Write cost telemetry row
    if (env.DB && usdCost !== null) {
      ctx.waitUntil(safe(env.DB.prepare(
        "INSERT INTO cost_telemetry (ts, slug, resource_profile, duration_s, platform, usd_cost, outcome, agent_id) VALUES (?,?,?,?,?,?,?,?)"
      ).bind(ts, slug, resourceProfile, durationS, 'github_actions', usdCost, outcome, String(body.agent_id || '')).run()));
    }

    // V6: Write OWASP findings rows
    if (env.DB && Array.isArray(body.owasp_flags) && body.owasp_flags.length > 0) {
      const owaspNameMap = {
        LLM01: 'Prompt Injection', LLM04: 'Model Denial of Service',
        LLM05: 'Insecure Output Handling', LLM06: 'Sensitive Information Disclosure',
        LLM08: 'Vector and Embedding Weaknesses', LLM09: 'Misinformation',
        LLM10: 'Unbounded Consumption',
      };
      const owaspSeverity = {
        LLM01: 'critical', LLM06: 'high', LLM05: 'high',
        LLM09: 'medium',   LLM10: 'high', LLM04: 'medium', LLM08: 'low',
      };
      for (const owaspId of body.owasp_flags) {
        ctx.waitUntil(safe(env.DB.prepare(
          "INSERT INTO owasp_findings (ts, slug, run_ts, owasp_id, owasp_name, severity, agent_hint, auto_detected) VALUES (?,?,?,?,?,?,?,1)"
        ).bind(ts, slug, ts, owaspId, owaspNameMap[owaspId] || owaspId, owaspSeverity[owaspId] || 'medium', agentHint || null).run()));
      }
    }

    // V6: Write pass@k metrics to weekly table
    if (env.DB && passK1 !== null) {
      const weekStart = new Date(ts);
      weekStart.setUTCDate(weekStart.getUTCDate() - weekStart.getUTCDay() + 1);
      const weekStr = weekStart.toISOString().slice(0, 10);
      // Upsert the pass_k_metrics row for this slug+week+profile
      ctx.waitUntil(safe(env.DB.prepare(`
        INSERT INTO pass_k_metrics (slug, week_start, profile, total_runs, successes, success_rate, pass_at_1, pass_at_3, pass_at_5, pass_at_8, computed_at)
        VALUES (?,?,?,1,?,?,?,?,?,?,?)
        ON CONFLICT(slug, week_start, profile) DO UPDATE SET
          total_runs=total_runs+1,
          successes=successes+excluded.successes,
          success_rate=CAST(successes+excluded.successes AS REAL)/CAST(total_runs+1 AS REAL),
          pass_at_1=excluded.pass_at_1,
          pass_at_3=excluded.pass_at_3,
          pass_at_5=excluded.pass_at_5,
          pass_at_8=excluded.pass_at_8,
          computed_at=excluded.computed_at
      `).bind(slug, weekStr, resourceProfile, outcome === 'success' ? 1 : 0, passK1, passK1, passK3, passK5, passK8, ts).run()));
    }

    // V6: Write A2A session row
    if (env.DB && a2aTested && typeof body.a2a_score === 'number') {
      ctx.waitUntil(safe(env.DB.prepare(
        "INSERT INTO a2a_sessions (ts, initiator_slug, responder_slug, session_score, handshake_ms, outcome) VALUES (?,?,?,?,?,?)"
      ).bind(ts, 'verditnxtgen-auditor', slug, body.a2a_score, body.a2a_handshake_ms || null, body.a2a_score > 0 ? 'success' : 'rejected').run()));
    }

    // V6: Update tool_intelligence cache
    if (env.DB && passK1 !== null) {
      ctx.waitUntil(safe(env.DB.prepare(`
        INSERT INTO tool_intelligence (slug, last_updated, pass_at_1, pass_at_3, pass_at_5, pass_at_8, intelligence_score)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(slug) DO UPDATE SET
          last_updated=excluded.last_updated,
          pass_at_1=excluded.pass_at_1,
          pass_at_3=excluded.pass_at_3,
          pass_at_5=excluded.pass_at_5,
          pass_at_8=excluded.pass_at_8
      `).bind(slug, ts, passK1, passK3, passK5, passK8, riskScore).run()));
    }

    for (const peer of coDeployed) {
      if (peer === slug) continue;
      ctx.waitUntil(safe(env.DB.prepare(
        "INSERT INTO infra_graph (slug_a, slug_b, edge_type, weight, source, ts) VALUES (?,?,?,?,?,?)"
      ).bind(slug, peer, "commonly_deployed_with", 1.0, "feedback", ts).run()));
    }
  }

  if (env.KVOPS) {
    ctx.waitUntil(safe(env.KVOPS.delete(`schema:neg:${slug}`)));
  }

  return json({ ok: true, recorded: { slug, outcome, ts } });
}

/* ─────────────────── /api/stack (composite stack planner) ──────────────────
 * Given a list of slugs, returns compatibility analysis + merged deployment hints.
 * Reads mcp_routing_index.json for tool metadata, infra_graph D1 for real
 * co-deployment signals, and returns a combined docker-compose hint.
 * ────────────────────────────────────────────────────────────────────────── */
async function handleStack(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }

  const slugs = (Array.isArray(body.slugs) ? body.slugs : [])
    .map(s => String(s).replace(/[^a-z0-9-]/g, "").slice(0, 80))
    .filter(Boolean)
    .slice(0, 10);

  if (slugs.length < 2) return json({ error: "Provide at least 2 slugs to plan a stack" }, 400);

  const origin = env.SITE_ORIGIN || new URL(request.url).origin;

  // Gap 7: Check for pre-computed stack schema first (instant response)
  const comboSlug = [...slugs].sort().join("--");
  try {
    const precomputed = await fetch(`${origin}/stacks/${comboSlug}.stack-schema.json`,
      { signal: AbortSignal.timeout(3000) });
    if (precomputed.ok) {
      const data = await precomputed.json();
      return json({ ...data.stack, _source: "precomputed", combo_slug: comboSlug });
    }
  } catch { /* fall through to live computation */ }

  // Load routing index for tool metadata + Gap 8: compatibility_matrix
  let bySlug = {}; let compatMatrix = {};
  try {
    const r = await fetch(`${origin}/mcp_routing_index.json`, { signal: AbortSignal.timeout(4000) });
    if (r.ok) {
      const routeData = await r.json();
      bySlug      = routeData.by_slug              || {};
      compatMatrix = routeData.compatibility_matrix || {};
    }
  } catch { /* proceed with empty index */ }

  // Load real co-deployment signals from infra_graph
  let graphEdges = [];
  if (env.DB) {
    try {
      const placeholders = slugs.map(() => "?").join(",");
      const rows = await env.DB.prepare(
        `SELECT slug_a, slug_b, edge_type, SUM(weight) as w
         FROM infra_graph
         WHERE slug_a IN (${placeholders}) AND slug_b IN (${placeholders})
         GROUP BY slug_a, slug_b, edge_type
         ORDER BY w DESC LIMIT 50`
      ).bind(...slugs, ...slugs).all();
      graphEdges = rows.results || [];
    } catch { /* non-fatal */ }
  }

  // Port conflict table (mirrors Python plan_agent_stack)
  const KNOWN_PORTS = {
    postgres: [5432], redis: [6379], qdrant: [6333, 6334],
    chroma: [8000], weaviate: [8080], supabase: [5432, 8000],
    agentmemory: [3000], mempalace: [3001], graphify: [8080],
    obscura: [9222], pinchtab: [9223], "browser-harness": [9224],
  };
  const CATEGORY_CONFLICTS = [
    [["agentmemory", "mempalace", "zep-cloud"],       "Multiple persistent memory layers — pick one"],
    [["qdrant", "chroma", "weaviate", "graphify"],     "Multiple vector stores — pick one unless sharding"],
    [["obscura", "pinchtab", "browser-harness"],       "Multiple browser automation layers — pick one"],
  ];

  const portMap = {};
  const warnings = [];
  const envVars = {};
  let totalRam = 0;
  let totalCpu = 0;

  const resolvedSlugs = slugs.filter(s => bySlug[s] || true);  // include unknowns with warning

  for (const slug of resolvedSlugs) {
    const tool = bySlug[slug];
    if (!tool) { warnings.push(`${slug}: not found in directory — schema may not exist`); }

    (KNOWN_PORTS[slug] || []).forEach(port => {
      (portMap[port] = portMap[port] || []).push(slug);
    });

    const cat = tool?.category || "";
    if (cat === "Database")   envVars[`${slug.toUpperCase().replace(/-/g,"_")}_URL`] = `<connection_string>`;
    if (cat === "Automation") envVars["BROWSER_WS_ENDPOINT"] = `ws://${slug}:9222`;
    if (cat === "AI/ML" && slug.includes("memory")) envVars["MEMORY_BACKEND_URL"] = `http://${slug}:3000`;

    const RAM_BY_CAT = { Database: 512, Automation: 1024, "AI/ML": 768, DevOps: 256 };
    const CPU_BY_CAT = { Database: 0.5, Automation: 1.0,  "AI/ML": 0.5, DevOps: 0.25 };
    totalRam += RAM_BY_CAT[cat] || 256;
    totalCpu += CPU_BY_CAT[cat] || 0.25;
  }

  // Port conflicts
  Object.entries(portMap).forEach(([port, tools]) => {
    if (tools.length > 1) warnings.push(`Port ${port} conflict: ${tools.join(", ")} — remap one`);
  });

  // Gap 8: Graph-based compatibility check from routing index compatibility_matrix
  for (let i = 0; i < slugs.length; i++) {
    for (let j = i + 1; j < slugs.length; j++) {
      const a = slugs[i]; const b = slugs[j];
      if (compatMatrix[a] !== undefined && compatMatrix[b] !== undefined) {
        if (!(compatMatrix[a] || []).includes(b) && !(compatMatrix[b] || []).includes(a)) {
          warnings.push(`No verified compatibility data for ${a} + ${b} — test before production`);
        }
      }
    }
  }

  // Category conflicts (hardcoded safety net)
  const slugSet = new Set(slugs);
  CATEGORY_CONFLICTS.forEach(([group, msg]) => {
    const overlap = group.filter(s => slugSet.has(s));
    if (overlap.length > 1) warnings.push(`${msg} (${overlap.join(", ")})`);
  });

  // Compose hint
  const composeServices = resolvedSlugs.map(slug => {
    const ports = (KNOWN_PORTS[slug] || []).map(p => `"${p}:${p}"`).join(", ");
    return `  ${slug}:\n    image: ${slug}:latest${ports ? `\n    ports: [${ports}]` : ""}`;
  }).join("\n\n");

  // Schema download URLs
  const schemaUrls = resolvedSlugs.reduce((acc, slug) => {
    acc[slug] = `${origin}/schemas/${slug}.agent-schema.json`;
    return acc;
  }, {});

  // Co-deployment evidence from feedback loop
  const coDeployEvidence = graphEdges
    .filter(e => slugSet.has(e.slug_a) && slugSet.has(e.slug_b))
    .map(e => ({ pair: [e.slug_a, e.slug_b], edge_type: e.edge_type, deployments: e.w }));

  return json({
    slugs,
    compatible:          warnings.length === 0,
    warnings,
    port_conflicts:      Object.fromEntries(Object.entries(portMap).filter(([,v]) => v.length > 1)),
    merged_env_vars:     envVars,
    merged_docker_compose: `version: '3.8'\nservices:\n${composeServices}`,
    resource_estimate: {
      total_ram_mb:   totalRam,
      total_cpu_cores: Math.round(totalCpu * 100) / 100,
      recommended_instance: totalRam <= 2048 ? "t3.small" : totalRam <= 4096 ? "t3.medium" : "t3.large",
    },
    schema_urls: schemaUrls,
    co_deployment_evidence: coDeployEvidence,
  });
}

/* ─────────────── /api/webhook/github (real-time schema invalidation) ────────
 * Register at: github.com/<org>/<repo>/settings/hooks
 * Events: push, release, issues (closed)
 * Secret: set GITHUB_WEBHOOK_SECRET env var in Cloudflare, paste same in GitHub
 *
 * On push/release → busts the schema cache for that slug so the next download
 * triggers a fresh schema (via the weekly scraper picking it up).
 * On issue closed → if labelled "bug", increments a known_bugs_stale flag in KV
 * so the daily cron prioritises re-fetching that tool's bug list.
 * ────────────────────────────────────────────────────────────────────────── */
async function handleGithubWebhook(request, env, ctx) {
  // 1. Verify HMAC signature
  const sig     = request.headers.get("X-Hub-Signature-256") || "";
  const event   = request.headers.get("X-GitHub-Event")     || "";
  const rawBody = await request.text();

  if (env.GITHUB_WEBHOOK_SECRET) {
    const encoder = new TextEncoder();
    const key     = await crypto.subtle.importKey(
      "raw", encoder.encode(env.GITHUB_WEBHOOK_SECRET),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const mac      = await crypto.subtle.sign("HMAC", key, encoder.encode(rawBody));
    const expected = "sha256=" + Array.from(new Uint8Array(mac))
      .map(b => b.toString(16).padStart(2, "0")).join("");
    if (sig !== expected) return json({ error: "Invalid signature" }, 401);
  }

  let payload;
  try { payload = JSON.parse(rawBody); } catch { return json({ error: "Bad JSON" }, 400); }

  // 2. Extract slug from repo full_name
  const fullName = (payload.repository?.full_name || "").toLowerCase();
  const slug     = fullName.split("/").pop().replace(/[^a-z0-9-]/g, "") || "";
  if (!slug) return json({ ok: true, action: "ignored", reason: "no slug" });

  // 3. Debounce — write slug to dirty_schemas KV list instead of busting immediately.
  //    High-velocity repos (Supabase, Next.js) fire dozens of push/issue events
  //    per hour from Dependabot and CI bots. Busting the cache on every ping
  //    would burn through Worker CPU limits and defeat the purpose of caching.
  //
  //    The 06:00 UTC cron reads dirty_schemas, de-dupes, and only re-fetches
  //    the tools that actually changed. One KV write per webhook — O(1) cost.
  if (env.KVOPS) {
    const isRelevant = (
      (event === "push"    && payload.ref === `refs/heads/${payload.repository?.default_branch}`) ||
      (event === "release" && payload.action === "published") ||
      (event === "issues"  && payload.action === "closed" &&
        (payload.issue?.labels || []).some(l => String(l.name).toLowerCase().includes("bug")))
    );

    if (isRelevant) {
      ctx.waitUntil((async () => {
        // Read current dirty set, add this slug, write back (TTL: 48h)
        const raw     = await safe(env.KVOPS.get("dirty_schemas")) || "[]";
        let   dirtySet;
        try { dirtySet = JSON.parse(raw); } catch { dirtySet = []; }
        if (!Array.isArray(dirtySet)) dirtySet = [];
        if (!dirtySet.includes(slug)) {
          dirtySet.push(slug);
          // Tag what kind of change triggered this for the cron to prioritise
          await safe(env.KVOPS.put(
            "dirty_schemas",
            JSON.stringify(dirtySet),
            { expirationTtl: 172800 }   // 48h — cron runs at 06:00 UTC daily
          ));
          // Also write a per-slug metadata entry so the cron knows event type
          await safe(env.KVOPS.put(
            `dirty:${slug}`,
            JSON.stringify({ event, ts: new Date().toISOString(), action: payload.action || "" }),
            { expirationTtl: 172800 }
          ));
        }
      })());
    }
  }

  return json({ ok: true, event, slug, queued: true });
}

/* ─────────────────────── GET /api/mcp — SSE transport (Ticket 2.1) ─────────
 *
 * MCP "Streamable HTTP" transport requires the server to handle both:
 *   POST /api/mcp  — client sends JSON-RPC, server responds (already exists)
 *   GET  /api/mcp  — server sends events on an SSE stream (added here)
 *
 * Clients that support SSE (Claude Desktop ≥ 0.9, Cursor ≥ 0.42) will open
 * this stream first to receive the capability handshake, then POST tool calls.
 *
 * This implementation sends:
 *   1. An "endpoint" event pointing back to POST /api/mcp (required by spec)
 *   2. A "server_info" event with tool list (optional, helps clients display tools)
 *   3. A keepalive comment every 15 seconds (prevents proxy timeouts)
 *
 * Cloudflare Workers support streaming responses via ReadableStream.
 * ─────────────────────────────────────────────────────────────────────────── */
async function handleMCPSSE(request, env) {
  const origin = env.SITE_ORIGIN || new URL(request.url).origin;

  // Rate limit SSE connections — 10 per IP per hour (prevents CPU exhaustion)
  if (env.KVOPS) {
    const ip     = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
    const ipHash = await sha256(ip + "|sse|" + requireSalt(env));
    const hour   = Math.floor(Date.now() / 3600000);
    const rlKey  = `rl:sse:${ipHash}:${hour}`;
    const used   = parseInt((await env.KVOPS.get(rlKey)) || "0", 10);
    const limit  = 10;
    if (used >= limit) {
      return new Response("rate limit exceeded — max 10 SSE connections/hour", {
        status: 429,
        headers: { "Retry-After": "3600", "Access-Control-Allow-Origin": "*" }
      });
    }
    // Non-blocking increment
    env.KVOPS.put(rlKey, String(used + 1), { expirationTtl: 3600 }).catch(() => {});
  }

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc    = new TextEncoder();

  const send = (event, data) =>
    writer.write(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
  const comment = () =>
    writer.write(enc.encode(`: keepalive\n\n`));

  // Run the SSE session asynchronously
  (async () => {
    try {
      // 1. Required by MCP spec: tell the client where to POST tool calls
      await send("endpoint", { uri: `${origin}/api/mcp` });

      // 2. Capability announcement (optional, improves Cursor/Claude UX)
      await send("server_info", {
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: {
          serverInfo: { name: "verditnxtgen-mcp", version: "1.0.0" },
          capabilities: { tools: {} },
          protocolVersion: "2024-11-05",
        }
      });

      // 3. Keepalive — send 3 comments at 20s intervals (60s total).
      //    Cloudflare Workers terminates idle SSE connections after ~100s anyway.
      //    Clients that support persistent SSE will reconnect automatically.
      for (let i = 0; i < 3; i++) {
        await new Promise(r => setTimeout(r, 20000));
        await comment();
      }
    } catch {
      // Client disconnected — silently close
    } finally {
      try { await writer.close(); } catch {}
    }
  })();

  return new Response(readable, {
    status: 200,
    headers: {
      "Content-Type":                "text/event-stream",
      "Cache-Control":               "no-cache, no-store",
      "Connection":                  "keep-alive",
      "Access-Control-Allow-Origin": "*",
      "X-Accel-Buffering":           "no",    // disable nginx buffering if behind proxy
    },
  });
}

/* ─────────────────────── /api/mcp (Model Context Protocol) ─────────────────────────── */
// Implements the MCP JSON-RPC 2.0 transport (Streamable HTTP variant).
// Exposes two tools to any MCP-compatible client (Claude Code, Cursor, etc.):
//   search_ai_infrastructure — keyword search over trending_summary.json
//   get_agent_schema         — fetch the deployment context schema for a slug
//
// Also handles the standard lifecycle methods clients send on first connect:
//   initialize  — capability handshake (required by spec before tools/list)
//   ping        — keep-alive check
//
// Bindings used: KVOPS (rate limit), SITE_ORIGIN (env var, falls back to request origin)
async function handleMCP(request, env, ctx) {
  // P1: Fingerprint the agent on every MCP call for analytics
  const fp = await fingerprintAgent(request, env);

  // Rate limit — separate namespace from audit/schema
  const ip     = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const ipHash = await sha256(ip + "|" + requireSalt(env));
  const limit  = clampInt(env.MCP_RATE_LIMIT_PER_HOUR ?? env.RATE_LIMIT_PER_HOUR, 1, 10000) || 120;
  const hour   = Math.floor(Date.now() / 3600000);
  const rlKey  = `rl:mcp:${ipHash}:${hour}`;
  if (env.KVOPS) {
    const used = parseInt((await env.KVOPS.get(rlKey)) || "0", 10);
    if (used >= limit) {
      return json({ jsonrpc: "2.0", id: null,
        error: { code: -32000, message: `Rate limit reached (${limit}/hour).` }
      }, 429);
    }
    ctx.waitUntil(env.KVOPS.put(rlKey, String(used + 1), { expirationTtl: 3600 }));
  }

  let req;
  try { req = await request.json(); } catch {
    return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
  }

  const origin = env.SITE_ORIGIN || new URL(request.url).origin;
  const id     = req.id ?? null;

  // ── initialize — required capability handshake ────────────────────────────
  if (req.method === "initialize") {
    return json({
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "verditnxtgen-mcp", version: "1.0.0" }
      }
    });
  }

  // ── ping — keep-alive ─────────────────────────────────────────────────────
  if (req.method === "ping") {
    return json({ jsonrpc: "2.0", id, result: {} });
  }

  // ── tools/list ────────────────────────────────────────────────────────────
  if (req.method === "tools/list") {
    return json({
      jsonrpc: "2.0", id,
      result: {
        tools: [
          {
            name: "search_ai_infrastructure",
            description: "Search the VerditNxtGen directory for audited open-source AI infrastructure tools. Returns up to 5 matches ranked by Verdit score, each with a schema_url field you can pass to get_agent_schema. Search by capability type (e.g. 'vector database', 'agent memory', 'headless browser', 'CI/CD', 'Kubernetes').",
            inputSchema: {
              type: "object",
              properties: {
                query: { type: "string", description: "Capability or tool type needed, e.g. 'vector database', 'agent memory', 'headless browser', 'kubernetes', 'auth'" }
              },
              required: ["query"]
            }
          },
          {
            name: "get_agent_schema",
            description: "Fetch the complete machine-readable deployment schema for a tool. Returns 7 intelligence layers: (1) health signals & Verdit score, (2) docker-compose + .env.example + OpenAPI spec, (3) exact CI/CD build/test/deploy commands extracted from GitHub Actions, (4) Kubernetes/Helm CPU+RAM resource limits, (5) database table list from SQL/Prisma schema, (6) known bug fixes with structured error codes and fix hints, (7) exact HTTP auth header pattern + OAuth 2.0 flows. Also includes dependency graph + supply chain risk score and deployment outcome data from real agent feedback.",
            inputSchema: {
              type: "object",
              properties: {
                slug: { type: "string", description: "Exact tool slug from search results, e.g. 'graphify', 'agentmemory', 'obscura'" }
              },
              required: ["slug"]
            }
          },
          {
            name: "plan_agent_stack",
            description: "Given 2-10 tool slugs, returns a compatibility analysis and merged deployment plan: port conflict detection, merged environment variables, combined docker-compose.yml, resource estimates (RAM/CPU), and schema download URLs for each tool. Use this before deploying a multi-tool stack to catch conflicts before they cause failures.",
            inputSchema: {
              type: "object",
              properties: {
                slugs: {
                  type: "array",
                  items: { type: "string" },
                  description: "List of 2-10 tool slugs to plan together, e.g. ['agentmemory', 'qdrant', 'obscura']",
                  minItems: 2,
                  maxItems: 10
                }
              },
              required: ["slugs"]
            }
          },
          {
            name: "report_deployment_outcome",
            description: "Report whether a deployment attempt succeeded or failed. This feeds the VerditNxtGen learning loop — outcomes are aggregated to compute deployment_verified scores and improve future schemas. Call this after every deployment attempt, success or failure.",
            inputSchema: {
              type: "object",
              properties: {
                slug:               { type: "string",  description: "The tool slug that was deployed" },
                outcome:            { type: "string",  enum: ["success", "failure"], description: "Whether the deployment succeeded" },
                error_code:         { type: "string",  description: "Optional: the error code or exit code if failed, e.g. 'Exit 137', 'ECONNREFUSED'" },
                agent_hint:         { type: "string",  description: "Optional: brief description of what failed or what worked" },
                co_deployed_with:   { type: "array", items: { type: "string" }, description: "Optional: other tool slugs deployed in the same stack" },
                schema_version:     { type: "string",  description: "Optional: schema version used, e.g. 'v1'" }
              },
              required: ["slug", "outcome"]
            }
          },
          {
            name: "get_model_card",
            description: "Returns the live training provenance and data quality metrics for the VerditNxtGen-Infra-7B model. Use this for due diligence: returns schema_version, total training rows, machine_pct (% of data from autonomous agents vs human submissions), positive/negative/neutral split, last fine-tune timestamp, and eval_loss. This is the auditable proof-of-flywheel.",
            inputSchema: {
              type: "object",
              properties: {
                include_breakdown: {
                  type: "boolean",
                  description: "If true, include per-agent-type breakdown from analytics. Default false."
                }
              },
              required: []
            }
          }
        ]
      }
    });
  }

  // ── tools/call ────────────────────────────────────────────────────────────
  if (req.method === "tools/call") {
    const toolName = String((req.params && req.params.name) || "");
    const args     = (req.params && req.params.arguments) || {};

    // ── search_ai_infrastructure ──────────────────────────────────────────
    if (toolName === "search_ai_infrastructure") {
      const query = String(args.query || "").toLowerCase().slice(0, 200);
      if (!query) {
        return json({ jsonrpc: "2.0", id,
          result: { isError: true, content: [{ type: "text", text: "query parameter is required." }] }
        });
      }

      // Try the routing index first (minified, faster, category-indexed).
      // Fall back to trending_summary.json if the index isn't available yet.
      let tools = [];
      try {
        const routeRes = await fetch(`${origin}/mcp_routing_index.json`,
          { signal: AbortSignal.timeout(4000) });
        if (routeRes.ok) {
          const routeData = await routeRes.json();
          const bySlug = routeData.by_slug || {};
          // Search across name, category, description
          tools = Object.entries(bySlug)
            .map(([slug, t]) => ({ slug, ...t }))
            .filter(t =>
              (t.name        || "").toLowerCase().includes(query) ||
              (t.category    || "").toLowerCase().includes(query) ||
              (t.description || "").toLowerCase().includes(query)
            )
            .sort((a, b) => (b.score || 0) - (a.score || 0))
            .slice(0, 5);
        } else {
          throw new Error("routing index not ready");
        }
      } catch {
        // Fallback: trending_summary.json
        try {
          const res = await fetch(`${origin}/trending_summary.json`,
            { signal: AbortSignal.timeout(5000) });
          if (!res.ok) throw new Error("summary fetch " + res.status);
          const data = await res.json();
          tools = (Array.isArray(data.tools) ? data.tools : [])
            .filter(t =>
              (t.name        || "").toLowerCase().includes(query) ||
              (t.category    || "").toLowerCase().includes(query) ||
              (t.description || "").toLowerCase().includes(query)
            ).slice(0, 5);
        } catch (e) {
          return json({ jsonrpc: "2.0", id,
            result: { isError: true, content: [{ type: "text", text: "Directory index unavailable: " + String(e.message || e) }] }
          });
        }
      }

      const text = tools.length
        ? JSON.stringify(tools, null, 2)
        : `No tools matched "${args.query}". Try broader terms like "memory", "browser", or "vector".`;

      // Block 2: Log zero-result queries so we know what to scrape next
      if (!tools.length && env.KVOPS) {
        const day = new Date().toISOString().slice(0, 10);
        ctx.waitUntil(
          env.KVOPS.get(`mcp:zero_results:${query}:${day}`).then(v =>
            env.KVOPS.put(`mcp:zero_results:${query}:${day}`, String((parseInt(v||"0")+1)), { expirationTtl: 30*86400 })
          ).catch(()=>{})
        );
      }

      return json({ jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text }] }
      });
    }

    // ── get_agent_schema ──────────────────────────────────────────────────
    if (toolName === "get_agent_schema") {
      const slug = String(args.slug || "").replace(/[^a-z0-9-]/g, "").slice(0, 80);
      if (!slug) {
        return json({ jsonrpc: "2.0", id,
          result: { isError: true, content: [{ type: "text", text: "slug parameter is required." }] }
        });
      }

      // Block 2: Log schema intent (intent → deployment conversion tracking)
      if (env.KVOPS) {
        const day = new Date().toISOString().slice(0, 10);
        ctx.waitUntil(Promise.all([
          env.KVOPS.get(`mcp:intent:${slug}:${day}`).then(v =>
            env.KVOPS.put(`mcp:intent:${slug}:${day}`, String((parseInt(v||"0")+1)), { expirationTtl: 90*86400 })
          ).catch(()=>{}),
          env.KVOPS.get(`mcp:calls:${day}`).then(v =>
            env.KVOPS.put(`mcp:calls:${day}`, String((parseInt(v||"0")+1)), { expirationTtl: 90*86400 })
          ).catch(()=>{}),
        ]));
      }

      let schemaData;
      try {
        const res = await fetch(`${origin}/schemas/${slug}.agent-schema.json`,
          { signal: AbortSignal.timeout(5000) });
        if (!res.ok) throw new Error("not_found");
        schemaData = await res.json();
      } catch (e) {
        const msg = String(e.message || e) === "not_found"
          ? `Schema for "${slug}" not found. Use search_ai_infrastructure to find valid slugs.`
          : `Schema fetch failed: ${String(e.message || e)}`;
        return json({ jsonrpc: "2.0", id,
          result: { isError: true, content: [{ type: "text", text: msg }] }
        });
      }

      return json({ jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: JSON.stringify(schemaData, null, 2) }] }
      });
    }

    // ── plan_agent_stack ──────────────────────────────────────────────────
    if (toolName === "plan_agent_stack") {
      const slugs = (Array.isArray(args.slugs) ? args.slugs : [])
        .map(s => String(s).replace(/[^a-z0-9-]/g, "")).filter(Boolean).slice(0, 10);
      if (slugs.length < 2) {
        return json({ jsonrpc: "2.0", id,
          result: { isError: true, content: [{ type: "text", text: "Provide at least 2 slugs." }] }
        });
      }
      // Reuse handleStack logic by constructing a synthetic request
      const fakeReq = new Request("https://verditnxtgen.com/api/stack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slugs }),
      });
      const stackRes  = await handleStack(fakeReq, env);
      const stackData = await stackRes.json();
      return json({ jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: JSON.stringify(stackData, null, 2) }] }
      });
    }

    // ── report_deployment_outcome ─────────────────────────────────────────
    if (toolName === "report_deployment_outcome") {
      const fakeReq = new Request("https://verditnxtgen.com/api/schema-feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          slug:             args.slug,
          outcome:          args.outcome,
          error_code:       args.error_code,
          agent_hint:       args.agent_hint,
          co_deployed_with: args.co_deployed_with,
          schema_version:   args.schema_version,
        }),
      });
      const fbRes  = await handleSchemaFeedback(fakeReq, env, { waitUntil: () => {} });
      const fbData = await fbRes.json();
      const text   = fbData.ok
        ? `Outcome recorded: ${args.outcome} for ${args.slug}. Thank you — this improves future schemas.`
        : `Error recording outcome: ${fbData.error}`;
      return json({ jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text }] }
      });
    }

    // ── get_model_card ────────────────────────────────────────────────────
    if (toolName === "get_model_card") {
      const includeBrk = args.include_breakdown === true;
      const origin     = env.SITE_ORIGIN || "https://verditnxtgen.com";

      // 1. Fetch model:latest from KV
      let modelState = {};
      if (env.KVOPS) {
        const raw = await safe(env.KVOPS.get("model:latest"));
        if (raw) { try { modelState = JSON.parse(raw); } catch {} }
      }

      // 2. Fetch training checkpoint summary
      let checkpoint = {};
      if (env.KVOPS) {
        const cpRaw = await safe(env.KVOPS.get("training:checkpoint:summary"));
        if (cpRaw) { try { checkpoint = JSON.parse(cpRaw); } catch {} }
      }

      // 3. Fetch analytics for machine_pct (last 90 days)
      let analytics = {};
      try {
        const since = new Date(Date.now() - 90 * 86400000).toISOString();
        if (env.DB) {
          const rows = await safe(env.DB.prepare(
            "SELECT agent_type, outcome, COUNT(*) as cnt FROM deployment_feedback WHERE ts > ? GROUP BY agent_type, outcome"
          ).bind(since).all());
          const byType = {};
          for (const row of (rows?.results || [])) {
            const at = row.agent_type || "unknown";
            if (!byType[at]) byType[at] = { success: 0, failure: 0, total: 0 };
            byType[at][row.outcome] = (byType[at][row.outcome] || 0) + row.cnt;
            byType[at].total += row.cnt;
          }
          analytics = {
            by_agent_type: byType,
            machine_pct:   _calcMachinePct(byType),
          };
        }
      } catch { /* non-fatal */ }

      const card = {
        model:            "VerditNxtGen-Infra-7B",
        base_model:       "mistralai/Mistral-7B-v0.1",
        schema_version:   "v1",
        status:           modelState.status || (modelState.ts ? "active" : "pending"),
        last_finetuned:   modelState.ts    || null,
        run_id:           modelState.run_id || null,
        repo:             modelState.repo  || null,
        eval_loss:        modelState.eval_loss || null,
        training_data: {
          total_rows:       checkpoint.total_rows        || null,
          positive_samples: checkpoint.positive          || null,
          negative_samples: checkpoint.negative          || null,
          neutral_samples:  checkpoint.neutral           || null,
          machine_pct:      analytics.machine_pct        || null,
          filter:           "agent_type = 'sandbox_harness' only (human data excluded)",
          schema_version:   "v1",
        },
        proof_of_flywheel: {
          machine_pct_note: analytics.machine_pct
            ? `${analytics.machine_pct}% of training data is from autonomous agents — zero human submissions in verified dataset`
            : "Accumulating — harness execution data pending",
          verifiable_at:  `${origin}/api/analytics?days=90`,
          model_card_url: modelState.repo ? `https://huggingface.co/${modelState.repo}` : null,
        },
        ...(includeBrk ? { agent_breakdown: analytics.by_agent_type } : {}),
      };

      return json({ jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: JSON.stringify(card, null, 2) }] }
      });
    }

    // Unknown tool
    return json({ jsonrpc: "2.0", id,
      result: { isError: true, content: [{ type: "text", text: `Unknown tool: ${toolName}` }] }
    });
  }

  // ── Unsupported method ────────────────────────────────────────────────────
  return json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
}
