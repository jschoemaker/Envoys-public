import type { FastifyInstance } from 'fastify'
import { timingSafeEqual, createHash } from 'crypto'
import { db } from '../db.js'
import type { Account } from '../db.js'
import { TIER_LIMITS } from '../limits.js'

const VALID_TIERS = new Set(Object.keys(TIER_LIMITS))

// Bucket a User-Agent string into a coarse client class. Order matters —
// LLM/search crawler patterns are matched before generic browser patterns
// because branded crawlers often include a Chrome/Safari token at the end.
function classifyUserAgent(ua: string | null): string {
  if (!ua) return 'no_ua'
  const u = ua.toLowerCase()
  if (/xai-searchbot|coherebot|claudebot|gptbot|perplexitybot|anthropic-ai|chatgpt-user|oai-searchbot|youbot|meta-externalagent|meta-externalfetcher/.test(u)) return 'crawler_llm'
  if (/googlebot|bingbot|duckduckbot|baiduspider|yandexbot|sogou|seznambot|applebot/.test(u)) return 'crawler_search'
  if (/facebookexternalhit|twitterbot|slackbot|linkedinbot|discordbot|telegrambot|whatsapp/.test(u)) return 'crawler_social'
  if (/^curl\//.test(u)) return 'cli_curl'
  if (/^wget\//.test(u)) return 'cli_wget'
  if (/python-requests|python-urllib|httpx|aiohttp/.test(u)) return 'cli_python'
  if (/postmanruntime|insomnia/.test(u)) return 'cli_api_tool'
  if (/node-fetch|axios|got\/|undici/.test(u)) return 'cli_node'
  if (/edg\/|chrome\/|firefox\/|safari\/|opera\//.test(u)) return 'browser'
  return 'unknown'
}

function requireAdminKey(req: any, reply: any, done: Function) {
  const adminKey = process.env.ADMIN_KEY
  if (!adminKey) return reply.code(503).send({ error: 'Admin endpoint not configured' })

  const auth = req.headers.authorization
  const provided = auth?.startsWith('Bearer ') ? auth.slice(7) : ''

  // Hash both sides to a fixed-length digest before comparing.
  // This prevents the length short-circuit from leaking the expected key length.
  const hash = (s: string) => Buffer.from(createHash('sha256').update(s).digest())
  const match = timingSafeEqual(hash(provided), hash(adminKey))

  if (!match) return reply.code(401).send({ error: 'Invalid admin key' })
  done()
}

export async function adminRoutes(app: FastifyInstance) {
  // Upgrade or downgrade an account's tier.
  // Usage: PATCH /admin/accounts/:id/tier  { "tier": "pro" }
  // Auth:  Authorization: Bearer <ADMIN_KEY>
  app.patch('/admin/accounts/:id/tier', { preHandler: requireAdminKey }, async (req, reply) => {
    const { id } = req.params as { id: string }
    const { tier } = req.body as { tier?: string }

    if (!tier || !VALID_TIERS.has(tier)) {
      return reply.code(400).send({
        error: `Invalid tier. Must be one of: ${[...VALID_TIERS].join(', ')}`,
      })
    }

    const account = db.prepare('SELECT * FROM accounts WHERE id = ?').get(id) as Account | undefined
    if (!account) return reply.code(404).send({ error: 'Account not found' })

    db.prepare('UPDATE accounts SET tier = ? WHERE id = ?').run(tier, id)

    return {
      id: account.id,
      handle: account.handle,
      email: account.email,
      tier,
    }
  })

  // Usage stats — resolution traffic, registry counts, growth, and developer funnel.
  // Optional ?days=N (default 7, max 365) controls the rolling window for in-window metrics.
  app.get('/admin/stats', { preHandler: requireAdminKey }, async (req, reply) => {
    const { days: daysRaw } = req.query as { days?: string }
    const days = Math.min(365, Math.max(1, parseInt(daysRaw ?? '7', 10) || 7))

    const now = Date.now()
    const windowStart = now - days * 24 * 60 * 60 * 1000
    const day = 24 * 60 * 60 * 1000

    // Resolve-kind events only — fetch_skill / fetch_spec are tracked separately
    // so they don't inflate "total resolves" or skew the error rate.
    const RESOLVE = "kind IN ('resolve_public_key', 'resolve_agent')"

    const total      = (db.prepare(`SELECT COUNT(*) AS n FROM usage_events WHERE status = 200 AND ${RESOLVE}`).get() as any).n
    const last24h    = (db.prepare(`SELECT COUNT(*) AS n FROM usage_events WHERE status = 200 AND ts >= ? AND ${RESOLVE}`).get(now - day) as any).n
    const lastWindow = (db.prepare(`SELECT COUNT(*) AS n FROM usage_events WHERE status = 200 AND ts >= ? AND ${RESOLVE}`).get(windowStart) as any).n

    const byKindRows = db.prepare(`
      SELECT kind, COUNT(*) AS n FROM usage_events WHERE status = 200 GROUP BY kind
    `).all() as Array<{ kind: string; n: number }>
    const byKind: Record<string, number> = {}
    for (const r of byKindRows) byKind[r.kind] = r.n

    // Status-bucketed breakdown — surfaces 4xx that the 200-only `byKind`
    // hides, so a non-zero error rate is always traceable to a visible row.
    const byKindBreakdown = db.prepare(`
      SELECT kind,
        SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS ok,
        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors,
        COUNT(*) AS total
      FROM usage_events
      GROUP BY kind
      ORDER BY total DESC
    `).all() as Array<{ kind: string; ok: number; errors: number; total: number }>

    const topAddresses = db.prepare(`
      SELECT address, COUNT(*) AS n FROM usage_events
      WHERE status = 200 AND ts >= ? AND address IS NOT NULL AND ${RESOLVE}
      GROUP BY address ORDER BY n DESC LIMIT 10
    `).all(windowStart) as Array<{ address: string; n: number }>

    const uniqueIps = (db.prepare(`
      SELECT COUNT(DISTINCT ip) AS n FROM usage_events
      WHERE ts >= ? AND ip IS NOT NULL AND ${RESOLVE}
    `).get(windowStart) as any).n

    const errorsWindow = (db.prepare(`
      SELECT COUNT(*) AS n FROM usage_events WHERE ts >= ? AND status >= 400 AND ${RESOLVE}
    `).get(windowStart) as any).n
    const totalEventsWindow = (db.prepare(`
      SELECT COUNT(*) AS n FROM usage_events WHERE ts >= ? AND ${RESOLVE}
    `).get(windowStart) as any).n

    // ── Registry ────────────────────────────────────────────────────────
    const accountsTotal   = (db.prepare("SELECT COUNT(*) AS n FROM accounts").get() as any).n
    const accountsByTier  = db.prepare("SELECT tier, COUNT(*) AS n FROM accounts GROUP BY tier ORDER BY n DESC").all() as Array<{ tier: string; n: number }>
    const agentsActive    = (db.prepare("SELECT COUNT(*) AS n FROM agents WHERE revoked = 0").get() as any).n
    const agentsRevoked   = (db.prepare("SELECT COUNT(*) AS n FROM agents WHERE revoked = 1").get() as any).n
    const cdTotal         = (db.prepare("SELECT COUNT(*) AS n FROM custom_domains").get() as any).n
    const cdVerified      = (db.prepare("SELECT COUNT(*) AS n FROM custom_domains WHERE verified = 1").get() as any).n

    // ── Growth (in window) ──────────────────────────────────────────────
    const newAccountsWindow = (db.prepare("SELECT COUNT(*) AS n FROM accounts WHERE created_at >= ?").get(windowStart) as any).n
    const newAgentsWindow   = (db.prepare("SELECT COUNT(*) AS n FROM agents   WHERE created_at >= ?").get(windowStart) as any).n

    // Agent activity ratio: distinct active agents resolved in window / total active agents.
    const activeResolved = (db.prepare(`
      SELECT COUNT(DISTINCT ue.address) AS n
      FROM usage_events ue
      WHERE ue.status = 200 AND ue.ts >= ? AND ue.address IS NOT NULL AND ${RESOLVE}
        AND EXISTS (SELECT 1 FROM agents ag WHERE ag.address = ue.address AND ag.revoked = 0)
    `).get(windowStart) as any).n
    const agentActivityRatio = agentsActive ? activeResolved / agentsActive : 0

    // ── Developer funnel ────────────────────────────────────────────────
    const skillWindow = (db.prepare("SELECT COUNT(*) AS n FROM usage_events WHERE kind = 'fetch_skill' AND ts >= ?").get(windowStart) as any).n
    const specWindow  = (db.prepare("SELECT COUNT(*) AS n FROM usage_events WHERE kind = 'fetch_spec'  AND ts >= ?").get(windowStart) as any).n
    const skillTotal  = (db.prepare("SELECT COUNT(*) AS n FROM usage_events WHERE kind = 'fetch_skill'").get() as any).n
    const specTotal   = (db.prepare("SELECT COUNT(*) AS n FROM usage_events WHERE kind = 'fetch_spec'").get() as any).n

    // ── Top accounts by resolve traffic in window ───────────────────────
    const topAccounts = db.prepare(`
      SELECT a.handle, a.tier, COUNT(*) AS n
      FROM usage_events ue
      JOIN agents   ag ON ag.address = ue.address
      JOIN accounts a  ON a.id = ag.account_id
      WHERE ue.status = 200 AND ue.ts >= ? AND ue.address IS NOT NULL AND ${RESOLVE}
      GROUP BY a.id ORDER BY n DESC LIMIT 10
    `).all(windowStart) as Array<{ handle: string; tier: string; n: number }>

    return {
      window_days: days,
      total_resolves:        total,
      resolves_last_24h:     last24h,
      resolves_last_window:  lastWindow,
      by_kind:               byKind,
      by_kind_breakdown:     byKindBreakdown,
      top_addresses:         topAddresses,
      unique_ips_window:     uniqueIps,
      error_rate_window:     totalEventsWindow ? errorsWindow / totalEventsWindow : 0,

      // registry
      accounts_total:        accountsTotal,
      accounts_by_tier:      accountsByTier,
      agents_active:         agentsActive,
      agents_revoked:        agentsRevoked,
      custom_domains_total:    cdTotal,
      custom_domains_verified: cdVerified,

      // growth
      new_accounts_window:   newAccountsWindow,
      new_agents_window:     newAgentsWindow,
      agent_activity_ratio:  agentActivityRatio,

      // developer funnel
      skill_fetches_window:  skillWindow,
      spec_fetches_window:   specWindow,
      skill_fetches_total:   skillTotal,
      spec_fetches_total:    specTotal,

      // top accounts
      top_accounts:          topAccounts,
    }
  })

  // Daily timeseries for charting — successful resolves per day over last N days.
  app.get('/admin/stats/timeseries', { preHandler: requireAdminKey }, async (req, reply) => {
    const { days: daysRaw } = req.query as { days?: string }
    const days = Math.min(365, Math.max(1, parseInt(daysRaw ?? '30', 10) || 30))

    const now = Date.now()
    const windowStart = now - days * 24 * 60 * 60 * 1000

    // Bucket on UTC day (ts in ms → day = floor(ts / 86_400_000)). Filtered to
    // resolve kinds so the chart reflects verifier traffic, not doc fetches.
    const rows = db.prepare(`
      SELECT (ts / 86400000) AS day, COUNT(*) AS n
      FROM usage_events
      WHERE status = 200 AND ts >= ?
        AND kind IN ('resolve_public_key', 'resolve_agent')
      GROUP BY day
      ORDER BY day ASC
    `).all(windowStart) as Array<{ day: number; n: number }>

    const series = rows.map((r) => ({
      date: new Date(r.day * 86400000).toISOString().slice(0, 10),
      count: r.n,
    }))
    return { days, series }
  })

  // Client-side traffic breakdown — top user-agents, top IPs, and bucketed
  // client classes (LLM crawler / search crawler / browser / CLI / unknown).
  // Useful for distinguishing legitimate indexing from scanner noise.
  app.get('/admin/stats/clients', { preHandler: requireAdminKey }, async (req, reply) => {
    const { days: daysRaw } = req.query as { days?: string }
    const days = Math.min(365, Math.max(1, parseInt(daysRaw ?? '7', 10) || 7))
    const windowStart = Date.now() - days * 24 * 60 * 60 * 1000

    const topUserAgents = db.prepare(`
      SELECT user_agent,
        COUNT(*) AS total,
        SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) AS ok,
        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors,
        MAX(ts) AS last_seen
      FROM usage_events
      WHERE ts >= ? AND user_agent IS NOT NULL
      GROUP BY user_agent
      ORDER BY total DESC
      LIMIT 20
    `).all(windowStart) as Array<{ user_agent: string; total: number; ok: number; errors: number; last_seen: number }>

    // Top IPs across ALL kinds (not just resolves) — the honest superset of
    // the existing unique_ips_window metric. Pairs each IP with its most
    // recent UA so the operator can attribute traffic without a second query.
    const topIps = db.prepare(`
      SELECT ue.ip,
        COUNT(*) AS total,
        MAX(ts) AS last_seen,
        (SELECT user_agent FROM usage_events WHERE ip = ue.ip AND user_agent IS NOT NULL ORDER BY ts DESC LIMIT 1) AS user_agent_sample
      FROM usage_events ue
      WHERE ts >= ? AND ip IS NOT NULL
      GROUP BY ue.ip
      ORDER BY total DESC
      LIMIT 20
    `).all(windowStart) as Array<{ ip: string; total: number; last_seen: number; user_agent_sample: string | null }>

    const totalUniqueIps = (db.prepare(`
      SELECT COUNT(DISTINCT ip) AS n FROM usage_events WHERE ts >= ? AND ip IS NOT NULL
    `).get(windowStart) as any).n

    // Aggregate by classifier. SQLite has no regex helper for this, so we pull
    // UAs and bucket in JS. Volume is bounded by event count in the window.
    const allUas = db.prepare(`
      SELECT user_agent FROM usage_events WHERE ts >= ?
    `).all(windowStart) as Array<{ user_agent: string | null }>

    const byClass: Record<string, number> = {}
    for (const r of allUas) {
      const cls = classifyUserAgent(r.user_agent)
      byClass[cls] = (byClass[cls] ?? 0) + 1
    }

    return {
      window_days: days,
      total_unique_ips_window: totalUniqueIps,
      top_user_agents: topUserAgents,
      top_ips: topIps,
      by_client_class: byClass,
    }
  })

  // Look up an account by handle or email — useful for finding the id before upgrading
  app.get('/admin/accounts/lookup', { preHandler: requireAdminKey }, async (req, reply) => {
    const { handle, email } = req.query as { handle?: string; email?: string }
    if (!handle && !email) return reply.code(400).send({ error: 'handle or email required' })

    const account = handle
      ? db.prepare('SELECT id, handle, email, tier, created_at FROM accounts WHERE handle = ?').get(handle)
      : db.prepare('SELECT id, handle, email, tier, created_at FROM accounts WHERE email = ?').get(email!)

    if (!account) return reply.code(404).send({ error: 'Account not found' })
    return account
  })
}
