import type { FastifyInstance } from 'fastify'
import { randomUUID, createPublicKey } from 'crypto'
import { db } from '../db.js'
import type { Agent } from '../db.js'
import { generateToken, hashToken } from '../crypto.js'
import { requireAccountKey, requireAgentKey } from '../middleware/auth.js'
import { getLimits } from '../limits.js'
import { recordUsage, recordAudit } from '../usage.js'
import { getVerifiedDomainForHandle, getVerifiedCustomDomain } from './accounts.js'

// Extract the handle portion of an envoys address — the segment between '@'
// and the service domain. Returns null if the address is on a custom domain
// or otherwise doesn't follow the standard format.
function handleFromAddress(address: string): string | null {
  const SERVICE_DOMAIN = process.env.SERVICE_DOMAIN ?? 'envoys.me'
  const at = address.indexOf('@')
  if (at < 0) return null
  const host = address.slice(at + 1)
  if (!host.endsWith('.' + SERVICE_DOMAIN)) return null
  return host.slice(0, host.length - SERVICE_DOMAIN.length - 1) || null
}

// Resolve the verification claim for an address. Handle-namespace addresses
// (name@<handle>.envoys.me) consult the handle attestation table; custom-domain
// addresses (name@example.com) consult the custom_domains table. The two paths
// are mutually exclusive — at most one of `verified_handle` / `verified_domain`
// is non-null in a resolver response.
function resolveVerification(address: string): {
  verified_handle: { domain: string; verified_at: number } | null
  verified_domain: { domain: string; verified_at: number } | null
} {
  const handle = handleFromAddress(address)
  if (handle) {
    return { verified_handle: getVerifiedDomainForHandle(handle), verified_domain: null }
  }
  const at = address.indexOf('@')
  const host = at >= 0 ? address.slice(at + 1) : ''
  return { verified_handle: null, verified_domain: host ? getVerifiedCustomDomain(host) : null }
}

const SERVICE_DOMAIN = process.env.SERVICE_DOMAIN ?? 'envoys.me'

export async function agentRoutes(app: FastifyInstance) {
  // Agent self-registers using the developer's account key.
  // The caller generates the Ed25519 keypair — only the public key is sent here.
  // The private key never leaves the caller's process.
  app.post('/agents/register', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!

    const { name, public_key, capabilities = [], domain } = req.body as {
      name?: string
      public_key?: string
      capabilities?: string[]
      domain?: string
    }
    if (!name) return reply.code(400).send({ error: 'name required' })
    if (!public_key) return reply.code(400).send({ error: 'public_key required (generate an Ed25519 keypair and send the public key)' })
    if (name.length > 64) return reply.code(400).send({ error: 'name must be 64 characters or fewer' })
    if (!Array.isArray(capabilities) || capabilities.length > 20) {
      return reply.code(400).send({ error: 'capabilities must be an array of at most 20 items' })
    }
    if (capabilities.some((c: any) => typeof c !== 'string' || c.length > 64)) {
      return reply.code(400).send({ error: 'each capability must be a string of at most 64 characters' })
    }
    if (domain && domain.length > 253) return reply.code(400).send({ error: 'domain must be 253 characters or fewer' })

    // Validate the submitted public key is a real Ed25519 key
    try {
      const key = createPublicKey(public_key)
      if (key.asymmetricKeyType !== 'ed25519') {
        return reply.code(400).send({ error: 'public_key must be an Ed25519 key' })
      }
    } catch {
      return reply.code(400).send({ error: 'public_key is not a valid PEM-encoded public key' })
    }

    // Enforce agent count limit for this tier
    const limits = getLimits(account.tier)
    if (limits.agents !== Infinity) {
      const { count } = db.prepare(`
        SELECT COUNT(*) as count FROM agents WHERE account_id = ? AND revoked = 0
      `).get(account.id) as { count: number }
      if (count >= limits.agents) {
        return reply.code(403).send({
          error: `Agent limit reached for ${account.tier} tier (max ${limits.agents}). Upgrade to add more agents.`,
        })
      }
    }

    const agentSlug = name.toLowerCase().replace(/[^a-z0-9-]/g, '-')

    let addressDomain = `${account.handle}.${SERVICE_DOMAIN}`
    if (domain) {
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain.toLowerCase())) {
        return reply.code(400).send({ error: 'Invalid domain format' })
      }
      const customDomain = db.prepare(`
        SELECT id FROM custom_domains
        WHERE domain = ? AND account_id = ? AND verified = 1
      `).get(domain.toLowerCase(), account.id)
      if (!customDomain) {
        return reply.code(403).send({ error: 'Domain not verified for this account. Complete DNS verification first.' })
      }
      addressDomain = domain.toLowerCase()
    }

    const address = `${agentSlug}@${addressDomain}`

    if (db.prepare('SELECT id FROM agents WHERE address = ?').get(address)) {
      return reply.code(409).send({ error: `Address "${address}" is already taken — try a different name` })
    }

    const id        = randomUUID()
    const agent_key = generateToken('agt')
    const now       = Date.now()

    db.prepare(`
      INSERT INTO agents (id, account_id, name, address, agent_key, public_key, capabilities, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, account.id, name, address, hashToken(agent_key), public_key, JSON.stringify(capabilities), now)

    db.prepare(`
      INSERT INTO public_key_history (agent_id, address, public_key, valid_from, valid_until, reason)
      VALUES (?, ?, ?, ?, NULL, 'register')
    `).run(id, address, public_key, now)

    recordAudit({ accountId: account.id, kind: 'agent.registered', detail: address, ip: req.ip ?? null })

    return reply.code(201).send({ id, address, agent_key, public_key })
  })

  // List all agents under the authenticated account.
  app.get('/agents', { preHandler: requireAccountKey }, async (req, reply) => {
    const agents = db.prepare(`
      SELECT id, name, address, public_key, capabilities, revoked, created_at
      FROM agents WHERE account_id = ?
    `).all(req.account!.id) as any[]

    return agents.map(a => ({ ...a, capabilities: JSON.parse(a.capabilities) }))
  })

  // Revoke an agent — its key stops working immediately. Revocation is final
  // and the address is permanently bound to this agent_id even after revocation;
  // it cannot be re-registered by anyone (including the original owner). This
  // is intentional — it preserves the integrity of any pinning that downstream
  // verifiers have done against the (address, public_key) pair.
  app.delete('/agents/:id', { preHandler: requireAccountKey }, async (req, reply) => {
    const { id } = req.params as { id: string }
    const agent = db
      .prepare('SELECT id, revoked FROM agents WHERE id = ? AND account_id = ?')
      .get(id, req.account!.id) as { id: string; revoked: number } | undefined

    if (!agent) return reply.code(404).send({ error: 'Agent not found' })
    if (agent.revoked) return { revoked: true }

    const now = Date.now()
    db.prepare('UPDATE agents SET revoked = 1 WHERE id = ?').run(id)
    // Close the currently-open key-history entry for this agent.
    db.prepare(`
      UPDATE public_key_history SET valid_until = ?
      WHERE agent_id = ? AND valid_until IS NULL
    `).run(now, id)

    // Resolve address for the audit detail before recording.
    const addr = db.prepare('SELECT address FROM agents WHERE id = ?').get(id) as { address: string } | undefined
    recordAudit({ accountId: req.account!.id, kind: 'agent.revoked', detail: addr?.address ?? id, ip: req.ip ?? null })

    return { revoked: true }
  })

  // Request a key rotation for an agent — sets a flag the agent picks up on next syncKeys().
  // The agent generates the new keypair client-side and confirms via POST /agent/rotate-keys.
  app.post('/agents/:id/rotate-keys', { preHandler: requireAccountKey }, async (req, reply) => {
    const { id } = req.params as { id: string }
    const agent = db
      .prepare('SELECT id FROM agents WHERE id = ? AND account_id = ?')
      .get(id, req.account!.id) as Agent | undefined

    if (!agent) return reply.code(404).send({ error: 'Agent not found' })

    db.prepare('UPDATE agents SET rotation_requested = 1 WHERE id = ?').run(id)
    const addr = db.prepare('SELECT address FROM agents WHERE id = ?').get(id) as { address: string } | undefined
    recordAudit({ accountId: req.account!.id, kind: 'agent.rotation_requested', detail: addr?.address ?? id, ip: req.ip ?? null })

    return {
      message: 'Rotation requested — agent will generate and submit new keys on next syncKeys() call',
    }
  })

  // Pull-based key sync — agent calls this on every startup.
  // Returns rotation_requested: true if the account holder has requested a rotation.
  // If true, generate a new keypair and call POST /agent/rotate-keys to confirm.
  app.get('/agent/keys', { preHandler: requireAgentKey }, async (req, reply) => {
    const agent = req.agent!
    return {
      rotation_requested: !!agent.rotation_requested,
      public_key: agent.public_key,
    }
  })

  // Agent confirms a rotation by submitting a newly generated public key.
  // The private key is generated client-side and never sent here.
  app.post('/agent/rotate-keys', { preHandler: requireAgentKey }, async (req, reply) => {
    const agent = req.agent!
    const { new_public_key } = req.body as { new_public_key?: string }

    if (!new_public_key) return reply.code(400).send({ error: 'new_public_key required' })

    try {
      const key = createPublicKey(new_public_key)
      if (key.asymmetricKeyType !== 'ed25519') {
        return reply.code(400).send({ error: 'new_public_key must be an Ed25519 key' })
      }
    } catch {
      return reply.code(400).send({ error: 'new_public_key is not a valid PEM-encoded public key' })
    }

    const now = Date.now()
    db.prepare('UPDATE agents SET public_key = ?, rotation_requested = 0 WHERE id = ?')
      .run(new_public_key, agent.id)
    // Close the previous key-history entry and open a new one. Done in a
    // transaction so a verifier never sees a moment where two keys are open.
    db.exec('BEGIN')
    try {
      db.prepare(`
        UPDATE public_key_history SET valid_until = ?
        WHERE agent_id = ? AND valid_until IS NULL
      `).run(now, agent.id)
      db.prepare(`
        INSERT INTO public_key_history (agent_id, address, public_key, valid_from, valid_until, reason)
        VALUES (?, ?, ?, ?, NULL, 'rotation')
      `).run(agent.id, agent.address, new_public_key, now)
      db.exec('COMMIT')
    } catch (e) {
      db.exec('ROLLBACK')
      throw e
    }

    return { rotated: true, public_key: new_public_key }
  })

  // Fetch an agent's public key by address — used to verify incoming signed requests.
  app.get('/agents/public-key', async (req, reply) => {
    const ip = req.ip ?? null
    const ua = req.headers['user-agent'] ?? null
    const { address } = req.query as { address?: string }
    if (!address) {
      recordUsage({ kind: 'resolve_public_key', address: null, status: 400, ip, userAgent: ua })
      return reply.code(400).send({ error: 'address required' })
    }

    const agent = db
      .prepare('SELECT address, public_key FROM agents WHERE address = ? AND revoked = 0')
      .get(address) as any

    if (!agent) {
      recordUsage({ kind: 'resolve_public_key', address, status: 404, ip, userAgent: ua })
      return reply.code(404).send({ error: 'Agent not found' })
    }
    recordUsage({ kind: 'resolve_public_key', address, status: 200, ip, userAgent: ua })
    return {
      address: agent.address,
      public_key: agent.public_key,
      ...resolveVerification(agent.address),
    }
  })

  // CRL-style feed — every (address, event) where a key validity period closed
  // after the supplied `since` timestamp. event is 'rotation' if a later
  // validity period exists for the same agent (the new key replacing the old)
  // or 'revocation' otherwise. Verifiers poll this and invalidate any cached
  // (address, public_key) pin for listed addresses.
  //
  // Public endpoint — same justification as /agents/:address/key-history.
  // Bounded by since to keep response size manageable; clients use the returned
  // `now` timestamp as their next `since`.
  app.get('/agents/revocations', async (req, reply) => {
    const { since: sinceRaw } = req.query as { since?: string }
    const since = parseInt(sinceRaw ?? '0', 10)
    if (!Number.isFinite(since) || since < 0) {
      return reply.code(400).send({ error: 'since must be a non-negative integer (unix milliseconds)' })
    }

    // Use h2.id > h.id (autoincrement) rather than valid_from comparison.
    // Same-millisecond rotations would tie on timestamps but the new row
    // always has a higher id (INSERT happens after the UPDATE in the rotate
    // transaction), making id-based ordering the reliable signal.
    const rows = db.prepare(`
      SELECT
        h.address,
        h.valid_until AS ts,
        CASE
          WHEN EXISTS (
            SELECT 1 FROM public_key_history h2
            WHERE h2.agent_id = h.agent_id AND h2.id > h.id
          ) THEN 'rotation'
          ELSE 'revocation'
        END AS event
      FROM public_key_history h
      WHERE h.valid_until IS NOT NULL AND h.valid_until > ?
      ORDER BY h.valid_until ASC
    `).all(since) as Array<{ address: string; ts: number; event: 'rotation' | 'revocation' }>

    return { since, now: Date.now(), events: rows }
  })

  // Public key history for an address — verifiers query this to detect rotation
  // events between cache reads. Returns every period of key validity for the
  // address, oldest first. current_key is null when the agent is revoked.
  // Public endpoint by design — public keys and rotation timestamps are not
  // sensitive, and verifiers must be able to audit without authentication.
  app.get('/agents/:address/key-history', async (req, reply) => {
    const { address } = req.params as { address: string }
    const exists = db.prepare('SELECT id FROM agents WHERE address = ?').get(address)
    if (!exists) return reply.code(404).send({ error: 'Agent not found' })

    const rows = db.prepare(`
      SELECT public_key, valid_from, valid_until, reason
      FROM public_key_history
      WHERE address = ?
      ORDER BY valid_from ASC
    `).all(address) as Array<{ public_key: string; valid_from: number; valid_until: number | null; reason: string }>

    const current = rows.find(r => r.valid_until === null) ?? null
    return {
      address,
      current_key: current?.public_key ?? null,
      revoked: current === null,
      history: rows,
    }
  })

  // Resolve an agent by address — the keyid URL in RFC 9421 signatures resolves here.
  app.get('/agents/:address', async (req, reply) => {
    const ip = req.ip ?? null
    const ua = req.headers['user-agent'] ?? null
    const { address } = req.params as { address: string }

    const agent = db
      .prepare('SELECT address, public_key FROM agents WHERE address = ? AND revoked = 0')
      .get(address) as any

    if (!agent) {
      recordUsage({ kind: 'resolve_agent', address, status: 404, ip, userAgent: ua })
      return reply.code(404).send({ error: 'Agent not found' })
    }
    recordUsage({ kind: 'resolve_agent', address, status: 200, ip, userAgent: ua })
    return {
      address: agent.address,
      public_key: agent.public_key,
      ...resolveVerification(agent.address),
    }
  })
}
