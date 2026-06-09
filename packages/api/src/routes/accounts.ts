import type { FastifyInstance } from 'fastify'
import { randomUUID } from 'crypto'
import { promises as dns } from 'dns'
import { db } from '../db.js'
import type { Account } from '../db.js'
import { generateToken, hashToken } from '../crypto.js'
import { requireAccountKey } from '../middleware/auth.js'
import { getLimits } from '../limits.js'
import { recordAudit } from '../usage.js'

// Reserved handles that cannot be claimed by users — vendor names, system names,
// and obvious squat targets. Kept centralised so admin-side tooling can audit
// the same list. To grant a reserved handle to its rightful owner, do it via
// direct DB write, not by removing the entry here.
const RESERVED_HANDLES = new Set<string>([
  // Major LLM / AI vendors
  'openai', 'anthropic', 'claude', 'chatgpt', 'gpt', 'mistral', 'huggingface',
  'perplexity', 'xai', 'grok', 'cohere', 'gemini', 'bard', 'llama', 'meta',
  // Cloud / infra vendors (common counterparties)
  'microsoft', 'azure', 'google', 'apple', 'amazon', 'aws', 'gcp',
  'cloudflare', 'hetzner', 'digitalocean', 'vercel', 'netlify',
  // System / admin names — common attacker squat targets
  'admin', 'root', 'system', 'support', 'security', 'abuse', 'noc',
  'postmaster', 'webmaster', 'hostmaster', 'info', 'contact', 'help',
  // Web / mail infrastructure prefixes
  'api', 'www', 'mail', 'smtp', 'imap', 'pop', 'ftp', 'ssh', 'ns', 'mx',
  // The project itself + close variants
  'envoys', 'envoy', 'envoymail', 'envoy-mail', 'agentmail',
  // Generic squat bait
  'example', 'test', 'demo', 'public', 'private', 'official', 'verified',
  'agent', 'bot', 'robot', 'service',
])

// Map digits to the letters they most commonly resemble. Used during
// canonicalisation to detect handles that differ from an existing one only by
// digit/letter substitution (`acmec0rp` vs `acmecorp`).
const DIGIT_LETTER_CONFUSABLES: Record<string, string> = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
}

// Compute a canonical form for handle uniqueness comparisons. Strips hyphens
// and substitutes confusable digits with their look-alike letters. Two handles
// that share a canonical form are considered visually conflicting and must not
// coexist — first registration wins.
export function canonicalizeHandle(handle: string): string {
  let out = ''
  for (const ch of handle) {
    if (ch === '-') continue
    out += DIGIT_LETTER_CONFUSABLES[ch] ?? ch
  }
  return out
}

// Handle rules: 3–30 chars, lowercase letters/numbers/hyphens, no leading or
// trailing hyphen, not in the reserved list. Confusable conflict checks (which
// require DB access) live in checkHandleConflict() below.
export function validateHandle(handle: string): string | null {
  if (!handle) return 'Handle is required'
  if (handle.length < 3) return 'Handle must be at least 3 characters'
  if (handle.length > 30) return 'Handle must be 30 characters or fewer'
  if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(handle)) return 'Handle can only contain lowercase letters, numbers, and hyphens, and cannot start or end with a hyphen'
  if (RESERVED_HANDLES.has(handle)) return 'Handle is reserved and cannot be registered'
  return null
}

// Look up whether a handle has a verified domain attestation. Used by the
// resolver endpoints to surface verification status to verifiers without
// requiring a separate request. Returns null if no verification exists or
// if the bound handle no longer matches (account changed handle).
export function getVerifiedDomainForHandle(handle: string): { domain: string; verified_at: number } | null {
  const row = db.prepare(`
    SELECT domain, verified_at
    FROM handle_verifications
    WHERE handle = ? AND verified = 1
  `).get(handle) as { domain: string; verified_at: number } | undefined
  return row ?? null
}

// Look up whether a custom domain has been DNS-verified. Parallel to the
// handle-attestation path: addresses on a verified custom domain (e.g.
// playground@envoys.me) get this surfaced as `verified_domain` in resolver
// responses, since they have no handle for `verified_handle` to apply to.
export function getVerifiedCustomDomain(domain: string): { domain: string; verified_at: number } | null {
  const row = db.prepare(`
    SELECT domain, verified_at
    FROM custom_domains
    WHERE domain = ? AND verified = 1
  `).get(domain) as { domain: string; verified_at: number | null } | undefined
  if (!row) return null
  return { domain: row.domain, verified_at: row.verified_at ?? 0 }
}

// Check whether a candidate handle conflicts with an existing one — either by
// exact match or by sharing a canonical form. Returns an error message or null.
// Pass excludeAccountId when validating an update so the account doesn't
// conflict with itself.
export function checkHandleConflict(handle: string, excludeAccountId?: string): string | null {
  const exact = excludeAccountId
    ? db.prepare('SELECT id FROM accounts WHERE handle = ? AND id != ?').get(handle, excludeAccountId)
    : db.prepare('SELECT id FROM accounts WHERE handle = ?').get(handle)
  if (exact) return 'Handle is already taken'

  const canonical = canonicalizeHandle(handle)
  const all = db.prepare(
    excludeAccountId
      ? 'SELECT handle FROM accounts WHERE id != ?'
      : 'SELECT handle FROM accounts'
  ).all(...(excludeAccountId ? [excludeAccountId] : [])) as Array<{ handle: string }>
  for (const row of all) {
    if (canonicalizeHandle(row.handle) === canonical) {
      return 'Handle is too similar to an existing handle (differs only in hyphens or digit/letter substitution)'
    }
  }
  return null
}

export async function accountRoutes(app: FastifyInstance) {
  // Check if a handle is available before committing to it
  app.get('/accounts/check-handle/:handle', async (req, reply) => {
    const { handle } = req.params as { handle: string }
    const err = validateHandle(handle)
    if (err) return reply.code(400).send({ available: false, error: err })

    const conflict = checkHandleConflict(handle)
    if (conflict) return reply.send({ available: false, error: conflict })
    return { available: true }
  })

  // Create a developer account.
  // email is optional — agents can register without one for fully autonomous onboarding.
  // handle is chosen by the caller — must pass validation and be unique.
  app.post('/accounts/register', async (req, reply) => {
    const { email, handle } = req.body as { email?: string; handle?: string }

    if (!handle) return reply.code(400).send({ error: 'handle required' })
    if (email && email.length > 254) return reply.code(400).send({ error: 'email must be 254 characters or fewer' })

    const handleErr = validateHandle(handle)
    if (handleErr) return reply.code(400).send({ error: handleErr })

    if (email && db.prepare('SELECT id FROM accounts WHERE email = ?').get(email)) {
      return reply.code(409).send({ error: 'Email already registered' })
    }

    const conflict = checkHandleConflict(handle)
    if (conflict) return reply.code(409).send({ error: conflict })

    const id          = randomUUID()
    const account_key = generateToken('ak')

    // The checks above are advisory — two concurrent registrations can both
    // pass them. The UNIQUE constraints are the real gate; surface a clean
    // 409 instead of a 500 when the race loses.
    try {
      db.prepare(`
        INSERT INTO accounts (id, email, account_key, handle, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, email ?? null, hashToken(account_key), handle, Date.now())
    } catch (e: any) {
      if (e?.message?.includes('UNIQUE')) {
        const taken = e.message.includes('accounts.email') ? 'Email already registered' : 'Handle is already taken'
        return reply.code(409).send({ error: taken })
      }
      throw e
    }

    recordAudit({ accountId: id, kind: 'account.signin', detail: 'email (new account)', ip: req.ip ?? null })

    return reply.code(201).send({
      id,
      handle,
      account_key,
      message: 'Save your account_key — it is shown once. Use it to register agents.',
      ...(email ? { email } : {}),
    })
  })

  // Account overview
  app.get('/accounts/me', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const agents = db.prepare(`
      SELECT id, name, address, public_key, capabilities, revoked, created_at
      FROM agents WHERE account_id = ?
    `).all(account.id) as any[]

    return {
      id: account.id,
      email: account.email,
      handle: account.handle,
      tier: account.tier,
      profile_complete: !!(account.email),
      agents: agents.map(a => ({ ...a, capabilities: JSON.parse(a.capabilities) })),
    }
  })

  // Usage stats for the authenticated account
  app.get('/accounts/stats', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const limits  = getLimits(account.tier)

    const { agents } = db.prepare(`
      SELECT COUNT(*) as agents FROM agents WHERE account_id = ? AND revoked = 0
    `).get(account.id) as { agents: number }

    const { domains } = db.prepare(`
      SELECT COUNT(*) as domains FROM custom_domains WHERE account_id = ? AND verified = 1
    `).get(account.id) as { domains: number }

    // Resolution counts for this account's agents over the last 7 days.
    // Uses the address-keyed usage_events table — only resolves are counted (not doc fetches).
    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
    const { resolves_7d } = db.prepare(`
      SELECT COUNT(*) as resolves_7d FROM usage_events
      WHERE ts >= ?
        AND kind IN ('resolve_public_key','resolve_agent')
        AND address IN (SELECT address FROM agents WHERE account_id = ?)
    `).get(sevenDaysAgo, account.id) as { resolves_7d: number }

    return {
      tier: account.tier,
      agents: {
        used:  agents,
        limit: limits.agents === Infinity ? null : limits.agents,
      },
      custom_domains: {
        used:  domains,
        limit: limits.customDomains === Infinity ? null : limits.customDomains,
      },
      rate_per_minute: limits.ratePerMinute === Infinity ? null : limits.ratePerMinute,
      resolves_7d,
    }
  })

  // Update email and/or handle — used after agent creates account to let human set their details
  app.patch('/accounts/me', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const { email, handle } = req.body as { email?: string; handle?: string }

    if (email && email.length > 254) return reply.code(400).send({ error: 'email must be 254 characters or fewer' })

    if (email) {
      if (db.prepare('SELECT id FROM accounts WHERE email = ? AND id != ?').get(email, account.id)) {
        return reply.code(409).send({ error: 'Email already in use' })
      }
    }

    if (handle) {
      const handleErr = validateHandle(handle)
      if (handleErr) return reply.code(400).send({ error: handleErr })
      const conflict = checkHandleConflict(handle, account.id)
      if (conflict) return reply.code(409).send({ error: conflict })
    }

    if (email) {
      db.prepare('UPDATE accounts SET email = ? WHERE id = ?').run(email, account.id)
      recordAudit({ accountId: account.id, kind: 'account.email_changed', detail: email, ip: req.ip ?? null })
    }
    if (handle) {
      db.prepare('UPDATE accounts SET handle = ? WHERE id = ?').run(handle, account.id)
      recordAudit({ accountId: account.id, kind: 'account.handle_changed', detail: handle, ip: req.ip ?? null })
      // Handle changed — invalidate any prior domain attestation, since it was
      // bound to the old handle. User must re-verify under the new handle.
      db.prepare('DELETE FROM handle_verifications WHERE account_id = ?').run(account.id)
    }

    const updated = db.prepare('SELECT * FROM accounts WHERE id = ?').get(account.id) as Account
    return { email: updated.email, handle: updated.handle, profile_complete: !!(updated.email) }
  })

  // Rotate the account key — authenticated, returns new key immediately.
  // Agent keys are unaffected.
  app.post('/accounts/me/rotate-key', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const new_account_key = generateToken('ak')
    db.prepare('UPDATE accounts SET account_key = ? WHERE id = ?').run(hashToken(new_account_key), account.id)
    recordAudit({ accountId: account.id, kind: 'account.key_rotated', ip: req.ip ?? null })
    return { account_key: new_account_key }
  })

  // Delete the authenticated account. Foreign keys are ON, and the append-only,
  // verifier-facing public_key_history references agents — so we can neither
  // hard-delete agents (it would force deleting their history) nor delete the
  // account row (agents still reference it). Instead we:
  //   - revoke every active agent and close its open key-history period, so each
  //     address resolves as revoked and pinned verifiers can detect the change;
  //   - delete the account's private records (custom domains, handle proofs, audit log);
  //   - scrub the account row to a credential-less, PII-less tombstone that only
  //     anchors the preserved agent/key-history data and keeps the handle reserved.
  // The caller's account_key stops working immediately.
  app.delete('/accounts/me', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const now     = Date.now()

    db.exec('BEGIN')
    try {
      const agents = db
        .prepare('SELECT id FROM agents WHERE account_id = ? AND revoked = 0')
        .all(account.id) as Array<{ id: string }>
      const revoke       = db.prepare('UPDATE agents SET revoked = 1, rotation_requested = 0 WHERE id = ?')
      const closeHistory = db.prepare(
        'UPDATE public_key_history SET valid_until = ? WHERE agent_id = ? AND valid_until IS NULL',
      )
      for (const a of agents) {
        revoke.run(a.id)
        closeHistory.run(now, a.id)
      }

      db.prepare('DELETE FROM custom_domains WHERE account_id = ?').run(account.id)
      db.prepare('DELETE FROM handle_verifications WHERE account_id = ?').run(account.id)
      db.prepare('DELETE FROM audit_events WHERE account_id = ?').run(account.id)

      // Tombstone: clear PII and replace the key with an unusable value that is
      // never returned, so this account can never authenticate again.
      const deadKey = hashToken(generateToken('deleted'))
      db.prepare('UPDATE accounts SET email = NULL, account_key = ? WHERE id = ?')
        .run(deadKey, account.id)

      db.exec('COMMIT')
    } catch (e) {
      db.exec('ROLLBACK')
      throw e
    }

    return { deleted: true }
  })

  // Recent audit events for the authenticated account. Surfaces sign-ins,
  // key rotations, agent register/revoke/rotation-request — everything a user
  // would scan to spot unauthorised activity.
  app.get('/accounts/audit', { preHandler: requireAccountKey }, async (req) => {
    const account = req.account!
    const limit = Math.min(100, parseInt(((req.query as any)?.limit ?? '20'), 10) || 20)
    const events = db.prepare(`
      SELECT ts, kind, detail FROM audit_events
      WHERE account_id = ? ORDER BY ts DESC LIMIT ?
    `).all(account.id, limit) as Array<{ ts: number; kind: string; detail: string | null }>
    return { events }
  })

  // Initiate a DNS-TXT proof that the account's handle is associated with a
  // real-world domain. Caller adds the returned TXT record to their DNS, then
  // calls /verify-handle/check. This is a real-world identity anchor outside
  // the first-come-first-served handle pool.
  app.post('/accounts/me/verify-handle', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const { domain } = req.body as { domain?: string }
    if (!domain) return reply.code(400).send({ error: 'domain required' })
    if (domain.length > 253) return reply.code(400).send({ error: 'domain must be 253 characters or fewer' })

    const clean = domain.toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .replace(/\/$/, '')

    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(clean)) {
      return reply.code(400).send({ error: 'Invalid domain format' })
    }

    const token = generateToken('hv')
    // REPLACE INTO so re-initiating with a new domain wipes the prior pending
    // verification — only one (account → domain) attestation slot at a time.
    db.prepare(`
      INSERT OR REPLACE INTO handle_verifications
        (account_id, handle, domain, verify_token, verified, verified_at, initiated_at)
      VALUES (?, ?, ?, ?, 0, NULL, ?)
    `).run(account.id, account.handle, clean, token, Date.now())

    return reply.code(201).send({
      handle: account.handle,
      domain: clean,
      verified: false,
      dns_record: {
        type:    'TXT',
        host:    `_envoys-handle.${clean}`,
        value:   `envoys-handle-verify=${token}`,
        purpose: `Proves ${clean} attests to handle "${account.handle}"`,
      },
      message: 'Add the DNS TXT record above, then call POST /accounts/me/verify-handle/check',
    })
  })

  // Run the DNS lookup and mark the verification as verified if the TXT
  // record matches. Idempotent and safe to retry — DNS propagation may take
  // up to 48 hours.
  app.post('/accounts/me/verify-handle/check', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const row = db.prepare(`
      SELECT * FROM handle_verifications WHERE account_id = ?
    `).get(account.id) as {
      handle: string; domain: string; verify_token: string; verified: number
    } | undefined

    if (!row) return reply.code(404).send({ error: 'No handle verification in progress — call POST /accounts/me/verify-handle first' })
    if (row.handle !== account.handle) {
      // Handle changed since verification was initiated — drop the stale row.
      db.prepare('DELETE FROM handle_verifications WHERE account_id = ?').run(account.id)
      return reply.code(409).send({ error: 'Handle changed since verification was initiated — re-initiate verification' })
    }
    if (row.verified) {
      return reply.send({ verified: true, handle: row.handle, domain: row.domain })
    }

    const expected = `envoys-handle-verify=${row.verify_token}`
    let values: string[] = []
    try {
      const records = await dns.resolveTxt(`_envoys-handle.${row.domain}`)
      values = records.map(chunks => chunks.join(''))
    } catch {
      return reply.code(400).send({
        error: 'TXT record not found yet — DNS may still be propagating (up to 48h)',
        txt_host:  `_envoys-handle.${row.domain}`,
        txt_value: expected,
      })
    }
    if (!values.some(v => v === expected)) {
      return reply.code(400).send({
        error: 'TXT record found but value does not match',
        expected,
        found: values,
      })
    }

    const now = Date.now()
    db.prepare('UPDATE handle_verifications SET verified = 1, verified_at = ? WHERE account_id = ?')
      .run(now, account.id)

    return reply.send({
      verified: true,
      handle: row.handle,
      domain: row.domain,
      verified_at: now,
    })
  })

  // Read current verification state for the account.
  app.get('/accounts/me/verify-handle', { preHandler: requireAccountKey }, async (req, reply) => {
    const account = req.account!
    const row = db.prepare(`
      SELECT handle, domain, verified, verified_at, initiated_at
      FROM handle_verifications WHERE account_id = ?
    `).get(account.id) as {
      handle: string; domain: string; verified: number; verified_at: number | null; initiated_at: number
    } | undefined
    if (!row) return { verified: false, handle: account.handle, domain: null }
    return {
      verified: !!row.verified,
      handle: row.handle,
      domain: row.domain,
      verified_at: row.verified_at,
      initiated_at: row.initiated_at,
    }
  })

  // Drop the verification — owner can voluntarily un-verify.
  app.delete('/accounts/me/verify-handle', { preHandler: requireAccountKey }, async (req, reply) => {
    db.prepare('DELETE FROM handle_verifications WHERE account_id = ?').run(req.account!.id)
    return { deleted: true }
  })

}
