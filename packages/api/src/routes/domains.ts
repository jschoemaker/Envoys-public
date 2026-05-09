import type { FastifyInstance } from 'fastify'
import { randomUUID } from 'crypto'
import { promises as dns } from 'dns'
import { db } from '../db.js'
import type { CustomDomain } from '../db.js'
import { generateToken } from '../crypto.js'
import { requireAccountKey } from '../middleware/auth.js'
import { getLimits } from '../limits.js'

const SERVICE_DOMAIN = process.env.SERVICE_DOMAIN ?? 'envoys.me'

// A subdomain is anything with more than 2 parts: agents.acme.com → true, acme.com → false
function isSubdomain(domain: string): boolean {
  return domain.split('.').length > 2
}

function txtHost(domain: string): string {
  return `_envoys.${domain}`
}

function buildInstructions(domain: string, token: string) {
  const subdomain = isSubdomain(domain)
  const txt_host  = txtHost(domain)
  const txt_value = `envoys-verify=${token}`

  const records: object[] = [
    {
      type:    'TXT',
      host:    txt_host,
      value:   txt_value,
      purpose: 'Proves you own this domain (required)',
    },
  ]

  if (subdomain) {
    records.push({
      type:    'CNAME',
      host:    domain,
      value:   SERVICE_DOMAIN,
      purpose: 'Routes the subdomain to Envoys (recommended)',
    })
  }

  return records
}

export async function domainRoutes(app: FastifyInstance) {
  // Step 1 — Initiate domain verification.
  // Accepts either a root domain (acme.com) or subdomain (agents.acme.com).
  // Returns the exact DNS records the user needs to add.
  app.post('/domains', { preHandler: requireAccountKey }, async (req, reply) => {
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

    // Enforce custom domain limit for this tier
    const limits = getLimits(req.account!.tier)
    if (limits.customDomains === 0) {
      return reply.code(403).send({
        error: `Custom domains are not available on the ${req.account!.tier} tier. Upgrade to Pro or higher.`,
      })
    }
    if (limits.customDomains !== Infinity) {
      const { count } = db.prepare(`
        SELECT COUNT(*) as count FROM custom_domains WHERE account_id = ?
      `).get(req.account!.id) as { count: number }
      if (count >= limits.customDomains) {
        return reply.code(403).send({
          error: `Custom domain limit reached for ${req.account!.tier} tier (max ${limits.customDomains}). Upgrade to add more.`,
        })
      }
    }

    // Only one account can own a domain
    const existing = db
      .prepare('SELECT * FROM custom_domains WHERE domain = ?')
      .get(clean) as CustomDomain | undefined

    if (existing) {
      if (existing.account_id !== req.account!.id) {
        return reply.code(409).send({ error: 'Domain already claimed by another account' })
      }
      return reply.send({
        domain: clean,
        subdomain: isSubdomain(clean),
        verified: !!existing.verified,
        dns_records: buildInstructions(clean, existing.verify_token),
        message: existing.verified
          ? 'Domain already verified.'
          : 'Add the DNS records below, then call POST /domains/verify',
      })
    }

    const id    = randomUUID()
    const token = generateToken('v')

    db.prepare(`
      INSERT INTO custom_domains (id, account_id, domain, verify_token, verified, created_at)
      VALUES (?, ?, ?, ?, 0, ?)
    `).run(id, req.account!.id, clean, token, Date.now())

    return reply.code(201).send({
      domain: clean,
      subdomain: isSubdomain(clean),
      verified: false,
      dns_records: buildInstructions(clean, token),
      message: 'Add the DNS records below, then call POST /domains/verify',
    })
  })

  // Step 2 — Verify domain ownership.
  // TXT is required. CNAME (subdomain only) is checked and reported but not required to pass.
  // Safe to retry — DNS propagation can take up to 48h.
  app.post('/domains/verify', { preHandler: requireAccountKey }, async (req, reply) => {
    const { domain } = req.body as { domain?: string }
    if (!domain) return reply.code(400).send({ error: 'domain required' })
    if (domain.length > 253) return reply.code(400).send({ error: 'domain must be 253 characters or fewer' })

    const clean = domain.toLowerCase().replace(/\/$/, '')
    const row = db
      .prepare('SELECT * FROM custom_domains WHERE domain = ? AND account_id = ?')
      .get(clean, req.account!.id) as CustomDomain | undefined

    if (!row) return reply.code(404).send({ error: 'Domain not found — call POST /domains first' })
    if (row.verified) {
      return reply.send({
        verified: true,
        domain: clean,
        cname_set: isSubdomain(clean) ? await checkCname(clean) : null,
      })
    }

    // ── TXT check (required) ─────────────────────────────────────────────
    const expected = `envoys-verify=${row.verify_token}`
    const txtResult = await checkTxt(txtHost(clean), expected)

    if (!txtResult.found) {
      return reply.code(400).send({
        error: 'TXT record not found yet — DNS may still be propagating (up to 48h)',
        txt_host:  txtHost(clean),
        txt_value: expected,
      })
    }

    if (!txtResult.matched) {
      return reply.code(400).send({
        error: 'TXT record found but value does not match',
        expected,
        found: txtResult.values,
      })
    }

    // ── CNAME check (subdomain only, advisory) ────────────────────────────
    let cnameSet: boolean | null = null
    if (isSubdomain(clean)) {
      cnameSet = await checkCname(clean)
    }

    db.prepare('UPDATE custom_domains SET verified = 1, verified_at = ? WHERE id = ?').run(Date.now(), row.id)

    return reply.send({
      verified: true,
      domain:   clean,
      cname_set: cnameSet,
      message: cnameSet === false
        ? `Domain verified. Add the CNAME record to complete subdomain routing, then agents can register as name@${clean}`
        : `Domain verified. Agents can now register as name@${clean}`,
    })
  })

  // List all domains for this account
  app.get('/domains', { preHandler: requireAccountKey }, async (req, reply) => {
    const rows = db.prepare(`
      SELECT id, domain, verified, created_at FROM custom_domains WHERE account_id = ?
    `).all(req.account!.id) as CustomDomain[]

    return rows.map(r => ({
      ...r,
      subdomain: isSubdomain(r.domain),
      verified:  !!r.verified,
    }))
  })

  // Remove a custom domain
  app.delete('/domains/:id', { preHandler: requireAccountKey }, async (req, reply) => {
    const { id } = req.params as { id: string }
    const row = db
      .prepare('SELECT id FROM custom_domains WHERE id = ? AND account_id = ?')
      .get(id, req.account!.id)

    if (!row) return reply.code(404).send({ error: 'Domain not found' })

    db.prepare('DELETE FROM custom_domains WHERE id = ?').run(id)
    return { deleted: true }
  })
}

// ── DNS helpers ──────────────────────────────────────────────────────────────

async function checkTxt(host: string, expected: string) {
  try {
    const records = await dns.resolveTxt(host)
    const values  = records.map(chunks => chunks.join(''))
    return { found: true, matched: values.some(v => v === expected), values }
  } catch {
    return { found: false, matched: false, values: [] }
  }
}

async function checkCname(domain: string): Promise<boolean> {
  try {
    const records = await dns.resolveCname(domain)
    return records.some(r => r.replace(/\.$/, '') === SERVICE_DOMAIN)
  } catch {
    return false
  }
}
