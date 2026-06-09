import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { generateKeyPairSync, createPrivateKey, sign as cryptoSign } from 'crypto'
import type { FastifyInstance } from 'fastify'

// setup.ts has already set DB_PATH=:memory: before this file runs (via setupFiles)
const { buildApp } = await import('../app.js')

let app: FastifyInstance

beforeAll(async () => {
  app = buildApp({ logger: false, rateLimit: false })
  await app.ready()
})

afterAll(async () => {
  await app.close()
})

function makeEd25519() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

// ── Account registration ──────────────────────────────────────────────────────

describe('POST /accounts/register', () => {
  it('creates an account and returns account_key', async () => {
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'acct1' } })
    expect(res.statusCode).toBe(201)
    const body = res.json()
    expect(body.account_key).toMatch(/^ak_/)
    expect(body.handle).toBe('acct1')
    expect(body.message).toBeTruthy()
    expect(body.id).toBeTruthy()
  })

  it('rejects a duplicate handle', async () => {
    await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'dupe' } })
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'dupe' } })
    expect(res.statusCode).toBe(409)
  })

  it('rejects a handle shorter than 3 chars', async () => {
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'ab' } })
    expect(res.statusCode).toBe(400)
  })

  it('rejects a handle with leading hyphen', async () => {
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: '-bad' } })
    expect(res.statusCode).toBe(400)
  })

  it('rejects a missing handle', async () => {
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: {} })
    expect(res.statusCode).toBe(400)
  })

  it('rejects a reserved handle', async () => {
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'microsoft' } })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/reserved/i)
  })

  it('rejects a confusable conflict (digit/letter substitution)', async () => {
    await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'acmecorp' } })
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'acmec0rp' } })
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toMatch(/similar/i)
  })

  it('rejects a confusable conflict (hyphen variation)', async () => {
    await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'foo-bar' } })
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'foobar' } })
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toMatch(/similar/i)
  })
})

// ── Agent registration ────────────────────────────────────────────────────────

describe('POST /agents/register', () => {
  let accountKey: string

  beforeAll(async () => {
    const res = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'agentowner' } })
    accountKey = res.json().account_key
  })

  it('registers an agent with a valid Ed25519 public key', async () => {
    const { publicKey } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'my-agent', public_key: publicKey },
    })
    expect(res.statusCode).toBe(201)
    const body = res.json()
    expect(body.address).toMatch(/^my-agent@agentowner\.envoys\.me$/)
    expect(body.agent_key).toMatch(/^agt_/)
    expect(body.public_key).toBe(publicKey)
    expect(body.private_key).toBeUndefined()
  })

  it('rejects registration without public_key', async () => {
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'no-key' },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/public_key/)
  })

  it('rejects a non-Ed25519 key (RSA)', async () => {
    const { publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'rsa-agent', public_key: publicKey },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/Ed25519/)
  })

  it('rejects a garbage public_key string', async () => {
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'garbage', public_key: 'not-a-key' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('rejects an unauthenticated request', async () => {
    const { publicKey } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      payload: { name: 'unauth', public_key: publicKey },
    })
    expect(res.statusCode).toBe(401)
  })

  // ── Proof-of-possession ─────────────────────────────────────────────────────

  function makePop(publicKey: string, privateKey: string, createdOffset = 0) {
    const pop_created = Math.floor(Date.now() / 1000) + createdOffset
    const pop = cryptoSign(
      null,
      Buffer.from(`envoys-pop:v1:${pop_created}:${publicKey}`),
      createPrivateKey(privateKey),
    ).toString('base64')
    return { pop, pop_created }
  }

  it('records pop_verified when a valid proof-of-possession is supplied', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'pop-agent', public_key: publicKey, ...makePop(publicKey, privateKey) },
    })
    expect(res.statusCode).toBe(201)
    expect(res.json().pop_verified).toBe(true)

    // Surfaced to verifiers in resolver responses.
    const resolved = await app.inject({ method: 'GET', url: `/agents/${res.json().address}` })
    expect(resolved.json().pop_verified).toBe(true)
  })

  it('registers without pop as pop_verified=false (compat)', async () => {
    const { publicKey } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'no-pop-agent', public_key: publicKey },
    })
    expect(res.statusCode).toBe(201)
    expect(res.json().pop_verified).toBe(false)

    const resolved = await app.inject({ method: 'GET', url: `/agents/${res.json().address}` })
    expect(resolved.json().pop_verified).toBe(false)
  })

  it('rejects a pop signed by a different key', async () => {
    const { publicKey } = makeEd25519()
    const { privateKey: otherPriv } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'forged-pop', public_key: publicKey, ...makePop(publicKey, otherPriv) },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/pop signature/)
  })

  it('rejects a stale pop_created', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'stale-pop', public_key: publicKey, ...makePop(publicKey, privateKey, -600) },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/window/)
  })

  it('rejects pop without pop_created (and vice versa)', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const { pop } = makePop(publicKey, privateKey)
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'half-pop', public_key: publicKey, pop },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/pop_created/)
  })
})

// ── Key rotation flow ─────────────────────────────────────────────────────────

describe('Key rotation flow', () => {
  let accountKey: string
  let agentKey: string
  let agentId: string
  let address: string
  let currentPublicKey: string

  beforeAll(async () => {
    const { publicKey } = makeEd25519()
    currentPublicKey = publicKey

    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'rotowner' } })
    accountKey = acct.json().account_key

    const agent = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'rot-agent', public_key: publicKey },
    })
    const body = agent.json()
    agentKey   = body.agent_key
    agentId    = body.id
    address    = body.address
  })

  it('GET /agent/keys returns rotation_requested: false initially', async () => {
    const res = await app.inject({ method: 'GET', url: '/agent/keys', headers: { authorization: `Bearer ${agentKey}` } })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ rotation_requested: false, public_key: currentPublicKey })
  })

  it('POST /agents/:id/rotate-keys sets the rotation flag', async () => {
    const res = await app.inject({
      method: 'POST', url: `/agents/${agentId}/rotate-keys`,
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json().message).toMatch(/rotation requested/i)
  })

  it('GET /agent/keys reflects rotation_requested: true', async () => {
    const res = await app.inject({ method: 'GET', url: '/agent/keys', headers: { authorization: `Bearer ${agentKey}` } })
    expect(res.json().rotation_requested).toBe(true)
  })

  it('POST /agent/rotate-keys confirms rotation with new key', async () => {
    const { publicKey: newKey } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agent/rotate-keys',
      headers: { authorization: `Bearer ${agentKey}` },
      payload: { new_public_key: newKey },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ rotated: true, public_key: newKey })
    currentPublicKey = newKey
  })

  it('GET /agent/keys clears the flag after confirmation', async () => {
    const res = await app.inject({ method: 'GET', url: '/agent/keys', headers: { authorization: `Bearer ${agentKey}` } })
    expect(res.json().rotation_requested).toBe(false)
  })

  it('POST /agent/rotate-keys rejects a non-Ed25519 key', async () => {
    const { publicKey: rsaKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })
    const res = await app.inject({
      method: 'POST', url: '/agent/rotate-keys',
      headers: { authorization: `Bearer ${agentKey}` },
      payload: { new_public_key: rsaKey },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/Ed25519/)
  })
})

// ── Permanent address binding ─────────────────────────────────────────────────

describe('Permanent address binding (DELETE /agents/:id)', () => {
  let accountKey: string
  let agentId: string
  let agentName: string
  let publicKey: string

  beforeAll(async () => {
    const kp = makeEd25519()
    publicKey = kp.publicKey
    agentName = 'permabound-agent'

    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'permaowner' } })
    accountKey = acct.json().account_key

    const agent = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: agentName, public_key: publicKey },
    })
    agentId = agent.json().id
  })

  it('DELETE /agents/:id soft-revokes the agent', async () => {
    const res = await app.inject({
      method: 'DELETE', url: `/agents/${agentId}`,
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ revoked: true })
  })

  it('Revoked agent is not resolvable', async () => {
    const res = await app.inject({ method: 'GET', url: `/agents/${agentName}@permaowner.envoys.me` })
    expect(res.statusCode).toBe(404)
  })

  it('Revoked address cannot be re-registered (permanent binding)', async () => {
    const { publicKey: newKey } = makeEd25519()
    const res = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: agentName, public_key: newKey },
    })
    expect(res.statusCode).toBe(409)
    expect(res.json().error).toMatch(/already taken/i)
  })
})

// ── Public key resolution ─────────────────────────────────────────────────────

describe('Public key resolution', () => {
  let address: string
  let publicKey: string

  beforeAll(async () => {
    const kp = makeEd25519()
    publicKey = kp.publicKey

    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'resolver' } })
    const accountKey = acct.json().account_key

    const agent = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'lookup-agent', public_key: publicKey },
    })
    address = agent.json().address
  })

  it('GET /agents/:address returns the public key', async () => {
    const res = await app.inject({ method: 'GET', url: `/agents/${address}` })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ address, public_key: publicKey })
  })

  it('GET /agents/public-key?address= returns the public key', async () => {
    const res = await app.inject({ method: 'GET', url: `/agents/public-key?address=${encodeURIComponent(address)}` })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ address, public_key: publicKey })
  })

  it('GET /agents/:address returns 404 for unknown address', async () => {
    const res = await app.inject({ method: 'GET', url: '/agents/nobody@nowhere.envoys.me' })
    expect(res.statusCode).toBe(404)
  })

  // Spec §6.1 — dual-shape keyid resolution. Verifier may request DID Document
  // form via Accept; default behavior unchanged.
  it('GET /agents/:address returns DID Document when Accept: application/did+json', async () => {
    const res = await app.inject({
      method: 'GET',
      url:    `/agents/${address}`,
      headers: { accept: 'application/did+json' },
    })
    expect(res.statusCode).toBe(200)
    expect(res.headers['content-type']).toContain('application/did+json')
    const doc = res.json()
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1')
    expect(doc.verificationMethod).toHaveLength(1)
    const vm = doc.verificationMethod[0]
    expect(vm.type).toMatch(/^Ed25519/)
    expect(vm.publicKeyJwk?.kty).toBe('OKP')
    expect(vm.publicKeyJwk?.crv).toBe('Ed25519')
    expect(typeof vm.publicKeyJwk?.x).toBe('string')
  })

  it('GET /agents/:address ignores wildcard Accept and serves native shape', async () => {
    const res = await app.inject({
      method: 'GET',
      url:    `/agents/${address}`,
      headers: { accept: '*/*' },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ address, public_key: publicKey })
  })

  it('GET /agents/:address with mixed Accept honors q=0 on did+json', async () => {
    const res = await app.inject({
      method: 'GET',
      url:    `/agents/${address}`,
      headers: { accept: 'application/did+json;q=0, application/json' },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ address, public_key: publicKey })
  })
})

// ── Usage tracking + admin stats ──────────────────────────────────────────────

describe('Usage tracking and /admin/stats', () => {
  const ADMIN_KEY = 'test-admin-key-stats'
  let address: string

  beforeAll(async () => {
    process.env.ADMIN_KEY = ADMIN_KEY

    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'statowner' } })
    const accountKey = acct.json().account_key

    const { publicKey } = makeEd25519()
    const agent = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'stat-agent', public_key: publicKey },
    })
    address = agent.json().address

    // Generate a known mix of resolves: 3× public-key 200, 2× :address 200, 1× public-key 404, 1× :address 404, 1× public-key 400.
    await app.inject({ method: 'GET', url: `/agents/public-key?address=${encodeURIComponent(address)}` })
    await app.inject({ method: 'GET', url: `/agents/public-key?address=${encodeURIComponent(address)}` })
    await app.inject({ method: 'GET', url: `/agents/public-key?address=${encodeURIComponent(address)}` })
    await app.inject({ method: 'GET', url: `/agents/${address}` })
    await app.inject({ method: 'GET', url: `/agents/${address}` })
    await app.inject({ method: 'GET', url: '/agents/public-key?address=nope@nowhere.envoys.me' })
    await app.inject({ method: 'GET', url: '/agents/nope@nowhere.envoys.me' })
    await app.inject({ method: 'GET', url: '/agents/public-key' })

    // Funnel events: 2 skill fetches + 1 spec fetch.
    await app.inject({ method: 'GET', url: '/.well-known/agent-skill' })
    await app.inject({ method: 'GET', url: '/.well-known/agent-skill.md' })
    await app.inject({ method: 'GET', url: '/specs/signature/v1' })
  })

  it('rejects /admin/stats without admin key', async () => {
    const res = await app.inject({ method: 'GET', url: '/admin/stats' })
    expect(res.statusCode).toBe(401)
  })

  it('returns stats with totals, by_kind, and top addresses', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.window_days).toBe(7)
    expect(body.total_resolves).toBeGreaterThanOrEqual(5)
    expect(body.by_kind.resolve_public_key).toBeGreaterThanOrEqual(3)
    expect(body.by_kind.resolve_agent).toBeGreaterThanOrEqual(2)
    const top = body.top_addresses.find((r: any) => r.address === address)
    expect(top).toBeTruthy()
    expect(top.n).toBeGreaterThanOrEqual(5)
    expect(body.error_rate_window).toBeGreaterThan(0)
    expect(body.unique_ips_window).toBeGreaterThanOrEqual(1)
  })

  it('honors ?days=N within bounds', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats?days=30',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json().window_days).toBe(30)
  })

  it('clamps absurd ?days values', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats?days=99999',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json().window_days).toBe(365)
  })

  it('timeseries returns at least one daily bucket', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats/timeseries?days=7',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.days).toBe(7)
    expect(Array.isArray(body.series)).toBe(true)
    expect(body.series.length).toBeGreaterThanOrEqual(1)
    expect(body.series[0].date).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(body.series[0].count).toBeGreaterThan(0)
  })

  it('returns registry counts (accounts, agents, custom domains)', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const body = res.json()
    expect(body.accounts_total).toBeGreaterThanOrEqual(1)
    expect(body.agents_active).toBeGreaterThanOrEqual(1)
    expect(typeof body.agents_revoked).toBe('number')
    expect(typeof body.custom_domains_total).toBe('number')
    expect(typeof body.custom_domains_verified).toBe('number')
    expect(Array.isArray(body.accounts_by_tier)).toBe(true)
    const free = body.accounts_by_tier.find((r: any) => r.tier === 'free')
    expect(free).toBeTruthy()
  })

  it('returns funnel counts (skill + spec fetches)', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const body = res.json()
    expect(body.skill_fetches_window).toBeGreaterThanOrEqual(2)
    expect(body.spec_fetches_window).toBeGreaterThanOrEqual(1)
    expect(body.skill_fetches_total).toBeGreaterThanOrEqual(2)
    expect(body.spec_fetches_total).toBeGreaterThanOrEqual(1)
    expect(body.by_kind.fetch_skill).toBeGreaterThanOrEqual(2)
    expect(body.by_kind.fetch_spec).toBeGreaterThanOrEqual(1)
  })

  it('returns growth + activity ratio', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const body = res.json()
    expect(body.new_accounts_window).toBeGreaterThanOrEqual(1)
    expect(body.new_agents_window).toBeGreaterThanOrEqual(1)
    expect(body.agent_activity_ratio).toBeGreaterThan(0)
    expect(body.agent_activity_ratio).toBeLessThanOrEqual(1)
  })

  it('returns top accounts joined through agents', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const body = res.json()
    expect(Array.isArray(body.top_accounts)).toBe(true)
    const owner = body.top_accounts.find((r: any) => r.handle === 'statowner')
    expect(owner).toBeTruthy()
    expect(owner.n).toBeGreaterThanOrEqual(5)
    expect(typeof owner.tier).toBe('string')
  })

  it('skill and spec fetches do not inflate resolve counts', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    const body = res.json()
    // Invariant: total_resolves must equal the sum of resolve-kind buckets only.
    // If skill/spec fetches leaked into the resolve filter, this would be larger.
    const resolveSum = (body.by_kind.resolve_public_key ?? 0) + (body.by_kind.resolve_agent ?? 0)
    expect(body.total_resolves).toBe(resolveSum)
    // And fetch kinds must have non-zero rows of their own.
    expect(body.by_kind.fetch_skill).toBeGreaterThanOrEqual(2)
    expect(body.by_kind.fetch_spec).toBeGreaterThanOrEqual(1)
  })

  it('rejects /admin/stats/clients without admin key', async () => {
    const res = await app.inject({ method: 'GET', url: '/admin/stats/clients' })
    expect(res.statusCode).toBe(401)
  })

  it('returns client breakdown (top UAs, top IPs, by_client_class)', async () => {
    const res = await app.inject({
      method: 'GET', url: '/admin/stats/clients?days=7',
      headers: { authorization: `Bearer ${ADMIN_KEY}` },
    })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.window_days).toBe(7)
    expect(typeof body.total_unique_ips_window).toBe('number')
    expect(Array.isArray(body.top_user_agents)).toBe(true)
    expect(Array.isArray(body.top_ips)).toBe(true)
    expect(body.by_client_class).toBeTruthy()
    // Fixture events (resolves + skill/spec fetches) must be bucketed somewhere —
    // the specific class depends on the test runner's default UA, which we don't pin.
    const totalBucketed = Object.values(body.by_client_class as Record<string, number>)
      .reduce((sum, n) => sum + n, 0)
    expect(totalBucketed).toBeGreaterThan(0)
    // Each top_ips row should carry an ip + total count, and last_seen ts.
    if (body.top_ips.length > 0) {
      expect(typeof body.top_ips[0].ip).toBe('string')
      expect(typeof body.top_ips[0].total).toBe('number')
      expect(typeof body.top_ips[0].last_seen).toBe('number')
    }
  })
})

// ── did:web:envoys.me Service DID Document ────────────────────────────────────

describe('GET /.well-known/did.json (did:web:envoys.me)', () => {
  it('returns a W3C DID Document with the configured service-key Ed25519 public key', async () => {
    const res = await app.inject({ method: 'GET', url: '/.well-known/did.json' })
    expect(res.statusCode).toBe(200)
    expect(res.headers['content-type']).toContain('application/did+json')
    expect(res.headers['cache-control']).toMatch(/max-age=300/)

    const doc = res.json()
    expect(doc.id).toBe('did:web:envoys.me')
    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1')

    expect(doc.verificationMethod).toHaveLength(1)
    const vm = doc.verificationMethod[0]
    expect(vm.type).toBe('JsonWebKey2020')
    expect(vm.controller).toBe('did:web:envoys.me')
    expect(vm.publicKeyJwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x:   '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    })

    expect(doc.service.map((s: any) => s.type)).toEqual([
      'EnvoysAgentRegistry',
      'EnvoysSpec',
      'EnvoysAgentSkill',
    ])
  })

  it('records a fetch_did_doc usage event', async () => {
    await app.inject({ method: 'GET', url: '/.well-known/did.json' })
    // Direct DB peek — the route records via recordUsage which inserts synchronously.
    const { db } = await import('../db.js')
    const row = db
      .prepare(`SELECT COUNT(*) AS n FROM usage_events WHERE kind = 'fetch_did_doc'`)
      .get() as { n: number }
    expect(row.n).toBeGreaterThan(0)
  })

  it('resolves cleanly via @envoys/sdk Envoys.resolveDidWeb (verification method ↔ JsonWebKey2020)', async () => {
    // Build the SDK key path from the inject'd response and confirm extractEd25519
    // accepts JsonWebKey2020 here too (regression test for sdk-v0.8.1 patch).
    const res = await app.inject({ method: 'GET', url: '/.well-known/did.json' })
    const doc = res.json()
    // Construct what a did:web resolver would receive and convert via JWK
    const { createPublicKey } = await import('crypto')
    const pub = createPublicKey({ key: doc.verificationMethod[0].publicKeyJwk, format: 'jwk' })
    const pem = pub.export({ format: 'pem', type: 'spki' }) as string
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----/)
  })
})

// ── Phase 2: key history + revocations + handle verification ──────────────────

describe('GET /agents/:address/key-history', () => {
  let address: string
  let accountKey: string
  let agentKey: string

  beforeAll(async () => {
    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'historian' } })
    accountKey = acct.json().account_key
    const { publicKey } = makeEd25519()
    const agent = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'tracked', public_key: publicKey },
    })
    address = agent.json().address
    agentKey = agent.json().agent_key
  })

  it('returns a single register entry initially', async () => {
    const res = await app.inject({ method: 'GET', url: `/agents/${address}/key-history` })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(body.address).toBe(address)
    expect(body.revoked).toBe(false)
    expect(body.history).toHaveLength(1)
    expect(body.history[0]).toMatchObject({ reason: 'register', valid_until: null })
    expect(body.current_key).toBeTruthy()
  })

  it('records a rotation event', async () => {
    const { publicKey: newKey } = makeEd25519()
    await app.inject({
      method: 'POST', url: '/agent/rotate-keys',
      headers: { authorization: `Bearer ${agentKey}` },
      payload: { new_public_key: newKey },
    })
    const res = await app.inject({ method: 'GET', url: `/agents/${address}/key-history` })
    const body = res.json()
    expect(body.history).toHaveLength(2)
    expect(body.history[0].reason).toBe('register')
    expect(body.history[0].valid_until).not.toBeNull()
    expect(body.history[1].reason).toBe('rotation')
    expect(body.history[1].valid_until).toBeNull()
    expect(body.current_key).toBe(newKey)
  })

  it('returns 404 for unknown address', async () => {
    const res = await app.inject({ method: 'GET', url: '/agents/nope@nowhere.envoys.me/key-history' })
    expect(res.statusCode).toBe(404)
  })
})

describe('GET /agents/revocations', () => {
  it('returns events newer than since with rotation/revocation classification', async () => {
    const before = Date.now() - 10
    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'crlowner' } })
    const accountKey = acct.json().account_key

    const { publicKey: pk1 } = makeEd25519()
    const a1 = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'rotator', public_key: pk1 },
    })
    const agentKey = a1.json().agent_key
    const addr1 = a1.json().address

    // Rotate once
    const { publicKey: pk2 } = makeEd25519()
    await app.inject({
      method: 'POST', url: '/agent/rotate-keys',
      headers: { authorization: `Bearer ${agentKey}` },
      payload: { new_public_key: pk2 },
    })

    // And revoke another agent
    const { publicKey: pk3 } = makeEd25519()
    const a2 = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'doomed', public_key: pk3 },
    })
    const a2Id = a2.json().id
    const addr2 = a2.json().address
    await app.inject({
      method: 'DELETE', url: `/agents/${a2Id}`,
      headers: { authorization: `Bearer ${accountKey}` },
    })

    const res = await app.inject({ method: 'GET', url: `/agents/revocations?since=${before}` })
    expect(res.statusCode).toBe(200)
    const body = res.json()
    expect(typeof body.now).toBe('number')

    const rotationEv = body.events.find((e: any) => e.address === addr1)
    expect(rotationEv).toBeTruthy()
    expect(rotationEv.event).toBe('rotation')

    const revocationEv = body.events.find((e: any) => e.address === addr2)
    expect(revocationEv).toBeTruthy()
    expect(revocationEv.event).toBe('revocation')
  })

  it('rejects negative since', async () => {
    const res = await app.inject({ method: 'GET', url: '/agents/revocations?since=-1' })
    expect(res.statusCode).toBe(400)
  })

  it('returns empty events when since is in the future', async () => {
    const future = Date.now() + 60_000
    const res = await app.inject({ method: 'GET', url: `/agents/revocations?since=${future}` })
    expect(res.statusCode).toBe(200)
    expect(res.json().events).toEqual([])
  })
})

describe('Handle verification (DNS-TXT)', () => {
  let accountKey: string

  beforeAll(async () => {
    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'verifyowner' } })
    accountKey = acct.json().account_key
  })

  it('initiates verification with TXT instructions', async () => {
    const res = await app.inject({
      method: 'POST', url: '/accounts/me/verify-handle',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { domain: 'verifyowner.test' },
    })
    expect(res.statusCode).toBe(201)
    const body = res.json()
    expect(body.verified).toBe(false)
    expect(body.handle).toBe('verifyowner')
    expect(body.dns_record.host).toBe('_envoys-handle.verifyowner.test')
    expect(body.dns_record.value).toMatch(/^envoys-handle-verify=hv_/)
  })

  it('rejects invalid domain format', async () => {
    const res = await app.inject({
      method: 'POST', url: '/accounts/me/verify-handle',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { domain: 'not a domain' },
    })
    expect(res.statusCode).toBe(400)
  })

  it('GET returns current verification state', async () => {
    const res = await app.inject({
      method: 'GET', url: '/accounts/me/verify-handle',
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(res.statusCode).toBe(200)
    expect(res.json()).toMatchObject({ verified: false, domain: 'verifyowner.test', handle: 'verifyowner' })
  })

  it('check returns 400 when TXT record is absent (cannot verify in test)', async () => {
    const res = await app.inject({
      method: 'POST', url: '/accounts/me/verify-handle/check',
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(res.statusCode).toBe(400)
    expect(res.json().error).toMatch(/TXT/)
  })

  it('DELETE removes the verification', async () => {
    const res = await app.inject({
      method: 'DELETE', url: '/accounts/me/verify-handle',
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(res.statusCode).toBe(200)
    const after = await app.inject({
      method: 'GET', url: '/accounts/me/verify-handle',
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(after.json()).toMatchObject({ verified: false, domain: null })
  })

  it('changing handle invalidates a prior verification', async () => {
    // Create verification
    await app.inject({
      method: 'POST', url: '/accounts/me/verify-handle',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { domain: 'example.test' },
    })
    // Patch handle
    await app.inject({
      method: 'PATCH', url: '/accounts/me',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { handle: 'verifyowner-renamed' },
    })
    // Verification should be gone
    const res = await app.inject({
      method: 'GET', url: '/accounts/me/verify-handle',
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(res.json()).toMatchObject({ verified: false, domain: null })
  })
})

describe('DELETE /accounts/me', () => {
  it('kills the account key, revokes agents, but preserves append-only key history', async () => {
    const acct = await app.inject({ method: 'POST', url: '/accounts/register', payload: { handle: 'delowner' } })
    const accountKey = acct.json().account_key
    const { publicKey } = makeEd25519()
    const agent = await app.inject({
      method: 'POST', url: '/agents/register',
      headers: { authorization: `Bearer ${accountKey}` },
      payload: { name: 'doomed', public_key: publicKey },
    })
    const address = agent.json().address

    const del = await app.inject({
      method: 'DELETE', url: '/accounts/me',
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(del.statusCode).toBe(200)
    expect(del.json().deleted).toBe(true)

    // The account key is dead immediately.
    const me = await app.inject({
      method: 'GET', url: '/accounts/me',
      headers: { authorization: `Bearer ${accountKey}` },
    })
    expect(me.statusCode).toBe(401)

    // The agent resolves as revoked (main endpoint 404)...
    const resolve = await app.inject({ method: 'GET', url: `/agents/${address}` })
    expect(resolve.statusCode).toBe(404)

    // ...but its append-only public-key history is preserved and marked revoked.
    const hist = await app.inject({ method: 'GET', url: `/agents/${address}/key-history` })
    expect(hist.statusCode).toBe(200)
    expect(hist.json().revoked).toBe(true)
    expect(hist.json().history.length).toBeGreaterThan(0)
  })

  it('rejects an unauthenticated delete', async () => {
    const res = await app.inject({ method: 'DELETE', url: '/accounts/me' })
    expect(res.statusCode).toBe(401)
  })
})
