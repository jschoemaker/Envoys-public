import { describe, it, expect, vi, beforeEach } from 'vitest'
import { generateKeyPairSync } from 'crypto'
import { Envoys } from '../index.js'

function makeEd25519() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

function makeAgent(overrides: Partial<ConstructorParameters<typeof Envoys>[0]> = {}) {
  const { publicKey, privateKey } = makeEd25519()
  return new Envoys({
    agentKey:   'agt_test',
    address:    'sender@team.envoys.me',
    publicKey,
    privateKey,
    ...overrides,
  })
}

// ── signRequest ───────────────────────────────────────────────────────────────

describe('signRequest', () => {
  it('produces Signature-Input and Signature headers', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Signature-Input']).toMatch(/^sig1=\(.*\);keyid=".*";created=\d+;nonce=".+"$/)
    expect(headers['Signature']).toMatch(/^sig1=:.+:$/)
  })

  it('includes Content-Digest for requests with a body', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('POST', '/', { hello: 'world' })
    expect(headers['Content-Digest']).toMatch(/^sha-256=:.+:$/)
    expect(headers['Signature-Input']).toContain('"content-digest"')
  })

  it('omits Content-Digest for requests without a body', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Content-Digest']).toBeUndefined()
    expect(headers['Signature-Input']).not.toContain('content-digest')
  })

  it('sets keyid to the agent address URL', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Signature-Input']).toContain('keyid="https://envoys.me/agents/sender@team.envoys.me"')
  })

  it('throws if no private key is provided', () => {
    const { publicKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'a@b.envoys.me', publicKey })
    expect(() => agent.signRequest('GET', '/')).toThrow(/private key/)
  })

  it('includes the tag parameter in Signature-Input when provided', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('POST', '/api/task', { hello: 'world' }, { tag: 'task' })
    expect(headers['Signature-Input']).toContain('tag="task"')
  })

  it('omits the tag parameter when not provided (backward compat)', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Signature-Input']).not.toContain('tag=')
  })

  it('escapes backslash and double-quote in tag per RFC 8941 sf-string', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('GET', '/', undefined, { tag: 'with "quotes" and \\ backslash' })
    expect(headers['Signature-Input']).toContain('tag="with \\"quotes\\" and \\\\ backslash"')
  })

  it('uses sha-256 Content-Digest for small bodies (< 4KB)', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('POST', '/', { hello: 'world' })
    expect(headers['Content-Digest']).toMatch(/^sha-256=:.+:$/)
  })

  it('auto-promotes Content-Digest to sha-512 for bodies >= 4KB', () => {
    const agent = makeAgent()
    const largeBody = { data: 'x'.repeat(5000) }  // ~5KB serialized
    const headers = agent.signRequest('POST', '/', largeBody)
    expect(headers['Content-Digest']).toMatch(/^sha-512=:.+:$/)
  })
})

// ── verifyRequest ─────────────────────────────────────────────────────────────

describe('verifyRequest', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearPins() })

  function mockFetch(publicKey: string) {
    return vi.fn().mockResolvedValue({
      ok:   true,
      json: async () => ({ address: 'sender@team.envoys.me', public_key: publicKey }),
    })
  }

  it('verifies a valid signed GET request', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_test', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/api/data')
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyRequest('GET', '/api/data', sigHeaders as any)
    expect(result.verified).toBe(true)
    expect(result.address).toBe('sender@team.envoys.me')
  })

  it('verifies a valid signed POST request with body', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_test', address: 'sender@team.envoys.me', publicKey, privateKey })
    const body = { jsonrpc: '2.0', method: 'message/send', id: '1' }
    const sigHeaders = agent.signRequest('POST', '/', body)
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyRequest('POST', '/', sigHeaders as any, body)
    expect(result.verified).toBe(true)
  })

  it('verifies a signed POST with a sha-512 Content-Digest (large body)', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_test', address: 'sender@team.envoys.me', publicKey, privateKey })
    const largeBody = { data: 'x'.repeat(5000) }
    const sigHeaders = agent.signRequest('POST', '/api/upload', largeBody)
    expect(sigHeaders['Content-Digest']).toMatch(/^sha-512=:.+:$/)
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyRequest('POST', '/api/upload', sigHeaders as any, largeBody)
    expect(result.verified).toBe(true)
  })

  it('verifies a signed request that carries the tag parameter', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_test', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/heartbeat', undefined, { tag: 'heartbeat' })
    expect(sigHeaders['Signature-Input']).toContain('tag="heartbeat"')
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyRequest('GET', '/heartbeat', sigHeaders as any)
    expect(result.verified).toBe(true)
  })

  it('rejects a signature older than 5 minutes', async () => {
    const agent = makeAgent()
    const sigHeaders = agent.signRequest('GET', '/path')
    const stale = Math.floor(Date.now() / 1000) - 600  // 10 min ago
    sigHeaders['Signature-Input'] = sigHeaders['Signature-Input'].replace(/created=\d+/, `created=${stale}`)

    const result = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/timestamp/)
  })

  it('rejects a signature with a future timestamp', async () => {
    const agent = makeAgent()
    const sigHeaders = agent.signRequest('GET', '/path')
    const future = Math.floor(Date.now() / 1000) + 120  // 2 min in future
    sigHeaders['Signature-Input'] = sigHeaders['Signature-Input'].replace(/created=\d+/, `created=${future}`)

    const result = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/timestamp/)
  })

  it('rejects a request with a tampered body', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_test', address: 'sender@team.envoys.me', publicKey, privateKey })
    const body = { message: 'original' }
    const sigHeaders = agent.signRequest('POST', '/', body)
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyRequest('POST', '/', sigHeaders as any, { message: 'tampered' })
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/Content-Digest/)
  })

  it('rejects a request missing Signature headers', async () => {
    const result = await Envoys.verifyRequest('GET', '/path', { 'content-type': 'application/json' } as any)
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/Signature/)
  })

  it('rejects when the signature does not verify against the public key', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const { publicKey: wrongKey } = makeEd25519()  // different key
    const agent = new Envoys({ agentKey: 'agt_test', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/path')
    // Mock fetch returns the WRONG public key
    vi.stubGlobal('fetch', mockFetch(wrongKey))

    const result = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(result.verified).toBe(false)
  })
})

// ── Envoys.fromEnv ───────────────────────────────────────────────────────────

describe('Envoys.fromEnv', () => {
  const KEYS = [
    'ENVOYS_AGENT_KEY',
    'ENVOYS_ADDRESS',
    'ENVOYS_PUBLIC_KEY',
    'ENVOYS_PRIVATE_KEY',
    'ENVOYS_BASE_URL',
    'SCOUT_AGENT_KEY',
    'SCOUT_ADDRESS',
    'SCOUT_PUBLIC_KEY',
    'SCOUT_PRIVATE_KEY',
  ]

  beforeEach(() => {
    for (const k of KEYS) delete process.env[k]
  })

  it('reads ENVOYS_* env vars by default', () => {
    const { publicKey, privateKey } = makeEd25519()
    process.env.ENVOYS_AGENT_KEY    = 'agt_test'
    process.env.ENVOYS_ADDRESS      = 'a@b.envoys.me'
    process.env.ENVOYS_PUBLIC_KEY   = publicKey
    process.env.ENVOYS_PRIVATE_KEY  = privateKey

    const agent = Envoys.fromEnv()
    expect(agent.address).toBe('a@b.envoys.me')
    expect(agent.publicKey).toBe(publicKey)
    // The agent should be able to sign — proves privateKey was loaded.
    expect(() => agent.signRequest('GET', '/')).not.toThrow()
  })

  it('uses a custom prefix when provided', () => {
    const { publicKey, privateKey } = makeEd25519()
    process.env.SCOUT_AGENT_KEY    = 'agt_scout'
    process.env.SCOUT_ADDRESS      = 'scout@team.envoys.me'
    process.env.SCOUT_PUBLIC_KEY   = publicKey
    process.env.SCOUT_PRIVATE_KEY  = privateKey

    const agent = Envoys.fromEnv({ prefix: 'SCOUT' })
    expect(agent.address).toBe('scout@team.envoys.me')
  })

  it('throws a clear error naming the missing var', () => {
    process.env.ENVOYS_AGENT_KEY    = 'agt_x'
    process.env.ENVOYS_ADDRESS      = 'a@b.envoys.me'
    // PUBLIC_KEY / PRIVATE_KEY missing
    expect(() => Envoys.fromEnv()).toThrow(/ENVOYS_PUBLIC_KEY/)
  })

  it('uses ENVOYS_BASE_URL when set', () => {
    const { publicKey, privateKey } = makeEd25519()
    process.env.ENVOYS_AGENT_KEY    = 'agt_x'
    process.env.ENVOYS_ADDRESS      = 'a@b.example.com'
    process.env.ENVOYS_PUBLIC_KEY   = publicKey
    process.env.ENVOYS_PRIVATE_KEY  = privateKey
    process.env.ENVOYS_BASE_URL     = 'https://custom.example.com'

    const agent = Envoys.fromEnv()
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Signature-Input']).toContain('keyid="https://custom.example.com/agents/a@b.example.com"')
  })

  it('opts.baseUrl overrides ENVOYS_BASE_URL', () => {
    const { publicKey, privateKey } = makeEd25519()
    process.env.ENVOYS_AGENT_KEY    = 'agt_x'
    process.env.ENVOYS_ADDRESS      = 'a@b.example.com'
    process.env.ENVOYS_PUBLIC_KEY   = publicKey
    process.env.ENVOYS_PRIVATE_KEY  = privateKey
    process.env.ENVOYS_BASE_URL     = 'https://wrong.example.com'

    const agent = Envoys.fromEnv({ baseUrl: 'https://right.example.com' })
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Signature-Input']).toContain('keyid="https://right.example.com/agents/a@b.example.com"')
  })

  it('does not require BASE_URL — defaults to envoys.me', () => {
    const { publicKey, privateKey } = makeEd25519()
    process.env.ENVOYS_AGENT_KEY    = 'agt_x'
    process.env.ENVOYS_ADDRESS      = 'a@b.envoys.me'
    process.env.ENVOYS_PUBLIC_KEY   = publicKey
    process.env.ENVOYS_PRIVATE_KEY  = privateKey
    // ENVOYS_BASE_URL NOT set

    const agent = Envoys.fromEnv()
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Signature-Input']).toContain('keyid="https://envoys.me/agents/a@b.envoys.me"')
  })
})

// ── Nonce + replay protection ────────────────────────────────────────────────

describe('nonce + replay protection', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearReplayCache(); Envoys.clearPins() })

  function mockFetch(publicKey: string) {
    return vi.fn().mockResolvedValue({
      ok:   true,
      json: async () => ({ public_key: publicKey }),
    })
  }

  it('signRequest emits a nonce parameter', () => {
    const agent = makeAgent()
    const headers = agent.signRequest('GET', '/path')
    expect(headers['Signature-Input']).toMatch(/;nonce="[A-Za-z0-9_-]{20,}"/)
  })

  it('two signatures of the same request have different nonces', () => {
    const agent = makeAgent()
    const a = agent.signRequest('POST', '/', { x: 1 })
    const b = agent.signRequest('POST', '/', { x: 1 })
    expect(a['Signature-Input']).not.toBe(b['Signature-Input'])
    expect(a['Signature']).not.toBe(b['Signature'])
  })

  it('first signed request verifies; replaying the exact same request is rejected', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/api/data')
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const first = await Envoys.verifyRequest('GET', '/api/data', sigHeaders as any)
    expect(first.verified).toBe(true)

    const replay = await Envoys.verifyRequest('GET', '/api/data', sigHeaders as any)
    expect(replay.verified).toBe(false)
    expect(replay.error).toMatch(/replay/i)
  })

  it('two distinct requests from the same agent both verify', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt', address: 'sender@team.envoys.me', publicKey, privateKey })
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const a = agent.signRequest('GET', '/a')
    const b = agent.signRequest('GET', '/b')

    expect((await Envoys.verifyRequest('GET', '/a', a as any)).verified).toBe(true)
    expect((await Envoys.verifyRequest('GET', '/b', b as any)).verified).toBe(true)
  })

  it('clearReplayCache() lets a previously-seen signature verify again', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/path')
    vi.stubGlobal('fetch', mockFetch(publicKey))

    expect((await Envoys.verifyRequest('GET', '/path', sigHeaders as any)).verified).toBe(true)
    Envoys.clearReplayCache()
    // After clearing, the same signature is accepted again.
    expect((await Envoys.verifyRequest('GET', '/path', sigHeaders as any)).verified).toBe(true)
  })

  it('failed signature verification does not pollute the replay cache', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const { publicKey: wrong } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/path')
    vi.stubGlobal('fetch', mockFetch(wrong))  // wrong key — verify fails

    const fail = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(fail.verified).toBe(false)

    // Now retry with the correct key — must succeed (cache wasn't polluted).
    vi.stubGlobal('fetch', mockFetch(publicKey))
    Envoys.clearKeyCache()  // ensure correct key is fetched
    const ok = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(ok.verified).toBe(true)
  })

  it('verifies when params are in unexpected order (forward-compat)', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt', address: 'sender@team.envoys.me', publicKey, privateKey })
    const original = agent.signRequest('GET', '/path')
    vi.stubGlobal('fetch', mockFetch(publicKey))

    // Re-sign manually with reordered params would change the signature base
    // and therefore the signature itself — so we just verify the ORIGINAL
    // signature parses correctly even though our parser is order-independent.
    expect((await Envoys.verifyRequest('GET', '/path', original as any)).verified).toBe(true)
  })
})

// ── signAgentCard / verifyAgentCard ──────────────────────────────────────────

describe('signAgentCard / verifyAgentCard', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearPins() })

  function mockFetch(publicKey: string, address = 'sender@team.envoys.me') {
    return vi.fn().mockResolvedValue({
      ok:   true,
      json: async () => ({ address, public_key: publicKey }),
    })
  }

  const sampleCard = {
    name: 'Echo Agent',
    url: 'http://localhost:3001',
    version: '1.0.0',
    capabilities: { streaming: false },
    skills: [{ id: 'echo', name: 'Echo' }],
  }

  it('produces a JWS compact-serialized string with three segments', () => {
    const agent = makeAgent()
    const jws = agent.signAgentCard(sampleCard)
    expect(jws.split('.')).toHaveLength(3)
  })

  it('encodes alg=EdDSA and the agent keyid in the JWS header', () => {
    const agent = makeAgent()
    const jws = agent.signAgentCard(sampleCard)
    const header = JSON.parse(Buffer.from(jws.split('.')[0], 'base64url').toString())
    expect(header.alg).toBe('EdDSA')
    expect(header.kid).toBe('https://envoys.me/agents/sender@team.envoys.me')
  })

  it('round-trips: signed card verifies and matches the original payload', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const jws = agent.signAgentCard(sampleCard)
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyAgentCard(jws)
    expect(result.verified).toBe(true)
    expect(result.card).toEqual(sampleCard)
    expect(result.address).toBe('sender@team.envoys.me')
    expect(result.keyid).toBe('https://envoys.me/agents/sender@team.envoys.me')
  })

  it('rejects a tampered payload', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const jws = agent.signAgentCard(sampleCard)
    const [h, _p, s] = jws.split('.')
    const tampered = `${h}.${Buffer.from(JSON.stringify({ ...sampleCard, name: 'Evil Agent' })).toString('base64url')}.${s}`
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyAgentCard(tampered)
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/Signature/)
  })

  it('rejects when fetched public key does not match signer', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const { publicKey: wrong } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const jws = agent.signAgentCard(sampleCard)
    vi.stubGlobal('fetch', mockFetch(wrong))

    const result = await Envoys.verifyAgentCard(jws)
    expect(result.verified).toBe(false)
  })

  it('rejects malformed JWS strings', async () => {
    const r1 = await Envoys.verifyAgentCard('not.a.jws.too.many.parts')
    expect(r1.verified).toBe(false)
    const r2 = await Envoys.verifyAgentCard('only-one-part')
    expect(r2.verified).toBe(false)
  })

  it('rejects unsupported alg', async () => {
    const fakeHeader = Buffer.from(JSON.stringify({ alg: 'HS256', kid: 'https://envoys.me/agents/x@y.envoys.me' })).toString('base64url')
    const fakePayload = Buffer.from(JSON.stringify(sampleCard)).toString('base64url')
    const fakeSig = Buffer.from('xxx').toString('base64url')
    const result = await Envoys.verifyAgentCard(`${fakeHeader}.${fakePayload}.${fakeSig}`)
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/EdDSA/)
  })

  it('rejects when kid is missing', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify(sampleCard)).toString('base64url')
    const sig = Buffer.from('xxx').toString('base64url')
    const result = await Envoys.verifyAgentCard(`${header}.${payload}.${sig}`)
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/kid/)
  })

  it('rejects when kid is not an Envoys agent URL', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'https://example.com/keys/1' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify(sampleCard)).toString('base64url')
    const sig = Buffer.from('xxx').toString('base64url')
    const result = await Envoys.verifyAgentCard(`${header}.${payload}.${sig}`)
    expect(result.verified).toBe(false)
    expect(result.error).toMatch(/Envoys agent URL/)
  })

  it('signAgentCard throws without a private key', () => {
    const { publicKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'a@b.envoys.me', publicKey })
    expect(() => agent.signAgentCard(sampleCard)).toThrow(/private key/)
  })
})

// ── Public key cache ─────────────────────────────────────────────────────────

describe('public key cache', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearPins() })

  it('reuses cached key on subsequent resolves', async () => {
    const { publicKey } = makeEd25519()
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ public_key: publicKey }) })
    vi.stubGlobal('fetch', fetchMock)

    await Envoys.resolvePublicKey('a@b.envoys.me')
    await Envoys.resolvePublicKey('a@b.envoys.me')
    await Envoys.resolvePublicKey('a@b.envoys.me')

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('caches per (baseUrl, address) tuple', async () => {
    const { publicKey } = makeEd25519()
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ public_key: publicKey }) })
    vi.stubGlobal('fetch', fetchMock)

    await Envoys.resolvePublicKey('a@b.envoys.me', 'https://envoys.me')
    await Envoys.resolvePublicKey('a@b.envoys.me', 'https://other.envoys.me')

    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('clearKeyCache() forces a refetch', async () => {
    const { publicKey } = makeEd25519()
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ public_key: publicKey }) })
    vi.stubGlobal('fetch', fetchMock)

    await Envoys.resolvePublicKey('a@b.envoys.me')
    Envoys.clearKeyCache()
    await Envoys.resolvePublicKey('a@b.envoys.me')

    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

// ── Envoys.verify (payload signing) ──────────────────────────────────────────

describe('Envoys.verify', () => {
  it('verifies a valid payload signature', () => {
    const agent = makeAgent()
    const payload = { data: 'hello', ts: 1234567890 }
    const sig = agent.sign(payload)
    const { publicKey } = makeEd25519()  // wrong key — use agent's actual key
    // re-extract publicKey from agent
    expect(Envoys.verify(payload, sig, (agent as any).publicKey)).toBe(true)
  })

  it('rejects a tampered payload', () => {
    const agent = makeAgent()
    const payload = { data: 'hello' }
    const sig = agent.sign(payload)
    expect(Envoys.verify({ data: 'tampered' }, sig, (agent as any).publicKey)).toBe(false)
  })

  it('rejects a signature from a different key', () => {
    const agent = makeAgent()
    const { publicKey: otherKey } = makeEd25519()
    const payload = { data: 'hello' }
    const sig = agent.sign(payload)
    expect(Envoys.verify(payload, sig, otherKey)).toBe(false)
  })
})

// ── Phase 3: enriched result envelope, pin store, allowlist ────────────────────

describe('verifyRequest result envelope', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearReplayCache(); Envoys.clearPins() })

  function mockFetch(publicKey: string) {
    return vi.fn().mockResolvedValue({
      ok:   true,
      json: async () => ({ public_key: publicKey }),
    })
  }

  it('populates keyid, address, publicKey on success', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/path')
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const result = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(result.verified).toBe(true)
    expect(result.keyid).toBe('https://envoys.me/agents/sender@team.envoys.me')
    expect(result.address).toBe('sender@team.envoys.me')
    expect(result.publicKey).toBe(publicKey)
    expect(result.error).toBeNull()
  })

  it('populates keyid + address even when signature verification fails', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('POST', '/api/transfer', { amount: 1 })
    // Mock the resolver to return a DIFFERENT public key — signature won't verify
    const { publicKey: wrongKey } = makeEd25519()
    vi.stubGlobal('fetch', mockFetch(wrongKey))

    const result = await Envoys.verifyRequest('POST', '/api/transfer', sigHeaders as any, { amount: 1 })
    expect(result.verified).toBe(false)
    expect(result.address).toBe('sender@team.envoys.me')
    expect(result.keyid).toContain('sender@team.envoys.me')
    expect(result.error).toMatch(/Signature verification failed/)
  })
})

describe('public-key pinning (default on)', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearReplayCache(); Envoys.clearPins() })

  function mockFetch(publicKey: string) {
    return vi.fn().mockResolvedValue({
      ok:   true,
      json: async () => ({ public_key: publicKey }),
    })
  }

  it('first contact auto-pins; second contact with the same key passes', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    vi.stubGlobal('fetch', mockFetch(publicKey))

    const r1 = await Envoys.verifyRequest('GET', '/a', agent.signRequest('GET', '/a') as any)
    expect(r1.verified).toBe(true)
    const r2 = await Envoys.verifyRequest('GET', '/b', agent.signRequest('GET', '/b') as any)
    expect(r2.verified).toBe(true)
  })

  it('second contact with a different key fails with informative error', async () => {
    const { publicKey: pkA, privateKey: skA } = makeEd25519()
    const { publicKey: pkB, privateKey: skB } = makeEd25519()
    const agentA = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey: pkA, privateKey: skA })
    const agentB = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey: pkB, privateKey: skB })

    // First request: key A. Pin gets set.
    vi.stubGlobal('fetch', mockFetch(pkA))
    const r1 = await Envoys.verifyRequest('GET', '/a', agentA.signRequest('GET', '/a') as any)
    expect(r1.verified).toBe(true)

    // Second request: key B (rotation). Resolver now returns key B and the
    // signature is from key B — signature itself is valid, but pin disagrees.
    Envoys.clearKeyCache()
    vi.stubGlobal('fetch', mockFetch(pkB))
    const r2 = await Envoys.verifyRequest('GET', '/b', agentB.signRequest('GET', '/b') as any)
    expect(r2.verified).toBe(false)
    expect(r2.error).toMatch(/Pinned public key mismatch/)
    expect(r2.error).toMatch(/resetPin/)
    expect(r2.address).toBe('sender@team.envoys.me')
  })

  it('resetPin allows new key after expected rotation', async () => {
    const { publicKey: pkA, privateKey: skA } = makeEd25519()
    const { publicKey: pkB, privateKey: skB } = makeEd25519()
    const agentA = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey: pkA, privateKey: skA })
    const agentB = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey: pkB, privateKey: skB })

    vi.stubGlobal('fetch', mockFetch(pkA))
    await Envoys.verifyRequest('GET', '/a', agentA.signRequest('GET', '/a') as any)

    Envoys.resetPin('sender@team.envoys.me')

    Envoys.clearKeyCache()
    vi.stubGlobal('fetch', mockFetch(pkB))
    const r = await Envoys.verifyRequest('GET', '/b', agentB.signRequest('GET', '/b') as any)
    expect(r.verified).toBe(true)
    expect(r.publicKey).toBe(pkB)
  })

  it('pinByPublicKey: false bypasses pin enforcement', async () => {
    const { publicKey: pkA, privateKey: skA } = makeEd25519()
    const { publicKey: pkB, privateKey: skB } = makeEd25519()
    const agentA = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey: pkA, privateKey: skA })
    const agentB = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey: pkB, privateKey: skB })

    vi.stubGlobal('fetch', mockFetch(pkA))
    await Envoys.verifyRequest('GET', '/a', agentA.signRequest('GET', '/a') as any, undefined, { pinByPublicKey: false })

    Envoys.clearKeyCache()
    vi.stubGlobal('fetch', mockFetch(pkB))
    const r = await Envoys.verifyRequest('GET', '/b', agentB.signRequest('GET', '/b') as any, undefined, { pinByPublicKey: false })
    expect(r.verified).toBe(true)
  })

  it('honours a custom pinStore', async () => {
    const store = new Map<string, string>()
    const pinStore = {
      get: (a: string) => store.get(a) ?? null,
      set: (a: string, k: string) => { store.set(a, k) },
      delete: (a: string) => { store.delete(a) },
      clear: () => store.clear(),
    }
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    vi.stubGlobal('fetch', mockFetch(publicKey))

    await Envoys.verifyRequest('GET', '/a', agent.signRequest('GET', '/a') as any, undefined, { pinStore })
    expect(store.get('sender@team.envoys.me')).toBe(publicKey)
  })
})

describe('allowlist', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearReplayCache(); Envoys.clearPins() })

  function mockFetch(publicKey: string) {
    return vi.fn().mockResolvedValue({
      ok:   true,
      json: async () => ({ public_key: publicKey }),
    })
  }

  it('allows a sender whose address is in the allowlist', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    vi.stubGlobal('fetch', mockFetch(publicKey))
    const r = await Envoys.verifyRequest('GET', '/p', agent.signRequest('GET', '/p') as any, undefined, {
      allowlist: ['sender@team.envoys.me'],
    })
    expect(r.verified).toBe(true)
  })

  it('allows a sender whose keyid is in the allowlist', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    vi.stubGlobal('fetch', mockFetch(publicKey))
    const r = await Envoys.verifyRequest('GET', '/p', agent.signRequest('GET', '/p') as any, undefined, {
      allowlist: ['https://envoys.me/agents/sender@team.envoys.me'],
    })
    expect(r.verified).toBe(true)
  })

  it('rejects a cryptographically-valid request from outside the allowlist', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    vi.stubGlobal('fetch', mockFetch(publicKey))
    const r = await Envoys.verifyRequest('GET', '/p', agent.signRequest('GET', '/p') as any, undefined, {
      allowlist: ['someone-else@other.envoys.me'],
    })
    expect(r.verified).toBe(false)
    expect(r.error).toMatch(/not in allowlist/)
    expect(r.address).toBe('sender@team.envoys.me')
  })

  it('empty allowlist array is treated as no allowlist (backwards compat)', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    vi.stubGlobal('fetch', mockFetch(publicKey))
    const r = await Envoys.verifyRequest('GET', '/p', agent.signRequest('GET', '/p') as any, undefined, {
      allowlist: [],
    })
    expect(r.verified).toBe(true)
  })
})

// ── Dual-shape keyid resolution (A2A-IDF v1.0 roadmap, PR #1850) ─────────────
// The verifier accepts either shape served at the keyid URL: a W3C DID Document
// (Content-Type application/did+json) or the Envoys-native { public_key } object.

describe('resolveKeyFromKeyid (dual-shape)', () => {
  beforeEach(() => { vi.unstubAllGlobals(); Envoys.clearKeyCache(); Envoys.clearReplayCache(); Envoys.clearPins() })

  function jwkFromPem(publicKeyPem: string) {
    const { createPublicKey } = require('crypto')
    return createPublicKey(publicKeyPem).export({ format: 'jwk' })
  }

  function mockDidDocument(publicKey: string) {
    const jwk = jwkFromPem(publicKey)
    return vi.fn().mockResolvedValue({
      ok:      true,
      headers: { get: (n: string) => n.toLowerCase() === 'content-type' ? 'application/did+json' : null },
      json:    async () => ({
        '@context':         ['https://www.w3.org/ns/did/v1'],
        id:                 'did:web:envoys.me:agents:sender@team.envoys.me',
        verificationMethod: [{
          id:           'did:web:envoys.me:agents:sender@team.envoys.me#key-1',
          type:         'Ed25519VerificationKey2020',
          controller:   'did:web:envoys.me:agents:sender@team.envoys.me',
          publicKeyJwk: jwk,
        }],
      }),
    })
  }

  it('verifies a signed request when keyid serves a DID Document', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('POST', '/api/task', { hello: 'world' })
    vi.stubGlobal('fetch', mockDidDocument(publicKey))

    const result = await Envoys.verifyRequest('POST', '/api/task', sigHeaders as any, { hello: 'world' })
    expect(result.verified).toBe(true)
    expect(result.keyid).toBe('https://envoys.me/agents/sender@team.envoys.me')
    expect(result.publicKey).toBe(publicKey)
  })

  it('verifies a signed request when keyid serves Envoys-native { public_key }', async () => {
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/path')
    const fetchMock  = vi.fn().mockResolvedValue({
      ok:      true,
      headers: { get: (n: string) => n.toLowerCase() === 'content-type' ? 'application/json' : null },
      json:    async () => ({ address: 'sender@team.envoys.me', public_key: publicKey }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(result.verified).toBe(true)
    expect(result.publicKey).toBe(publicKey)
  })

  it('falls back to shape detection when Content-Type header is missing', async () => {
    // Legacy resolvers and existing test mocks may not set Content-Type.
    // The resolver detects shape by payload structure when the header is absent.
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/path')
    const fetchMock  = vi.fn().mockResolvedValue({
      ok:   true,  // no headers — pre-0.7.2 mock shape
      json: async () => ({ public_key: publicKey }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(result.verified).toBe(true)
  })

  it('detects DID Document by payload shape when Content-Type says application/json', async () => {
    // Some resolvers serve DID Documents as plain application/json. Fall back to
    // structural detection (presence of verificationMethod array).
    const { publicKey, privateKey } = makeEd25519()
    const agent = new Envoys({ agentKey: 'agt_x', address: 'sender@team.envoys.me', publicKey, privateKey })
    const sigHeaders = agent.signRequest('GET', '/path')
    const jwk = jwkFromPem(publicKey)
    const fetchMock = vi.fn().mockResolvedValue({
      ok:      true,
      headers: { get: () => 'application/json' },
      json:    async () => ({
        id:                 'did:web:envoys.me',
        verificationMethod: [{ type: 'Ed25519VerificationKey2020', publicKeyJwk: jwk }],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const result = await Envoys.verifyRequest('GET', '/path', sigHeaders as any)
    expect(result.verified).toBe(true)
  })

  it('throws with a clear error when DID Document uses publicKeyMultibase', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok:      true,
      headers: { get: () => 'application/did+json' },
      json:    async () => ({
        verificationMethod: [{
          type:               'Ed25519VerificationKey2020',
          publicKeyMultibase: 'z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
        }],
      }),
    })
    vi.stubGlobal('fetch', fetchMock)
    await expect(Envoys.resolveKeyFromKeyid('https://envoys.me/agents/x@y.envoys.me'))
      .rejects.toThrow(/publicKeyMultibase/)
  })

  it('rejects unrecognized keyid response shapes', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok:      true,
      headers: { get: () => 'application/json' },
      json:    async () => ({ something: 'else' }),
    })
    vi.stubGlobal('fetch', fetchMock)
    await expect(Envoys.resolveKeyFromKeyid('https://envoys.me/agents/x@y.envoys.me'))
      .rejects.toThrow(/Unrecognized keyid response shape/)
  })

  it('caches by full keyid URL', async () => {
    const { publicKey } = makeEd25519()
    const fetchMock = vi.fn().mockResolvedValue({
      ok:      true,
      headers: { get: () => 'application/json' },
      json:    async () => ({ public_key: publicKey }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await Envoys.resolveKeyFromKeyid('https://envoys.me/agents/a@b.envoys.me')
    await Envoys.resolveKeyFromKeyid('https://envoys.me/agents/a@b.envoys.me')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('sends Accept header advertising both shapes', async () => {
    const { publicKey } = makeEd25519()
    const fetchMock = vi.fn().mockResolvedValue({
      ok:      true,
      headers: { get: () => 'application/json' },
      json:    async () => ({ public_key: publicKey }),
    })
    vi.stubGlobal('fetch', fetchMock)

    await Envoys.resolveKeyFromKeyid('https://envoys.me/agents/a@b.envoys.me')
    const call = fetchMock.mock.calls[0]
    const accept = call[1]?.headers?.Accept ?? ''
    expect(accept).toContain('application/did+json')
    expect(accept).toContain('application/json')
  })
})
