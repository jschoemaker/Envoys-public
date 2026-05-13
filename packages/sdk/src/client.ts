import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign, verify as cryptoVerify, createHash } from 'crypto'
import type {
  EnvoysConfig,
  RegisterOptions,
  RegisterResult,
  KeySyncResult,
  VerifyAgentCardResult,
  VerifyRequestResult,
  VerifyRequestOptions,
  PinStore,
} from './types.js'

const DEFAULT_BASE_URL    = 'https://envoys.me'
const KEY_CACHE_TTL_MS    = 5 * 60 * 1000
const REPLAY_CACHE_TTL_MS = 5 * 60 * 1000  // matches signature timestamp window

const keyCache    = new Map<string, { key: string; expires: number }>()
const replayCache = new Map<string, number>()  // signature key → expires_at

// Default in-process pin store. Map-based, fast, and lost on process restart —
// fine for stateless services, but persistent verifiers should pass a custom
// pinStore that writes to disk/Redis/whatever survives a deploy.
const defaultPinStore: PinStore = (() => {
  const m = new Map<string, string>()
  return {
    get(address)   { return m.get(address) ?? null },
    set(address, publicKey) { m.set(address, publicKey) },
    delete(address) { m.delete(address) },
    clear() { m.clear() },
  }
})()

// Probabilistic GC — sweep expired entries every ~100th call.
function maybeSweepReplayCache() {
  if (Math.random() > 0.01) return
  const now = Date.now()
  for (const [k, v] of replayCache) {
    if (v < now) replayCache.delete(k)
  }
}

function b64url(buf: Buffer): string {
  return buf.toString('base64url')
}

function fromB64url(s: string): Buffer {
  return Buffer.from(s, 'base64url')
}

// Extract the first Ed25519 public key from a W3C DID Document and return it
// as PEM SPKI. Supports publicKeyJwk (OKP/Ed25519) — the form Envoys' own
// did:web export uses and the most standardized across DID resolvers. Other
// encodings (publicKeyMultibase, publicKeyBase58) surface a clear error so
// the caller knows which format was found.
function extractEd25519FromDidDocument(doc: any, sourceUrl: string): string {
  const methods: Array<{
    type?: string
    publicKeyJwk?: { kty?: string; crv?: string; x?: string }
    publicKeyMultibase?: string
    publicKeyBase58?: string
  }> = doc?.verificationMethod ?? []

  const ed = methods.find(m =>
    typeof m.type === 'string' && m.type.startsWith('Ed25519') &&
    m.publicKeyJwk?.kty === 'OKP' &&
    m.publicKeyJwk?.crv === 'Ed25519'
  )

  if (!ed) {
    const fallback = methods.find(m => typeof m.type === 'string' && m.type.startsWith('Ed25519'))
    if (fallback?.publicKeyMultibase) {
      throw new Error(`DID Document at ${sourceUrl} uses publicKeyMultibase; currently supports publicKeyJwk only`)
    }
    if (fallback?.publicKeyBase58) {
      throw new Error(`DID Document at ${sourceUrl} uses publicKeyBase58; currently supports publicKeyJwk only`)
    }
    throw new Error(`No Ed25519 verification method with publicKeyJwk found in DID Document at ${sourceUrl}`)
  }

  const keyObj = createPublicKey({ key: ed.publicKeyJwk!, format: 'jwk' })
  return keyObj.export({ format: 'pem', type: 'spki' }) as string
}

export class Envoys {
  readonly address: string
  readonly publicKey: string
  private agentKey: string
  private privateKey: string | undefined
  private readonly baseUrl: string

  constructor(config: EnvoysConfig) {
    this.agentKey   = config.agentKey
    this.address    = config.address
    this.publicKey  = config.publicKey
    this.privateKey = config.privateKey
    this.baseUrl    = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '')
  }

  // ── Construction from environment ─────────────────────────────────────────
  // Reads agent credentials from process.env. By default looks for:
  //   ENVOYS_AGENT_KEY, ENVOYS_ADDRESS, ENVOYS_PUBLIC_KEY, ENVOYS_PRIVATE_KEY
  //   ENVOYS_BASE_URL (optional)
  //
  // Set `prefix` to swap the namespace when running multiple agents in one
  // process — e.g. fromEnv({ prefix: 'SCOUT' }) reads SCOUT_AGENT_KEY etc.
  static fromEnv(opts: { prefix?: string; baseUrl?: string } = {}): Envoys {
    const prefix = opts.prefix ?? 'ENVOYS'
    const get = (suffix: string, required = true): string | undefined => {
      const name  = `${prefix}_${suffix}`
      const value = process.env[name]
      if (!value && required) {
        throw new Error(`Envoys.fromEnv: missing required env var ${name}`)
      }
      return value
    }

    return new Envoys({
      agentKey:   get('AGENT_KEY')!,
      address:    get('ADDRESS')!,
      publicKey:  get('PUBLIC_KEY')!,
      privateKey: get('PRIVATE_KEY')!,
      baseUrl:    opts.baseUrl ?? get('BASE_URL', false),
    })
  }

  // ── Registration (one-time setup) ─────────────────────────────────────────
  // Generates an Ed25519 keypair locally, registers with Envoys, and returns a
  // ready-to-use client. The private key never leaves this process.
  // Store result.agentKey, result.privateKey, result.publicKey, and result.address.
  static async register(opts: RegisterOptions): Promise<{ client: Envoys; result: RegisterResult }> {
    const baseUrl = (opts.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, '')

    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding:  { type: 'spki',  format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    })

    const res = await fetch(`${baseUrl}/agents/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${opts.accountKey}`,
      },
      body: JSON.stringify({ name: opts.name, public_key: publicKey, capabilities: opts.capabilities ?? [] }),
    })

    if (!res.ok) {
      const err = await res.json() as any
      throw new Error(`Registration failed: ${err.error}`)
    }

    const raw = await res.json() as any
    const result: RegisterResult = {
      id:         raw.id,
      address:    raw.address,
      agentKey:   raw.agent_key,
      publicKey,
      privateKey,
    }

    const client = new Envoys({
      agentKey:   result.agentKey,
      address:    result.address,
      publicKey:  result.publicKey,
      privateKey: result.privateKey,
      baseUrl,
    })
    return { client, result }
  }

  // ── Key management ────────────────────────────────────────────────────────
  // Call on every startup. If a rotation has been requested, generates a new keypair
  // locally, confirms with the server, and returns the new keys for the caller to persist.
  // The private key never leaves this process.
  async syncKeys(): Promise<KeySyncResult> {
    const raw = await this.request('GET', '/agent/keys')

    if (raw.rotation_requested) {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
        publicKeyEncoding:  { type: 'spki',  format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      })
      await this.request('POST', '/agent/rotate-keys', { new_public_key: publicKey })
      this.privateKey = privateKey
      return { rotated: true, publicKey, privateKey }
    }

    return { rotated: false, publicKey: raw.public_key }
  }

  // ── Payload signing ───────────────────────────────────────────────────────
  // Sign an arbitrary JSON payload with your Ed25519 private key.
  // Returns a base64 signature the recipient can verify with your public key.
  sign(payload: object): string {
    if (!this.privateKey) throw new Error('No private key — provide privateKey in EnvoysConfig')
    const key  = createPrivateKey(this.privateKey)
    const data = Buffer.from(JSON.stringify(payload))
    return cryptoSign(null, data, key).toString('base64')
  }

  // ── HTTP request signing (RFC 9421) ───────────────────────────────────────
  // Returns headers to attach to an outgoing HTTP request.
  // keyid is automatically your resolvable address URL — recipients resolve it to verify.
  //
  // Usage:
  //   const sigHeaders = agent.signRequest('POST', '/some/path', body)
  //   fetch(url, { method: 'POST', headers: { ...sigHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  //
  // Options:
  //   tag — RFC 9421 §2.3 sf-string parameter that disambiguates signing
  //         purpose (e.g. "task", "heartbeat", "delegation") under the same
  //         keyid. Optional; verifiers MAY use it to enforce signing-context
  //         expectations. Absent tag is equivalent to tag="a2a-message" for
  //         downstream compatibility.
  signRequest(method: string, path: string, body?: object, opts?: { tag?: string }): Record<string, string> {
    if (!this.privateKey) throw new Error('No private key — provide privateKey in EnvoysConfig')

    const keyid      = `${this.baseUrl}/agents/${this.address}`
    const created    = Math.floor(Date.now() / 1000)
    const nonce      = randomBytes(16).toString('base64url')  // 22-char unique tag
    const components = ['"@method"', '"@path"']
    const headers: Record<string, string> = {}

    let sigBase = `"@method": ${method.toUpperCase()}\n"@path": ${path}\n`

    if (body !== undefined) {
      const bodyBuf = Buffer.from(JSON.stringify(body))
      // RFC 9530 / spec §6: SHA-256 by default, auto-promote to SHA-512 for
      // bodies >= 4KB. Larger bodies benefit from the wider digest; smaller
      // bodies stay light. Receivers MUST accept both algorithms (see verify).
      const useSha512 = bodyBuf.length >= 4096
      const algoNode  = useSha512 ? 'sha512' : 'sha256'
      const algoHdr   = useSha512 ? 'sha-512' : 'sha-256'
      const digest    = createHash(algoNode).update(bodyBuf).digest('base64')
      headers['Content-Digest'] = `${algoHdr}=:${digest}:`
      components.push('"content-digest"')
      sigBase += `"content-digest": ${algoHdr}=:${digest}:\n`
    }

    let params = `;keyid="${keyid}";created=${created};nonce="${nonce}"`
    if (opts?.tag) {
      // RFC 9421 §2.3 sf-string: escape backslash and DQUOTE per RFC 8941.
      const escapedTag = opts.tag.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
      params += `;tag="${escapedTag}"`
    }
    sigBase += `"@signature-params": (${components.join(' ')})${params}`

    const key = createPrivateKey(this.privateKey)
    const sig = cryptoSign(null, Buffer.from(sigBase), key).toString('base64')

    headers['Signature-Input'] = `sig1=(${components.join(' ')})${params}`
    headers['Signature']       = `sig1=:${sig}:`
    return headers
  }

  // ── Agent Card signing (JWS Compact, RFC 7515 + RFC 8037 EdDSA) ──────────
  // Signs a JSON Agent Card (e.g. /.well-known/agent.json) so recipients can
  // verify it hasn't been tampered with. The kid header is your resolvable
  // address URL — verifiers fetch it to get the public key.
  //
  // Returns a JWS compact string: header.payload.signature
  signAgentCard(card: object): string {
    if (!this.privateKey) throw new Error('No private key — provide privateKey in EnvoysConfig')
    const keyid       = `${this.baseUrl}/agents/${this.address}`
    const headerJson  = JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid: keyid })
    const headerB64   = b64url(Buffer.from(headerJson))
    const payloadB64  = b64url(Buffer.from(JSON.stringify(card)))
    const signingIn   = `${headerB64}.${payloadB64}`
    const key         = createPrivateKey(this.privateKey)
    const sig         = b64url(cryptoSign(null, Buffer.from(signingIn), key))
    return `${headerB64}.${payloadB64}.${sig}`
  }

  // Verify a JWS-signed Agent Card. Resolves the kid URL to fetch the issuer's
  // public key, verifies the signature, and returns the parsed card.
  static async verifyAgentCard(jws: string): Promise<VerifyAgentCardResult> {
    try {
      const parts = jws.split('.')
      if (parts.length !== 3) return { verified: false, error: 'Malformed JWS — expected 3 segments' }
      const [headerB64, payloadB64, sigB64] = parts

      let header: any
      try { header = JSON.parse(fromB64url(headerB64).toString()) }
      catch { return { verified: false, error: 'Malformed JWS header' } }

      if (header.alg !== 'EdDSA') return { verified: false, error: `Unsupported alg "${header.alg}" — expected EdDSA` }
      if (typeof header.kid !== 'string') return { verified: false, error: 'Missing or invalid kid header' }

      const keyid     = header.kid as string
      const agentsIdx = keyid.indexOf('/agents/')
      if (agentsIdx === -1) return { verified: false, keyid, error: 'kid is not an Envoys agent URL' }
      const address   = keyid.slice(agentsIdx + '/agents/'.length)
      const keyidBase = keyid.slice(0, agentsIdx)

      const publicKeyPem = await Envoys.resolveKeyFromKeyid(keyid)
      const key = createPublicKey(publicKeyPem)
      const ok  = cryptoVerify(null, Buffer.from(`${headerB64}.${payloadB64}`), key, fromB64url(sigB64))
      if (!ok) return { verified: false, keyid, address, error: 'Signature verification failed' }

      let card: any
      try { card = JSON.parse(fromB64url(payloadB64).toString()) }
      catch { return { verified: false, keyid, address, error: 'Malformed JWS payload' } }

      return { verified: true, card, keyid, address }
    } catch (err: any) {
      return { verified: false, error: err?.message ?? 'Verification error' }
    }
  }

  // ── Verification ──────────────────────────────────────────────────────────
  // Verify a payload signature against a known Ed25519 public key (PEM SPKI).
  static verify(payload: object, signature: string, publicKey: string): boolean {
    try {
      const key  = createPublicKey(publicKey)
      const data = Buffer.from(JSON.stringify(payload))
      return cryptoVerify(null, data, key, Buffer.from(signature, 'base64'))
    } catch {
      return false
    }
  }

  // Verify an incoming RFC 9421-signed HTTP request.
  //
  // Returns a {verified, keyid, address, publicKey, error} envelope. Identity
  // fields are populated whenever the data is available — *including on
  // failure* — so callers can log or surface "we tried to verify a request
  // claiming to be from X." A successful crypto check alone is not trust:
  // pair this with an out-of-band-bootstrapped allowlist or pin store.
  //
  // By default, this method:
  //   - Verifies signature, timestamp, replay, and (for bodied requests) digest
  //   - Pins the first-seen public key per address — subsequent contact with
  //     a different key fails verification (catches account-compromise rotation)
  //   - Honours an optional allowlist of acceptable senders
  static async verifyRequest(
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: object,
    options: VerifyRequestOptions = {},
  ): Promise<VerifyRequestResult> {
    const pinByPublicKey = options.pinByPublicKey ?? true
    const pinStore       = options.pinStore ?? defaultPinStore
    const allowlist      = options.allowlist

    const fail = (
      error: string,
      partial: Partial<Pick<VerifyRequestResult, 'keyid' | 'address' | 'publicKey'>> = {},
    ): VerifyRequestResult => ({
      verified:  false,
      keyid:     partial.keyid     ?? null,
      address:   partial.address   ?? null,
      publicKey: partial.publicKey ?? null,
      error,
    })

    try {
      const h: Record<string, string> = {}
      for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = v

      const sigInput  = h['signature-input']
      const sigHeader = h['signature']
      if (!sigInput || !sigHeader) {
        return fail('Missing Signature-Input or Signature headers')
      }

      // sig1=("@method" "@path" "content-digest");keyid="...";created=...;nonce="..."
      // Parse components and parameters separately for order-independence and forward
      // compatibility with new params (the nonce was added in v2).
      const headMatch = sigInput.match(/^sig1=\(([^)]*)\)(.*)$/)
      if (!headMatch) return fail('Malformed Signature-Input')
      const componentsStr = headMatch[1]
      const paramsStr     = headMatch[2]

      const params: Record<string, string> = {}
      for (const m of paramsStr.matchAll(/;(\w+)=(?:"([^"]*)"|([^;]+))/g)) {
        params[m[1]] = (m[2] !== undefined ? m[2] : m[3])
      }
      const keyid   = params.keyid
      const created = params.created
      if (!keyid || !created) {
        return fail('Signature-Input missing keyid or created')
      }

      // sig1=:base64sig:
      const sigMatch = sigHeader.match(/^sig1=:([A-Za-z0-9+/=]+):$/)
      if (!sigMatch) return fail('Malformed Signature header', { keyid })
      const sigB64 = sigMatch[1]

      // Extract address and base URL from keyid early so identity is populated
      // on every subsequent failure path.
      const agentsIdx = keyid.indexOf('/agents/')
      if (agentsIdx === -1) return fail('keyid is not an Envoys agent URL', { keyid })
      const address   = keyid.slice(agentsIdx + '/agents/'.length)
      const keyidBase = keyid.slice(0, agentsIdx)

      // Reject signatures older than 5 minutes
      const age = Math.floor(Date.now() / 1000) - parseInt(created, 10)
      if (age > 300 || age < -30) {
        return fail('Signature timestamp out of acceptable range', { keyid, address })
      }

      // Replay protection — reject any signature we've already accepted
      // within the timestamp window. Spec §7. Keyed by the full signature
      // because Ed25519 is deterministic but the nonce makes each request unique.
      const replayKey = `${keyid}|${created}|${sigB64}`
      const seenAt    = replayCache.get(replayKey)
      const now       = Date.now()
      if (seenAt && seenAt > now) {
        return fail('Replay detected — signature already accepted', { keyid, address })
      }

      // If body is present, verify it matches the Content-Digest header before touching the sig.
      // Receivers MUST accept both sha-256 (default) and sha-512 (auto-promoted for >=4KB bodies).
      // Spec §6 / RFC 9530.
      if (body !== undefined) {
        const receivedDigest = h['content-digest']
        if (!receivedDigest) {
          return fail('Missing Content-Digest header for request with body', { keyid, address })
        }
        const bodyBuf = Buffer.from(JSON.stringify(body))
        let expectedDigest: string
        if (receivedDigest.startsWith('sha-512=:')) {
          expectedDigest = `sha-512=:${createHash('sha512').update(bodyBuf).digest('base64')}:`
        } else if (receivedDigest.startsWith('sha-256=:')) {
          expectedDigest = `sha-256=:${createHash('sha256').update(bodyBuf).digest('base64')}:`
        } else {
          return fail('Unsupported Content-Digest algorithm (expected sha-256 or sha-512)', { keyid, address })
        }
        if (receivedDigest !== expectedDigest) {
          return fail('Content-Digest mismatch — body has been tampered', { keyid, address })
        }
      }

      // Parse component names from '"@method" "@path" ...'
      const components = (componentsStr.match(/"([^"]+)"/g) ?? []).map(s => s.slice(1, -1))

      // Reconstruct signature base — must match signRequest() exactly
      let sigBase = ''
      for (const c of components) {
        if (c === '@method')        sigBase += `"@method": ${method.toUpperCase()}\n`
        else if (c === '@path')     sigBase += `"@path": ${path}\n`
        else if (c === 'content-digest') {
          const cd = h['content-digest']
          if (!cd) return fail('Missing Content-Digest header', { keyid, address })
          sigBase += `"content-digest": ${cd}\n`
        }
      }
      sigBase += `"@signature-params": (${componentsStr})${paramsStr}`

      const publicKeyPem = await Envoys.resolveKeyFromKeyid(keyid)
      const key = createPublicKey(publicKeyPem)
      const ok  = cryptoVerify(null, Buffer.from(sigBase), key, Buffer.from(sigB64, 'base64'))
      if (!ok) return fail('Signature verification failed', { keyid, address, publicKey: publicKeyPem })

      // Public-key pinning: catches silent identity takeover via account compromise.
      // The first time we successfully verify a sender, we record their public key.
      // On every subsequent contact, the resolved key must match the pin — otherwise
      // we surface a clear failure that the caller has to consciously dismiss
      // (via Envoys.resetPin) if a rotation was expected.
      if (pinByPublicKey) {
        const pinned = await pinStore.get(address)
        if (pinned === null) {
          await pinStore.set(address, publicKeyPem)
        } else if (pinned !== publicKeyPem) {
          return fail(
            `Pinned public key mismatch — call Envoys.resetPin('${address}') if rotation was expected`,
            { keyid, address, publicKey: publicKeyPem },
          )
        }
      }

      // Allowlist enforcement runs *after* signature verification — we only
      // want to admit cryptographically-valid senders into the comparison.
      // Each allowlist entry is matched against both keyid and address so
      // callers can be loose about which form they store.
      if (allowlist && allowlist.length > 0) {
        if (!allowlist.includes(keyid) && !allowlist.includes(address)) {
          return fail(
            `Sender not in allowlist (keyid=${keyid})`,
            { keyid, address, publicKey: publicKeyPem },
          )
        }
      }

      // Only record on successful verify — bad signatures don't pollute the cache.
      replayCache.set(replayKey, now + REPLAY_CACHE_TTL_MS)
      maybeSweepReplayCache()
      return {
        verified:  true,
        keyid,
        address,
        publicKey: publicKeyPem,
        error:     null,
      }
    } catch (err: any) {
      return fail(err?.message ?? 'Verification error')
    }
  }

  // Public-key pin management. Pins are written automatically on first
  // successful verification; reset when you've confirmed a rotation
  // out-of-band, or call clearPins() in a test or graceful-restart scenario.
  static resetPin(address: string, options: { pinStore?: PinStore } = {}): void | Promise<void> {
    return (options.pinStore ?? defaultPinStore).delete(address)
  }
  static clearPins(options: { pinStore?: PinStore } = {}): void | Promise<void> {
    return (options.pinStore ?? defaultPinStore).clear()
  }

  // Clear the in-process replay cache. Useful for tests.
  static clearReplayCache(): void {
    replayCache.clear()
  }

  // Fetch another agent's public key from the Envoys registry.
  // Cached in-process for 5 minutes to avoid round-tripping on every verify.
  // Use the returned key with Envoys.verify() to authenticate their signatures.
  static async resolvePublicKey(address: string, baseUrl = DEFAULT_BASE_URL): Promise<string> {
    const base     = baseUrl.replace(/\/$/, '')
    const cacheKey = `${base}|${address}`
    const cached   = keyCache.get(cacheKey)
    if (cached && cached.expires > Date.now()) return cached.key

    const url = `${base}/agents/public-key?address=${encodeURIComponent(address)}`
    const res = await fetch(url)
    if (!res.ok) throw new Error(`Agent not found: ${address}`)
    const data = await res.json() as { public_key: string }

    keyCache.set(cacheKey, { key: data.public_key, expires: Date.now() + KEY_CACHE_TTL_MS })
    return data.public_key
  }

  // Fetch a public key by fetching the keyid URL directly and accepting either
  // shape it serves: a W3C DID Document (Content-Type application/did+json) or
  // the Envoys-native { address, public_key } object (any JSON Content-Type).
  // This is the verifier path used by verifyRequest and verifyAgentCard, and
  // is what makes Envoys structurally compatible with the dual-shape keyid
  // resolution called for in the A2A Identity Trust Framework v1.0 roadmap
  // (a2aproject/A2A#1850) — the verifier accepts whichever shape the keyid
  // happens to serve without caller-side opt-in.
  //
  // Cached for 5 minutes keyed on the full keyid URL. The cache is shared with
  // resolvePublicKey but keyed differently, so neither path invalidates the
  // other's entries.
  static async resolveKeyFromKeyid(keyidUrl: string): Promise<string> {
    const cached = keyCache.get(keyidUrl)
    if (cached && cached.expires > Date.now()) return cached.key

    const res = await fetch(keyidUrl, {
      headers: { Accept: 'application/did+json, application/json;q=0.9' },
    })
    if (!res.ok) throw new Error(`keyid URL did not resolve: ${keyidUrl} (HTTP ${res.status})`)

    const contentType = (res.headers?.get?.('content-type') ?? '').toLowerCase()
    const data        = await res.json() as any

    let publicKeyPem: string
    if (contentType.includes('application/did+json') || Array.isArray(data?.verificationMethod)) {
      publicKeyPem = extractEd25519FromDidDocument(data, keyidUrl)
    } else if (typeof data?.public_key === 'string') {
      publicKeyPem = data.public_key
    } else {
      throw new Error(`Unrecognized keyid response shape at ${keyidUrl} — expected DID Document or { public_key }`)
    }

    keyCache.set(keyidUrl, { key: publicKeyPem, expires: Date.now() + KEY_CACHE_TTL_MS })
    return publicKeyPem
  }

  // Clear the in-process public key cache. Useful for tests or after a known rotation.
  static clearKeyCache(): void {
    keyCache.clear()
  }

  // Resolve an Ed25519 public key from a did:web DID Document.
  //
  // Fetches https://<domain>/.well-known/did.json, finds the first Ed25519
  // verification method, and returns it as a PEM-encoded SPKI public key —
  // the same shape Envoys.resolvePublicKey returns. Bridges did:web key
  // resolution into the Envoys verification workflow without an intermediary
  // service: a verifier that wants to check a signature whose keyid is a
  // did:web URL can call this and pass the result to Envoys.verifyRequest.
  //
  // Currently supports verification methods that publish the key as
  // publicKeyJwk (the most standardized form). Methods using
  // publicKeyMultibase or publicKeyBase58 throw with a clear error so the
  // caller knows which format was found; support for those can be added
  // when there's a concrete need.
  static async resolveDidWeb(domain: string): Promise<string> {
    const host = domain.replace(/^https?:\/\//, '').replace(/\/$/, '')
    const url  = `https://${host}/.well-known/did.json`
    const res  = await fetch(url)
    if (!res.ok) throw new Error(`did:web DID Document not found at ${url} (HTTP ${res.status})`)
    const doc = await res.json()
    return extractEd25519FromDidDocument(doc, url)
  }

  // ── Internals ─────────────────────────────────────────────────────────────
  private async request(method: string, path: string, body?: object): Promise<any> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${this.agentKey}`,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText })) as any
      throw new Error(err.error ?? `Request failed: ${res.status}`)
    }
    return res.json()
  }
}
