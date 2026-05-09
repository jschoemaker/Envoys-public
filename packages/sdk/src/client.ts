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
  signRequest(method: string, path: string, body?: object): Record<string, string> {
    if (!this.privateKey) throw new Error('No private key — provide privateKey in EnvoysConfig')

    const keyid      = `${this.baseUrl}/agents/${this.address}`
    const created    = Math.floor(Date.now() / 1000)
    const nonce      = randomBytes(16).toString('base64url')  // 22-char unique tag
    const components = ['"@method"', '"@path"']
    const headers: Record<string, string> = {}

    let sigBase = `"@method": ${method.toUpperCase()}\n"@path": ${path}\n`

    if (body !== undefined) {
      const bodyStr = JSON.stringify(body)
      const digest  = createHash('sha256').update(bodyStr).digest('base64')
      headers['Content-Digest'] = `sha-256=:${digest}:`
      components.push('"content-digest"')
      sigBase += `"content-digest": sha-256=:${digest}:\n`
    }

    const params = `;keyid="${keyid}";created=${created};nonce="${nonce}"`
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

      const publicKeyPem = await Envoys.resolvePublicKey(address, keyidBase)
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

      // If body is present, verify it matches the Content-Digest header before touching the sig
      if (body !== undefined) {
        const receivedDigest = h['content-digest']
        if (!receivedDigest) {
          return fail('Missing Content-Digest header for request with body', { keyid, address })
        }
        const expectedDigest = `sha-256=:${createHash('sha256').update(JSON.stringify(body)).digest('base64')}:`
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

      const publicKeyPem = await Envoys.resolvePublicKey(address, keyidBase)
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

  // Clear the in-process public key cache. Useful for tests or after a known rotation.
  static clearKeyCache(): void {
    keyCache.clear()
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
