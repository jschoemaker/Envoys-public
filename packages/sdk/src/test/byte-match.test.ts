// Byte-match tests against envoys-rfc9421 §14 vectors.
//
// These prove the Node SDK's wire format is byte-identical to the spec
// vectors. Any independent implementation targeting the same vectors
// can converge against the same canonical fixtures.
//
// Mocks node:crypto's randomBytes via vi.mock (hoisted above imports)
// and Date.now via vi.useFakeTimers so signRequest produces deterministic
// output for each pinned vector.

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'

// vi.mock is hoisted above all imports — the SDK picks up this mocked
// crypto when it runs `import { randomBytes } from 'crypto'`.
vi.mock('crypto', async () => {
  const actual = await vi.importActual<typeof import('crypto')>('crypto')
  return {
    ...actual,
    randomBytes: (n: number) => {
      const stub = (globalThis as any).__testNonceBytes as Buffer | undefined
      if (stub) return stub.subarray(0, n)
      return actual.randomBytes(n)
    },
  }
})

import { Envoys } from '../index.js'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { createPrivateKey } from 'crypto'

const __dirname = dirname(fileURLToPath(import.meta.url))
// Resolve fixtures: prefer sibling envoys-public/ checkout, fall back to
// agentmail's own copy.
function findFixtures(): string | null {
  const candidates = [
    join(__dirname, '../../../../../envoys-public/fixtures/envoys-rfc9421'),
    join(__dirname, '../../../../fixtures/envoys-rfc9421'),
  ]
  for (const c of candidates) {
    try { readFileSync(join(c, 'manifest.json')); return c } catch {}
  }
  return null
}

const FIX = findFixtures()

const POSITIVE_VECTORS = [
  'vec-1-get-no-body',
  'vec-2-post-json-body',
  'vec-3-post-empty-body',
  'vec-4-tag-param',
  'vec-5-sha512-large-body',
]

function loadKeypair(): { pub_pem: string; priv_pem: string } {
  const kp = JSON.parse(readFileSync(join(FIX!, 'keypair.json'), 'utf-8'))
  // Reconstruct PEM private key from RFC 8032 seed hex
  const seed = Buffer.from(kp.private_key_seed_hex, 'hex')
  // Ed25519 PKCS8 with the seed: cleanest is JWK round-trip
  const x_b64url = kp.public_key_jwk.x
  const d_b64url = seed.toString('base64url')
  const privKey = createPrivateKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: x_b64url, d: d_b64url },
    format: 'jwk',
  })
  const priv_pem = privKey.export({ format: 'pem', type: 'pkcs8' }) as string
  return { pub_pem: kp.public_key_pem_spki, priv_pem }
}

function splitKeyid(keyid: string): [string, string] {
  const idx = keyid.indexOf('/agents/')
  if (idx === -1) throw new Error(`bad keyid: ${keyid}`)
  return [keyid.slice(0, idx), keyid.slice(idx + '/agents/'.length)]
}

describe.skipIf(!FIX)('§14 vector byte-match (spec v1.5.1)', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })
  afterEach(() => {
    vi.useRealTimers()
    delete (globalThis as any).__testNonceBytes
    Envoys.clearReplayCache()
    Envoys.clearKeyCache()
    Envoys.clearPins()
  })

  it.each(POSITIVE_VECTORS)('byte-matches %s', (vecId) => {
    const vec = JSON.parse(readFileSync(join(FIX!, 'positive', `${vecId}.json`), 'utf-8'))
    const { pub_pem, priv_pem } = loadKeypair()
    const [baseUrl, address] = splitKeyid(vec.inputs.keyid)

    // Pin time + nonce
    vi.setSystemTime(vec.inputs.created * 1000)
    ;(globalThis as any).__testNonceBytes = Buffer.from(vec.inputs.nonce, 'base64url')

    const agent = new Envoys({
      agentKey: 'n/a',
      address,
      publicKey: pub_pem,
      privateKey: priv_pem,
      baseUrl,
    })

    const body = vec.inputs.body === null ? undefined : vec.inputs.body
    const tag  = vec.inputs.tag
    const headers = agent.signRequest(
      vec.inputs.method,
      vec.inputs.path,
      body,
      tag ? { tag } : undefined,
    )

    // The fixture's expected.signature is the bare base64 value, not the
    // wrapped HTTP header (sig1=:...:). Extract for comparison.
    const actualSigBare = headers['Signature'].replace(/^sig1=:/, '').replace(/:$/, '')

    expect(headers['Signature-Input']).toBe(vec.expected.signature_input)
    expect(actualSigBare).toBe(vec.expected.signature)
    if (body !== undefined) {
      expect(headers['Content-Digest']).toBe(vec.expected.content_digest)
    }
  })
})
