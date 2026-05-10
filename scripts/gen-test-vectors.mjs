// Generates deterministic test vectors for the Envoys Signature Extension
// using the RFC 8032 §7.1 Test 1 Ed25519 keypair. Outputs ready-to-paste
// markdown for spec §13 Test Vectors.
//
// The keypair, the per-request created/nonce values, and the body bytes are
// all fixed — running this script will always produce the same signatures.
// Implementers can reproduce by computing RFC 9421 Signature-Base over the
// listed components and signing with the listed key.

import { createPrivateKey, createPublicKey, sign as cryptoSign, createHash } from 'crypto'

// ── RFC 8032 §7.1 Test 1 keypair ─────────────────────────────────────────────
// Secret seed: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
// Public key:  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
const PRIV_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const PUB_HEX  = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'

const b64url = (hex) => Buffer.from(hex, 'hex').toString('base64url')

const jwkPriv = { kty: 'OKP', crv: 'Ed25519', x: b64url(PUB_HEX), d: b64url(PRIV_HEX) }
const jwkPub  = { kty: 'OKP', crv: 'Ed25519', x: b64url(PUB_HEX) }

const privKey = createPrivateKey({ key: jwkPriv, format: 'jwk' })
const pubKey  = createPublicKey({ key: jwkPub,  format: 'jwk' })

const PUB_PEM = pubKey.export({ format: 'pem', type: 'spki' }).toString().trim()

// ── Test request inputs (deterministic; pinned for reproducibility) ──────────
const VECTORS = [
  {
    name:    'GET request, no body',
    method:  'GET',
    path:    '/api/health',
    body:    '',
    keyid:   'https://envoys.me/agents/test@rfc8032-vec1.example',
    created: 1714000000,
    nonce:   'AAECAwQFBgcICQoLDA0ODw',          // base64url of 0x00..0x0F
  },
  {
    name:    'POST request, JSON body',
    method:  'POST',
    path:    '/api/task',
    body:    '{"task":"summarize","url":"https://example.com/doc"}',
    keyid:   'https://envoys.me/agents/test@rfc8032-vec1.example',
    created: 1714000060,
    nonce:   'EBESExQVFhcYGRobHB0eHw',          // base64url of 0x10..0x1F
  },
  {
    name:    'POST request, empty JSON body',
    method:  'POST',
    path:    '/api/echo',
    body:    '{}',
    keyid:   'https://envoys.me/agents/test@rfc8032-vec1.example',
    created: 1714000120,
    nonce:   'ICEiIyQlJicoKSorLC0uLw',          // base64url of 0x20..0x2F
  },
]

function digest(body) {
  return 'sha-256=:' + createHash('sha256').update(body).digest('base64') + ':'
}

function signatureBase(v) {
  const cd = digest(v.body)
  const sigParams = `("@method" "@path" "content-digest");keyid="${v.keyid}";created=${v.created};nonce="${v.nonce}"`
  let base = ''
  base += `"@method": ${v.method.toUpperCase()}\n`
  base += `"@path": ${v.path}\n`
  base += `"content-digest": ${cd}\n`
  base += `"@signature-params": ${sigParams}`
  return { base, contentDigest: cd, sigParams }
}

console.log('### Public key (PEM SPKI)\n')
console.log('```')
console.log(PUB_PEM)
console.log('```\n')

console.log('### Private key (raw seed, hex; for reproducing only)\n')
console.log('```')
console.log(PRIV_HEX)
console.log('```')
console.log('\n*Source: RFC 8032 §7.1 Test 1.*\n')

VECTORS.forEach((v, i) => {
  const { base, contentDigest, sigParams } = signatureBase(v)
  const sig = cryptoSign(null, Buffer.from(base), privKey).toString('base64')
  console.log(`### Vector ${i + 1} — ${v.name}\n`)
  console.log('**Inputs:**')
  console.log('```')
  console.log(`method:  ${v.method}`)
  console.log(`path:    ${v.path}`)
  console.log(`body:    ${v.body || '(empty)'}`)
  console.log(`keyid:   ${v.keyid}`)
  console.log(`created: ${v.created}`)
  console.log(`nonce:   "${v.nonce}"`)
  console.log('```\n')
  console.log('**Computed `Content-Digest` header:**')
  console.log('```')
  console.log(contentDigest)
  console.log('```\n')
  console.log('**Signature base:**')
  console.log('```')
  console.log(base)
  console.log('```\n')
  console.log('**Computed `Signature-Input` header value (for `sig1`):**')
  console.log('```')
  console.log(`sig1=${sigParams}`)
  console.log('```\n')
  console.log('**Computed `Signature` header value:**')
  console.log('```')
  console.log(`sig1=:${sig}:`)
  console.log('```\n')
})
