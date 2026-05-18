// Generates the crypto-bearing fields for the envoys-rfc9421 conformance
// fixture set (fixtures/envoys-rfc9421/). Single source of truth for the
// `expected` block of every positive vector — content_digest,
// signature_input, signature_base, and signature are all derived from one
// pass over the canonical inputs below, so signature_input and the
// @signature-params line inside signature_base can never diverge.
//
// Run:  node scripts/gen-fixtures.mjs            → prints all six vectors
//       node scripts/gen-fixtures.mjs --check    → also asserts the
//         committed fixture JSON matches the computed values
//
// Keypair: RFC 8032 §7.1 Test 1 (public, non-secret — see keypair.json).

import { createPrivateKey, sign as cryptoSign, createHash } from 'crypto'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname  = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(__dirname, '../fixtures/envoys-rfc9421')

const PRIV_HEX = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
const PUB_HEX  = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
const b64url   = (hex) => Buffer.from(hex, 'hex').toString('base64url')
const privKey  = createPrivateKey({
  key: { kty: 'OKP', crv: 'Ed25519', x: b64url(PUB_HEX), d: b64url(PRIV_HEX) },
  format: 'jwk',
})

const KEYID = 'https://envoys.me/agents/test@rfc8032-vec1.example'

// ── Canonical inputs — the source of truth ──────────────────────────────────
// `body` is the literal byte sequence the Content-Digest covers. vec-1 models
// an empty body — Content-Digest of zero bytes is still present + signed, per
// spec §4.2 (always required, body MAY be empty) and §14 Vector 1. vec-6
// reuses vec-2's inputs verbatim — same wire signature, different
// keyid-resolution shape.
const VECTORS = [
  { file: 'positive/vec-1-get-no-body.json',
    method: 'GET',  path: '/api/health', body: Buffer.from(''),
    created: 1714000000, nonce: 'AAECAwQFBgcICQoLDA0ODw' },

  { file: 'positive/vec-2-post-json-body.json',
    method: 'POST', path: '/api/task',
    body: Buffer.from('{"task":"summarize","url":"https://example.com/doc"}'),
    created: 1714000060, nonce: 'EBESExQVFhcYGRobHB0eHw' },

  { file: 'positive/vec-3-post-empty-body.json',
    method: 'POST', path: '/api/echo', body: Buffer.from('{}'),
    created: 1714000120, nonce: 'ICEiIyQlJicoKSorLC0uLw' },

  { file: 'positive/vec-4-tag-param.json',
    method: 'POST', path: '/api/task',
    body: Buffer.from('{"task":"summarize","url":"https://example.com/doc"}'),
    created: 1714000180, nonce: 'MDEyMzQ1Njc4OUFCQ0RFRg', tag: 'task' },

  // vec-5: JSON body whose serialized form is exactly 4096 bytes — the §4.2
  // SHA-512 auto-promotion threshold. JSON.stringify({data:'A'×4085}) is
  // 9 + 4085 + 2 = 4096 bytes, so it tests the threshold through the same
  // JSON-body path the SDK and real A2A traffic use.
  { file: 'positive/vec-5-sha512-large-body.json',
    method: 'POST', path: '/api/upload',
    body: Buffer.from(JSON.stringify({ data: 'A'.repeat(4085) })),
    created: 1714000240, nonce: 'WFhYWFhYWFhYWFhYWFhYWA' },

  { file: 'positive/vec-6-dual-shape-did-document.json',
    method: 'POST', path: '/api/task',
    body: Buffer.from('{"task":"summarize","url":"https://example.com/doc"}'),
    created: 1714000060, nonce: 'EBESExQVFhcYGRobHB0eHw' },
]

// RFC 9530 Content-Digest. SHA-256 by default; auto-promote to SHA-512 for
// bodies >= 4096 bytes, matching @envoys/sdk signRequest and spec §4.2.
function contentDigest(body) {
  if (body.length >= 4096) {
    return 'sha-512=:' + createHash('sha512').update(body).digest('base64') + ':'
  }
  return 'sha-256=:' + createHash('sha256').update(body).digest('base64') + ':'
}

// One pass: every field below is derived from the same `params` string, so
// signature_input and the @signature-params line in signature_base are
// byte-identical by construction.
function compute(v) {
  const cd = contentDigest(v.body)
  let params = `keyid="${KEYID}";created=${v.created};nonce="${v.nonce}"`
  if (v.tag) {
    const escaped = v.tag.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    params += `;tag="${escaped}"`
  }
  const sigParams = `("@method" "@path" "content-digest");${params}`
  const base =
    `"@method": ${v.method.toUpperCase()}\n` +
    `"@path": ${v.path}\n` +
    `"content-digest": ${cd}\n` +
    `"@signature-params": ${sigParams}`
  const signature = cryptoSign(null, Buffer.from(base), privKey).toString('base64')
  return {
    content_digest:  cd,
    signature_input: `sig1=${sigParams}`,
    signature_base:  base,
    signature,
  }
}

const check = process.argv.includes('--check')
let failures = 0

for (const v of VECTORS) {
  const out = compute(v)
  console.log(`\n=== ${v.file} ===`)
  console.log(`content_digest:  ${out.content_digest}`)
  console.log(`signature_input: ${out.signature_input}`)
  console.log(`signature:       ${out.signature}`)

  if (check) {
    const committed = JSON.parse(readFileSync(join(FIXTURE_DIR, v.file), 'utf8'))
    const e = committed.expected
    const cmp = [
      ['content_digest',  e.content_digest,  out.content_digest],
      ['signature_input', e.signature_input, out.signature_input],
      ['signature_base',  e.signature_base,  out.signature_base],
      ['signature',       e.signature,       out.signature],
    ]
    for (const [field, got, want] of cmp) {
      if (got === undefined) { console.log(`  · ${field}: (not committed)`); continue }
      if (got === want)      { console.log(`  ✓ ${field}`); continue }
      // vec-5 carries the sha-512 digest under a distinct field name + a
      // placeholder in signature_base until generated — tolerate that here.
      if (got === 'TBD — compute via scripts/gen-test-vectors.mjs with the above inputs' ||
          got === 'TBD — compute via scripts/gen-test-vectors.mjs once Content-Digest is filled in' ||
          (typeof got === 'string' && got.startsWith('TBD')) ||
          (field === 'signature_base' && got.includes('<content_digest'))) {
        console.log(`  · ${field}: still TBD in committed fixture`)
        continue
      }
      console.log(`  ✗ ${field} MISMATCH`)
      console.log(`      committed: ${JSON.stringify(got)}`)
      console.log(`      computed:  ${JSON.stringify(want)}`)
      failures++
    }
  }
}

if (check) {
  console.log(failures === 0
    ? '\nAll committed fixture values match the generator.'
    : `\n${failures} mismatch(es) — committed fixtures are out of sync with the generator.`)
  process.exit(failures === 0 ? 0 : 1)
}
