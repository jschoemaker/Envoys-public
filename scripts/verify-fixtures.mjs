// Cross-implementation verifier for RFC 9421 wire-signature conformance fixtures.
//
// For each vector: reconstructs the RFC 9421 signature base, recomputes the
// Content-Digest, checks signature_input <-> @signature-params agreement (the
// divergence class that bit Hippo's vectors.json), and verifies the Ed25519
// signature. Negative vectors assert their declared rejection condition holds.
//
// Pluggable per format. Each adapter normalizes its source format into one
// internal vector shape; the verification core is shared:
//   envoys  — the Envoys envoys-rfc9421 set (manifest + per-vector files)
//   aim     — the AIM aim-did-rfc9421 composition fixtures
//             (opena2a-org/a2a-idf-conformance) — wire-layer verification
//   hippo   — STUB; see loadHippo()
//
// This is mesh participation, not an arbiter. The Envoys verifier validating
// AIM's wire layer is one node checking another — the same way AIM's verifiers
// and aeoess's suite cross-check Envoys. It is deliberately NOT pitched as a
// neutral central validator: that role wants a clean-room implementation
// independent of every provider (cf. msaleme for the CTEF/JCS layer). This
// verifier shares logic lineage with the Envoys SDK and spec; it is the
// substrate author's tool, useful for cross-checking but not an authority.
//
// Run:
//   node scripts/verify-fixtures.mjs [fixtures/envoys-rfc9421]
//   node scripts/verify-fixtures.mjs <path-to-aim-fixtures> --format aim
//   node scripts/verify-fixtures.mjs <path-to-hippo-fixtures> --format hippo  (stub)

import { createPublicKey, verify as cryptoVerify, createHash } from 'crypto'
import { readFileSync, readdirSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join, resolve } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))

// The RFC 8032 §7.1 keypair ships with the Envoys fixture set and is the shared
// keypair for both the Envoys and AIM suites. Loaded once relative to this
// script, independent of which fixture set is being verified.
const RFC8032_KEYPAIR    = JSON.parse(
  readFileSync(join(__dirname, '../fixtures/envoys-rfc9421/keypair.json'), 'utf8'),
)
const RFC8032_PUBKEY_PEM = RFC8032_KEYPAIR.public_key_pem_spki

// ── shared verification core ────────────────────────────────────────────────

// RFC 9530 Content-Digest. SHA-256 default; SHA-512 auto-promote at >= 4096
// bytes, matching spec §4.2.
function contentDigest(body) {
  const algo = body.length >= 4096 ? 'sha512'  : 'sha256'
  const hdr  = body.length >= 4096 ? 'sha-512' : 'sha-256'
  return `${hdr}=:${createHash(algo).update(body).digest('base64')}:`
}

// Reconstruct the RFC 9421 signature base from a Signature-Input value plus the
// request line and Content-Digest value. null on a malformed header or an
// unrecognized component.
function reconstructBase(sigInput, method, path, cdValue) {
  const m = sigInput.match(/^sig1=\(([^)]*)\)(.*)$/)
  if (!m) return null
  const components = (m[1].match(/"([^"]+)"/g) ?? []).map(s => s.slice(1, -1))
  let base = ''
  for (const c of components) {
    if (c === '@method')             base += `"@method": ${method.toUpperCase()}\n`
    else if (c === '@path')          base += `"@path": ${path}\n`
    else if (c === 'content-digest') base += `"content-digest": ${cdValue}\n`
    else return null
  }
  base += `"@signature-params": (${m[1]})${m[2]}`
  return base
}

// Normalized positive vector:
//   { id, specRef, method, path, body (Buffer),
//     expected: { content_digest, signature_input, signature_base, signature },
//     pubKeyPem }
function verifyPositive(v) {
  const cd = contentDigest(v.body)
  if (cd !== v.expected.content_digest)
    return { ok: false, msg: `Content-Digest mismatch — computed ${cd}` }

  const base = reconstructBase(v.expected.signature_input, v.method, v.path, cd)
  if (base !== v.expected.signature_base)
    return { ok: false, msg: 'signature_base does not reconstruct from signature_input + request line + digest' }

  const paramsFromInput = v.expected.signature_input.replace(/^sig1=/, '')
  if (!v.expected.signature_base.endsWith(`"@signature-params": ${paramsFromInput}`))
    return { ok: false, msg: 'signature_input diverges from the @signature-params line in signature_base' }

  const ok = cryptoVerify(
    null, Buffer.from(v.expected.signature_base),
    createPublicKey(v.pubKeyPem),
    Buffer.from(v.expected.signature, 'base64'),
  )
  if (!ok) return { ok: false, msg: 'Ed25519 signature does not verify against the keypair' }
  return { ok: true, msg: `${v.specRef} — digest ✓ base ✓ input/base agreement ✓ signature ✓` }
}

// Normalized negative vector: { id, specRef, cover, code, inputs }.
function verifyNegative(v) {
  if (v.cover === 'body-integrity') {
    const recomputed = contentDigest(Buffer.from(v.inputs.body_received_bytes_utf8, 'utf8'))
    const header     = v.inputs.headers_received['Content-Digest']
    if (recomputed === header) return { ok: false, msg: 'received body matches Content-Digest — not a mismatch fixture' }
    return { ok: true, msg: `${v.specRef} — recomputed digest ≠ Content-Digest header → verifier rejects pre-signature (${v.code})` }
  }
  if (v.cover === 'timestamp-freshness') {
    const created = Number(v.inputs.headers_received['Signature-Input'].match(/created=(\d+)/)?.[1])
    const age     = v.inputs.verifier_now_unix - created
    if (!Number.isFinite(age)) return { ok: false, msg: 'could not parse created from Signature-Input' }
    if (age <= 300)            return { ok: false, msg: `age ${age}s within the 300s window — not an expired fixture` }
    return { ok: true, msg: `${v.specRef} — age ${age}s exceeds the 300s window → verifier rejects (${v.code})` }
  }
  if (v.cover === 'replay-protection') {
    const h      = v.inputs.headers_received
    const sigB64 = h['Signature'].match(/^sig1=:(.+):$/)?.[1]
    const base   = reconstructBase(h['Signature-Input'], v.inputs.method, v.inputs.path, h['Content-Digest'])
    if (!base || !sigB64) return { ok: false, msg: 'could not reconstruct base / signature from headers_received' }
    const valid = cryptoVerify(null, Buffer.from(base), createPublicKey(RFC8032_PUBKEY_PEM), Buffer.from(sigB64, 'base64'))
    if (!valid) return { ok: false, msg: 'signature does not verify — a replay fixture must carry a genuine signature' }
    return { ok: true, msg: `${v.specRef} — signature genuinely valid; §7 dedup cache must reject the replayed tuple (${v.code})` }
  }
  return { ok: false, msg: `unknown negative-vector cover "${v.cover}"` }
}

// ── format adapters ─────────────────────────────────────────────────────────

// Envoys envoys-rfc9421: manifest.json + per-vector files, positives + negatives.
function loadEnvoys(dir) {
  const manifest  = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'))
  const keypair   = JSON.parse(readFileSync(join(dir, manifest.keypair), 'utf8'))
  const pem       = keypair.public_key_pem_spki
  const positives = [], negatives = []
  for (const m of manifest.vectors) {
    const v = JSON.parse(readFileSync(join(dir, m.file), 'utf8'))
    if (m.kind === 'positive') {
      const i = v.inputs
      let body
      if (typeof i.body_b64 === 'string')             body = Buffer.from(i.body_b64, 'base64')
      else if (typeof i.body_bytes_utf8 === 'string') body = Buffer.from(i.body_bytes_utf8, 'utf8')
      else                                            body = Buffer.from('')
      positives.push({
        id: m.id, specRef: m.spec_ref,
        method: i.method, path: i.path, body,
        expected: v.expected, pubKeyPem: pem,
      })
    } else {
      negatives.push({ id: m.id, specRef: m.spec_ref, cover: m.covers[0], code: m.expected_error_code, inputs: v.inputs })
    }
  }
  return { positives, negatives }
}

// AIM aim-did-rfc9421 (opena2a-org/a2a-idf-conformance): per-fixture JSON files,
// no manifest. Composition fixtures — the envelope (bilateral receipt,
// delegation chain) is framework-layer; this verifier checks the wire layer,
// which is what AIM's own fixtures scope the conformance claim to. The set
// pins the RFC 8032 §7.1 keypair (its keypairRef points at a vectors/ file
// that is not currently in the repo — the §7.1 key is well-known and shared
// with the Envoys suite, so it is used directly here).
function loadAim(dir) {
  const positives = []
  for (const file of readdirSync(dir).sort()) {
    if (!file.endsWith('.json')) continue
    const v = JSON.parse(readFileSync(join(dir, file), 'utf8'))
    if (!v.input || !v.expected) continue
    const envoysSpec = (v.spec ?? []).find(s => s.id === 'Envoys signature/v1')
    positives.push({
      id:      v.name ?? file,
      specRef: envoysSpec ? `AIM wrap of Envoys ${envoysSpec.section}` : 'AIM aim-did-rfc9421',
      method:  v.input.method,
      path:    v.input.path,
      body:    Buffer.from(v.input.body ?? '', v.input.bodyEncoding ?? 'utf-8'),
      expected: {
        content_digest:  v.expected.contentDigest,
        signature_input: v.expected.signatureInput,
        signature_base:  v.expected.signatureBase,
        signature:       v.expected.signatureBase64,
      },
      pubKeyPem: RFC8032_PUBKEY_PEM,
    })
  }
  return { positives, negatives: [] }
}

// Hippo hippo-rfc9421: STUB. The fixture set is on unmerged PR
// opena2a-org/a2a-idf-conformance#2, and the format is under active revision
// (reviewer asked for keypair.publicKeyBase64 -> keyidResolution). Building an
// adapter against it now is coding to a moving target. Implement once PR #2
// merges and the format stabilizes. The Hippo set uses an independent keypair,
// so the adapter will load Hippo's own public key per-fixture rather than the
// shared RFC 8032 §7.1 key.
function loadHippo(_dir) {
  throw new Error(
    'Hippo adapter not implemented — hippo-rfc9421 is on unmerged PR ' +
    'opena2a-org/a2a-idf-conformance#2 with a format still under revision. ' +
    'Implement once the PR merges and the keypair / keyidResolution shape stabilizes.',
  )
}

// ── main ────────────────────────────────────────────────────────────────────

const args     = process.argv.slice(2)
const fmtIdx   = args.indexOf('--format')
const format   = fmtIdx >= 0 ? args[fmtIdx + 1] : 'envoys'
const pathArg  = args.find((a, i) => !a.startsWith('--') && (fmtIdx < 0 || i !== fmtIdx + 1))
const fixtureDir = resolve(pathArg ?? 'fixtures/envoys-rfc9421')

const loaders = { envoys: loadEnvoys, aim: loadAim, hippo: loadHippo }
if (!loaders[format]) {
  console.error(`Unknown format "${format}" — expected envoys | aim | hippo`)
  process.exit(2)
}

console.log(`Verifying ${fixtureDir}`)
console.log(`Format: ${format}\n`)

let positives, negatives
try {
  ({ positives, negatives } = loaders[format](fixtureDir))
} catch (err) {
  console.error(`Cannot load ${format} fixtures: ${err.message}`)
  process.exit(2)
}

let pass = 0
const failures = []
const report = (id, r) => {
  if (r.ok) { pass++; console.log(`  ok   ${id} — ${r.msg}`) }
  else      { failures.push(`${id}: ${r.msg}`); console.log(`  FAIL ${id} — ${r.msg}`) }
}

if (positives.length) {
  console.log('Positive vectors:')
  for (const v of positives) report(v.id, verifyPositive(v))
}
if (negatives.length) {
  console.log('\nNegative vectors:')
  for (const v of negatives) report(v.id, verifyNegative(v))
}

console.log(`\n${pass} passed, ${failures.length} failed`)
if (failures.length) {
  failures.forEach(f => console.log('  - ' + f))
  process.exit(1)
}
console.log(`\nAll ${format} fixtures verified.`)
