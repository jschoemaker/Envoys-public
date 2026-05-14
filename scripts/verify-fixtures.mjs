// Cross-implementation verifier for the envoys-rfc9421 conformance fixtures.
// Walks manifest.json and, for each vector:
//
//   positive — resolves the literal body bytes, recomputes the RFC 9530
//     Content-Digest, reconstructs the RFC 9421 signature base from the
//     committed signature_input, asserts the committed signature_base
//     reconstructs identically, checks signature_input ↔ @signature-params
//     agreement (the divergence class that bit Hippo's vectors.json), and
//     verifies the Ed25519 signature against keypair.json.
//
//   negative — asserts the declared rejection condition actually holds:
//     a digest mismatch, a timestamp outside the §5.2 window, or a
//     genuinely-valid signature whose (keyid, created, signature) tuple a
//     §7 dedup cache must reject on replay.
//
// Exit code is non-zero on any failure, so it drops into CI or an
// aggregate test run. The vector format is implementation-neutral — a
// verifier in any language can consume the same manifest + vector files.
//
// Run:  node scripts/verify-fixtures.mjs [fixtures/envoys-rfc9421]

import { createPublicKey, verify as cryptoVerify, createHash } from 'crypto'
import { readFileSync } from 'fs'
import { join, resolve } from 'path'

const fixtureDir = resolve(process.argv[2] ?? 'fixtures/envoys-rfc9421')
const manifest   = JSON.parse(readFileSync(join(fixtureDir, 'manifest.json'), 'utf8'))
const keypair    = JSON.parse(readFileSync(join(fixtureDir, manifest.keypair), 'utf8'))
const pubKey     = createPublicKey(keypair.public_key_pem_spki)

let pass = 0
const failures = []
const ok  = (id, msg) => { pass++; console.log(`  ok   ${id} — ${msg}`) }
const bad = (id, msg) => { failures.push(`${id}: ${msg}`); console.log(`  FAIL ${id} — ${msg}`) }

// Resolve a vector's literal body bytes. body_b64 is the canonical
// language-neutral field; body_bytes_utf8 is a convenience for text bodies;
// an absent/null body means zero bytes.
function bodyBytes(inputs) {
  if (typeof inputs.body_b64 === 'string')        return Buffer.from(inputs.body_b64, 'base64')
  if (typeof inputs.body_bytes_utf8 === 'string') return Buffer.from(inputs.body_bytes_utf8, 'utf8')
  if (inputs.body === null || inputs.body === undefined) return Buffer.from('')
  return null
}

// RFC 9530 Content-Digest. SHA-256 default; SHA-512 auto-promote at >= 4096
// bytes, matching spec §4.2 and @envoys/sdk signRequest.
function contentDigest(body) {
  const algo = body.length >= 4096 ? 'sha512' : 'sha256'
  const hdr  = body.length >= 4096 ? 'sha-512' : 'sha-256'
  return `${hdr}=:${createHash(algo).update(body).digest('base64')}:`
}

// Reconstruct the RFC 9421 signature base from a Signature-Input value plus
// the request line and the Content-Digest value. Returns null on a
// malformed header or an unrecognized component.
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

console.log(`Verifying ${fixtureDir}`)
console.log(`Keypair: ${keypair.source}\n`)

// ── Positive vectors ────────────────────────────────────────────────────────
console.log('Positive vectors:')
for (const v of manifest.vectors.filter(x => x.kind === 'positive')) {
  const { inputs, expected } = JSON.parse(readFileSync(join(fixtureDir, v.file), 'utf8'))

  const body = bodyBytes(inputs)
  if (body === null) { bad(v.id, 'cannot resolve body bytes (no body_b64 / body_bytes_utf8 / null body)'); continue }

  const cd = contentDigest(body)
  if (cd !== expected.content_digest) {
    bad(v.id, `Content-Digest mismatch — computed ${cd}, committed ${expected.content_digest}`); continue
  }

  const base = reconstructBase(expected.signature_input, inputs.method, inputs.path, cd)
  if (base !== expected.signature_base) {
    bad(v.id, 'signature_base does not reconstruct from signature_input + request line + digest'); continue
  }

  // signature_input must equal the @signature-params line of the base verbatim
  // (minus the sig1= label). This is the Hippo divergence check.
  const paramsFromInput = expected.signature_input.replace(/^sig1=/, '')
  if (!expected.signature_base.endsWith(`"@signature-params": ${paramsFromInput}`)) {
    bad(v.id, 'signature_input diverges from the @signature-params line in signature_base'); continue
  }

  const sigValid = cryptoVerify(
    null, Buffer.from(expected.signature_base), pubKey,
    Buffer.from(expected.signature, 'base64'),
  )
  if (!sigValid) { bad(v.id, 'Ed25519 signature does not verify against the fixture keypair'); continue }

  ok(v.id, `${v.spec_ref} — digest ✓ base ✓ input/base agreement ✓ signature ✓`)
}

// ── Negative vectors ────────────────────────────────────────────────────────
console.log('\nNegative vectors:')
for (const v of manifest.vectors.filter(x => x.kind === 'negative')) {
  const { inputs } = JSON.parse(readFileSync(join(fixtureDir, v.file), 'utf8'))
  const cover = v.covers[0]
  const code  = v.expected_error_code

  if (cover === 'body-integrity') {
    const recvBody   = Buffer.from(inputs.body_received_bytes_utf8, 'utf8')
    const recomputed = contentDigest(recvBody)
    const header     = inputs.headers_received['Content-Digest']
    if (recomputed === header) {
      bad(v.id, 'received body actually matches Content-Digest — not a mismatch fixture')
    } else {
      ok(v.id, `${v.spec_ref} — recomputed digest ≠ Content-Digest header → verifier rejects pre-signature (${code})`)
    }
  }
  else if (cover === 'timestamp-freshness') {
    const created = Number(inputs.headers_received['Signature-Input'].match(/created=(\d+)/)?.[1])
    const age     = inputs.verifier_now_unix - created
    if (!Number.isFinite(age))   bad(v.id, 'could not parse created from Signature-Input')
    else if (age <= 300)         bad(v.id, `age ${age}s is within the 300s window — not an expired fixture`)
    else                         ok(v.id, `${v.spec_ref} — age ${age}s exceeds the 300s window → verifier rejects (${code})`)
  }
  else if (cover === 'replay-protection') {
    const h        = inputs.headers_received
    const sigB64   = h['Signature'].match(/^sig1=:(.+):$/)?.[1]
    const base     = reconstructBase(h['Signature-Input'], inputs.method, inputs.path, h['Content-Digest'])
    if (!base || !sigB64) { bad(v.id, 'could not reconstruct base / signature from headers_received'); continue }
    const valid = cryptoVerify(null, Buffer.from(base), pubKey, Buffer.from(sigB64, 'base64'))
    if (!valid) {
      bad(v.id, 'signature does not verify — a replay fixture must carry a genuine, valid signature')
    } else {
      ok(v.id, `${v.spec_ref} — signature is genuinely valid; §7 dedup cache must reject the replayed (keyid, created, signature) tuple (${code})`)
    }
  }
  else {
    bad(v.id, `unknown negative-vector cover "${cover}"`)
  }
}

console.log(`\n${pass} passed, ${failures.length} failed`)
if (failures.length) {
  console.log('\nFailures:')
  failures.forEach(f => console.log('  - ' + f))
  process.exit(1)
}
console.log('\nAll envoys-rfc9421 fixtures verified.')
