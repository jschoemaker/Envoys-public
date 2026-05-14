// Second-implementation conformance check: runs @envoys/sdk's
// Envoys.verifyRequest() against the envoys-rfc9421 fixture set.
//
// The SDK's verifyRequest has its own signature-base reconstruction,
// Content-Digest, timestamp, and replay logic — entirely separate code
// from scripts/verify-fixtures.mjs. If both agree the fixtures verify,
// that's two independent Envoys implementations corroborating, not the
// generator agreeing with itself.
//
// Two things are stubbed so the static fixtures can run through the live
// SDK: Date.now() (fixtures carry 2024 timestamps; the SDK enforces a
// 300s freshness window) and fetch() (the keyid URL is a test address
// that doesn't resolve — stubbed to return the RFC 8032 §7.1 public key,
// or the DID Document for the dual-shape vector).
//
// All six positive vectors are runnable: vec-5's body is a JSON object
// that serializes to exactly 4096 bytes, so it goes through the SDK's
// JSON-body path like every real A2A request.
//
// Run:  node scripts/sdk-cross-check.mjs   (build the SDK first)

import { Envoys } from '../packages/sdk/dist/index.js'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIX      = join(__dirname, '../fixtures/envoys-rfc9421')
const keypair  = JSON.parse(readFileSync(join(FIX, 'keypair.json'), 'utf8'))
const PUB_PEM  = keypair.public_key_pem_spki

const realFetch   = globalThis.fetch
const realDateNow = Date.now

const stubDateNow = (unixSeconds) => { Date.now = () => unixSeconds * 1000 }
const restoreDateNow = () => { Date.now = realDateNow }

const stubFetchNative = () => {
  globalThis.fetch = async () => ({
    ok: true,
    headers: { get: (n) => n.toLowerCase() === 'content-type' ? 'application/json' : null },
    json: async () => ({ address: 'test@rfc8032-vec1.example', public_key: PUB_PEM }),
  })
}
const stubFetchDidDocument = (didDoc) => {
  globalThis.fetch = async () => ({
    ok: true,
    headers: { get: (n) => n.toLowerCase() === 'content-type' ? 'application/did+json' : null },
    json: async () => didDoc,
  })
}
const restoreFetch = () => { globalThis.fetch = realFetch }

const clearCaches = () => { Envoys.clearKeyCache(); Envoys.clearReplayCache(); Envoys.clearPins() }

let pass = 0
const failures = []
const ok  = (id, msg) => { pass++; console.log(`  ok   ${id} — ${msg}`) }
const bad = (id, msg) => { failures.push(`${id}: ${msg}`); console.log(`  FAIL ${id} — ${msg}`) }

const headersFromExpected = (e) => ({
  'signature-input': e.signature_input,
  'signature':       `sig1=:${e.signature}:`,
  'content-digest':  e.content_digest,
})

console.log('SDK cross-check — @envoys/sdk verifyRequest vs envoys-rfc9421 fixtures\n')

// ── Positive vectors ────────────────────────────────────────────────────────
console.log('Positive:')
for (const id of [
  'vec-1-get-no-body',
  'vec-2-post-json-body',
  'vec-3-post-empty-body',
  'vec-4-tag-param',
  'vec-5-sha512-large-body',
  'vec-6-dual-shape-did-document',
]) {
  const v = JSON.parse(readFileSync(join(FIX, 'positive', `${id}.json`), 'utf8'))
  const { inputs, expected } = v

  clearCaches()
  stubDateNow(inputs.created)
  if (id === 'vec-6-dual-shape-did-document') stubFetchDidDocument(v.keyid_response.body)
  else stubFetchNative()

  const headers = headersFromExpected(expected)
  const body = (inputs.body === null || inputs.body === undefined) ? undefined : inputs.body

  const r = await Envoys.verifyRequest(inputs.method, inputs.path, headers, body)
  restoreDateNow()
  restoreFetch()

  if (r.verified) ok(id, `verified=true (${r.keyid})`)
  else            bad(id, `verified=false — ${r.error}`)
}

// ── Negative vectors ────────────────────────────────────────────────────────
console.log('\nNegative:')

// vec-n1 — Content-Digest mismatch. Date.now stubbed into the window so the
// verifier reaches the digest check instead of failing on timestamp first.
{
  const v = JSON.parse(readFileSync(join(FIX, 'negative', 'vec-n1-content-digest-mismatch.json'), 'utf8'))
  const h = v.inputs.headers_received
  const created = Number(h['Signature-Input'].match(/created=(\d+)/)[1])
  clearCaches(); stubDateNow(created); stubFetchNative()
  const r = await Envoys.verifyRequest(
    v.inputs.method, v.inputs.path,
    { 'signature-input': h['Signature-Input'], 'signature': h['Signature'], 'content-digest': h['Content-Digest'] },
    v.inputs.body_received,
  )
  restoreDateNow(); restoreFetch()
  if (!r.verified && /digest/i.test(r.error)) ok('vec-n1', `rejected — ${r.error}`)
  else if (!r.verified)                       bad('vec-n1', `rejected, wrong reason — ${r.error}`)
  else                                        bad('vec-n1', 'verified=true — should have rejected')
}

// vec-n2 — expired timestamp. Date.now stubbed to verifier_now_unix so age > 300s.
{
  const v = JSON.parse(readFileSync(join(FIX, 'negative', 'vec-n2-expired-timestamp.json'), 'utf8'))
  const h = v.inputs.headers_received
  clearCaches(); stubDateNow(v.inputs.verifier_now_unix); stubFetchNative()
  const r = await Envoys.verifyRequest(
    v.inputs.method, v.inputs.path,
    { 'signature-input': h['Signature-Input'], 'signature': h['Signature'], 'content-digest': h['Content-Digest'] },
    undefined,
  )
  restoreDateNow(); restoreFetch()
  if (!r.verified && /timestamp/i.test(r.error)) ok('vec-n2', `rejected — ${r.error}`)
  else if (!r.verified)                          bad('vec-n2', `rejected, wrong reason — ${r.error}`)
  else                                           bad('vec-n2', 'verified=true — should have rejected')
}

// vec-n3 — replay. Verify once (must succeed), verify the identical request
// again without clearing the replay cache (must reject).
{
  const v = JSON.parse(readFileSync(join(FIX, 'negative', 'vec-n3-replay.json'), 'utf8'))
  const h = v.inputs.headers_received
  const created = Number(h['Signature-Input'].match(/created=(\d+)/)[1])
  clearCaches(); stubDateNow(created); stubFetchNative()
  const headers = { 'signature-input': h['Signature-Input'], 'signature': h['Signature'], 'content-digest': h['Content-Digest'] }
  const r1 = await Envoys.verifyRequest(v.inputs.method, v.inputs.path, headers, v.inputs.body)
  const r2 = await Envoys.verifyRequest(v.inputs.method, v.inputs.path, headers, v.inputs.body)
  restoreDateNow(); restoreFetch()
  if (r1.verified && !r2.verified && /replay/i.test(r2.error)) ok('vec-n3', `first verified, replay rejected — ${r2.error}`)
  else if (!r1.verified)                                       bad('vec-n3', `first delivery failed — ${r1.error}`)
  else if (r2.verified)                                        bad('vec-n3', 'replay verified=true — dedup not catching it')
  else                                                         bad('vec-n3', `replay rejected, wrong reason — ${r2.error}`)
}

console.log(`\n${pass} passed, ${failures.length} failed`)
if (failures.length) {
  failures.forEach(f => console.log('  - ' + f))
  process.exit(1)
}
console.log('\n@envoys/sdk verifyRequest agrees with verify-fixtures.mjs on all 9 vectors.')
console.log('Two independent Envoys implementations corroborate the fixture set.')
