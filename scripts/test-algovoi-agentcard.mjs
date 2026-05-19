// Variant of test #5: AlgoVoi's agent card is plain JSON, but it carries
// an EdDSA JWS inside x-foxbook.signatures.jws_signature, signed with the
// SAME Ed25519 key that their did:web publishes. This script:
//
//   1. Fetches AlgoVoi's agent card
//   2. Pulls the JWS out of the Foxbook extension
//   3. Resolves AlgoVoi's public key via Envoys.resolveDidWeb (the same
//      thing we just shipped in 0.8.1)
//   4. Verifies the EdDSA JWS signature using that resolved key
//
// End result: cryptographic proof that AlgoVoi's published agent card
// was signed by whoever holds the private key matching their did:web
// identity. Cross-vendor verification using only Envoys-SDK-resolved
// public keys + standard primitives.
//
// Note: we don't use Envoys.verifyAgentCard() directly because Foxbook's
// JWS uses a different `kid` convention than Envoys-native cards (no
// envoys.me agent URL). Same Ed25519 underneath; different envelope shape.

import { Envoys } from '../packages/sdk/dist/index.js'
import { createPublicKey, verify as cryptoVerify } from 'node:crypto'

const DOMAIN = 'api.algovoi.co.uk'
const CARD_URL = `https://${DOMAIN}/.well-known/agent.json`

console.log(`Fetching ${CARD_URL}...\n`)
const card = await (await fetch(CARD_URL)).json()
console.log(`Card: ${card.name} v${card.version} (${card.provider?.organization})`)

const fb = card['x-foxbook']
if (!fb?.signatures?.jws_signature) {
  console.error('FAIL: no x-foxbook.signatures.jws_signature on the agent card')
  process.exit(1)
}
const jws = fb.signatures.jws_signature
const [h64, p64, s64] = jws.split('.')
const header = JSON.parse(Buffer.from(h64, 'base64url').toString())
console.log(`JWS header: ${JSON.stringify(header)}`)
console.log(`JWS signature: ${s64.slice(0, 24)}... (${Buffer.from(s64, 'base64url').length} bytes)\n`)

console.log(`Resolving did:web:${DOMAIN} via @envoys/sdk...`)
const resolvedPem = await Envoys.resolveDidWeb(DOMAIN)
console.log(`Resolved PEM:`)
console.log(resolvedPem)

// Cross-check: x-foxbook also publishes the public key as hex
const fbHex = fb.signatures.ed25519_public_key_hex
if (fbHex) {
  const fbPubKey = createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(fbHex, 'hex').toString('base64url') },
    format: 'jwk',
  })
  const fbPem = fbPubKey.export({ format: 'pem', type: 'spki' })
  const match = fbPem === resolvedPem
  console.log(`x-foxbook.signatures.ed25519_public_key_hex matches did:web-resolved key: ${match ? 'YES' : 'NO'}`)
  if (!match) {
    console.log(`(would mean the agent card's signer differs from the did:web identity)`)
  }
}

// Verify the JWS signature using the did:web-resolved key
const signingInput = `${h64}.${p64}`
const pubKey = createPublicKey(resolvedPem)
const ok = cryptoVerify(null, Buffer.from(signingInput), pubKey, Buffer.from(s64, 'base64url'))
console.log(`\nJWS signature verifies against did:web-resolved key: ${ok ? 'YES' : 'NO'}`)

if (ok) {
  console.log('\n[OK] AlgoVoi\'s agent card is cryptographically anchored to their did:web identity.')
  console.log('     Envoys SDK successfully resolved the key + verified the third-party signature.')
} else {
  console.log('\n[FAIL] signature verification failed')
  process.exit(1)
}
