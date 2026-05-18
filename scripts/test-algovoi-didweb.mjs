// One-shot test: does @envoys/sdk 0.8.1 successfully resolve a real
// third-party did:web deployment (AlgoVoi's api.algovoi.co.uk)?
//
// 0.8.1 added JsonWebKey2020 acceptance to extractEd25519FromDidDocument —
// AlgoVoi's DID Document uses that wrapper type (W3C generic), which 0.8.0
// rejected. After the patch, this script demonstrates that Envoys's §6
// dual-shape resolution interoperates with a real third-party did:web
// deployment, not just our own fixtures.
//
// Note on Windows: if you hit UNABLE_TO_VERIFY_LEAF_SIGNATURE here, run
// with `NODE_OPTIONS=--use-system-ca`. Some AVs (e.g. Norton) intercept
// TLS for less-trafficked domains and present a self-signed root that's
// in the Windows trust store but not Node's bundled Mozilla CA list.

import { Envoys } from '../packages/sdk/dist/index.js'

const DOMAIN = 'api.algovoi.co.uk'

console.log(`Resolving did:web:${DOMAIN} via @envoys/sdk 0.8.1...\n`)

try {
  const pem = await Envoys.resolveDidWeb(DOMAIN)
  console.log('SUCCESS — resolved to PEM SPKI:')
  console.log(pem)

  // Also try the keyid-URL path which is what verifyRequest/verifyAgentCard use
  console.log('\nAlso testing resolveKeyFromKeyid against the .well-known URL...')
  const pem2 = await Envoys.resolveKeyFromKeyid(`https://${DOMAIN}/.well-known/did.json`)
  console.log('SUCCESS — resolved via dual-shape detector to PEM SPKI:')
  console.log(pem2)

  console.log('\n[OK] Envoys SDK interoperates with AlgoVoi did:web deployment.')
} catch (e) {
  console.error('FAILED:', e.message)
  console.error('\nFull error:', e)
  process.exit(1)
}
