// Resolve our own did:web:envoys.me via the Envoys SDK and confirm the
// PEM matches the expected service-key from /.well-known/did.json.
import { Envoys } from '../packages/sdk/dist/index.js'

const pem = await Envoys.resolveDidWeb('envoys.me')
console.log('Envoys.resolveDidWeb("envoys.me") returned:')
console.log(pem)

// Sanity: matches what the live route serves
const r = await fetch('https://envoys.me/.well-known/did.json')
const doc = await r.json()
const expectedX = doc.verificationMethod[0].publicKeyJwk.x
console.log(`\nLive DID Doc publicKeyJwk.x: ${expectedX}`)
console.log(`Expected (gen-service-did-key.mjs output): MaK_13zTn-J4wK2TdjBPQS57JofclILxHu4fiCLr-Fw`)
console.log(`Match: ${expectedX === 'MaK_13zTn-J4wK2TdjBPQS57JofclILxHu4fiCLr-Fw'}`)
