// One-shot: generate a fresh Ed25519 keypair for did:web:envoys.me.
//
// - Writes the private key to ~/.envoys/envoys-service-key.json (mode 0600)
//   so it lives outside this repo and outside the server's env files.
// - Prints the PUBLIC half (PEM SPKI, JWK x value, and ready-to-paste
//   shell exports) so it can be wired into envoys-api's .env without ever
//   moving the private key through a shared transport.
//
// Re-runs: idempotent — refuses to overwrite an existing key file. Delete
// it manually if you really want to rotate.

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { generateKeyPairSync, createPublicKey } from 'node:crypto'

const STORE_DIR  = path.join(os.homedir(), '.envoys')
const STORE_PATH = path.join(STORE_DIR, 'envoys-service-key.json')

if (fs.existsSync(STORE_PATH)) {
  console.error(`Refusing to overwrite existing key at ${STORE_PATH}`)
  console.error(`Delete the file manually if you want to rotate the service DID key.`)
  process.exit(2)
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
})

const pubJwk = createPublicKey(publicKey).export({ format: 'jwk' })

const record = {
  kid:         'did:web:envoys.me#service-key-1',
  controller:  'did:web:envoys.me',
  alg:         'EdDSA',
  publicKeyPem:  publicKey,
  publicKeyJwk:  pubJwk,
  privateKeyPem: privateKey,
  createdAt:     new Date().toISOString(),
  purpose:       'Service-level identity for did:web:envoys.me. Private stays on dev machine; server only needs the public JWK x value to render /.well-known/did.json.',
}

fs.mkdirSync(STORE_DIR, { recursive: true })
fs.writeFileSync(STORE_PATH, JSON.stringify(record, null, 2), { mode: 0o600 })

console.log(`Wrote keypair to ${STORE_PATH} (mode 0600).\n`)
console.log(`Public PEM:`)
console.log(publicKey)
console.log(`Public JWK:`)
console.log(JSON.stringify(pubJwk, null, 2))
console.log()
console.log(`# Add this to packages/api/.env locally and on the server:`)
console.log(`ENVOYS_SERVICE_DID_PUBLIC_JWK_X="${pubJwk.x}"`)
console.log()
console.log(`(That's all the server needs — the private key never leaves this machine.)`)
