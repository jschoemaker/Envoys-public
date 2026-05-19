// Probe candidate identity endpoints — both Envoys-native /agents/* and
// did:web /.well-known/did.json — to find real 200s with Envoys-SDK-resolvable
// Ed25519 keys. Used to filter the list before driving Hermes through them.

import { Envoys } from '../packages/sdk/dist/index.js'

const ENVOYS_AGENTS = [
  'hermes@hermes-local-rnilhj.envoys.me',
  'playground@envoys.me',
]

const DID_WEB_DOMAINS = [
  'api.algovoi.co.uk',
  'envoys.me',
  'identity.foundation',
  'demo.spruceid.com',
  'transmute.industries',
  'sphereon.com',
  'web.spherity.com',
  'ssi.dock.io',
]

console.log('=== Envoys-native /agents/* probes ===')
for (const addr of ENVOYS_AGENTS) {
  const url = `https://envoys.me/agents/${encodeURIComponent(addr)}`
  try {
    const r = await fetch(url)
    if (r.ok) {
      const j = await r.json()
      const pem = j.public_key
      const ok = typeof pem === 'string' && pem.includes('BEGIN PUBLIC KEY')
      console.log(`  [${r.status}] ${addr} — pem=${ok ? 'OK' : 'missing'}`)
    } else {
      console.log(`  [${r.status}] ${addr} — skip`)
    }
  } catch (e) {
    console.log(`  [ERR]  ${addr} — ${e.message}`)
  }
}

console.log('\n=== did:web /.well-known/did.json probes ===')
for (const domain of DID_WEB_DOMAINS) {
  try {
    const r = await fetch(`https://${domain}/.well-known/did.json`)
    if (!r.ok) {
      console.log(`  [${r.status}] did:web:${domain} — skip`)
      continue
    }
    try {
      const pem = await Envoys.resolveDidWeb(domain)
      console.log(`  [200+OK]  did:web:${domain} — Envoys SDK extracted Ed25519 PEM (${pem.length}B)`)
    } catch (e) {
      console.log(`  [200+ERR] did:web:${domain} — Envoys SDK rejected: ${e.message.slice(0, 90)}`)
    }
  } catch (e) {
    console.log(`  [ERR]     did:web:${domain} — ${e.message}`)
  }
}
