// Cross-impl interop helper — drives @envoys/sdk sign/verify from JSON
// input/output files, so external test harnesses (in any language) can
// produce a Node-signed request or verify one without embedding the SDK.
//
// Two modes:
//   sign   — reads {address, base_url, public_pem, private_pem, method, path, body, tag?}
//            from --input file, writes {method, path, body, headers} to --output
//   verify — reads {method, path, body, headers, public_pem} from --input file,
//            writes {verified, error, keyid, address} to --output
//
// In verify mode, globalThis.fetch is stubbed so resolveKeyFromKeyid
// returns the test public_pem (the test keyid is not a real URL).

import { Envoys } from '../packages/sdk/dist/index.js'
import { readFileSync, writeFileSync } from 'fs'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, val, i, arr) => {
    if (val.startsWith('--')) acc.push([val.slice(2), arr[i + 1]])
    return acc
  }, []),
)

const mode    = args.mode
const inFile  = args.input
const outFile = args.output

if (!mode || !inFile || !outFile) {
  console.error('Usage: --mode sign|verify --input <file.json> --output <file.json>')
  process.exit(2)
}

const input = JSON.parse(readFileSync(inFile, 'utf-8'))

if (mode === 'sign') {
  const agent = new Envoys({
    agentKey:   'n/a',
    address:    input.address,
    publicKey:  input.public_pem,
    privateKey: input.private_pem,
    baseUrl:    input.base_url,
  })
  const headers = agent.signRequest(
    input.method,
    input.path,
    input.body ?? undefined,
    input.tag ? { tag: input.tag } : undefined,
  )
  writeFileSync(outFile, JSON.stringify({
    method:  input.method,
    path:    input.path,
    body:    input.body ?? null,
    headers,
  }, null, 2))
  process.exit(0)
}

if (mode === 'verify') {
  // Stub fetch so resolveKeyFromKeyid returns the test public_pem.
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    headers: { get: (name) => name.toLowerCase() === 'content-type' ? 'application/json' : null },
    json: async () => ({ address: input.headers['Signature-Input']?.match(/keyid="[^"]*\/agents\/([^"]+)"/)?.[1] ?? 'unknown', public_key: input.public_pem }),
  })
  Envoys.clearKeyCache()
  Envoys.clearReplayCache()
  Envoys.clearPins()

  const result = await Envoys.verifyRequest(
    input.method,
    input.path,
    input.headers,
    input.body ?? undefined,
    { pinByPublicKey: false },
  )
  writeFileSync(outFile, JSON.stringify({
    verified: result.verified,
    error:    result.error,
    keyid:    result.keyid,
    address:  result.address,
  }, null, 2))
  process.exit(result.verified ? 0 : 1)
}

console.error(`Unknown mode: ${mode}`)
process.exit(2)
