import type { FastifyInstance } from 'fastify'
import { createHash, createPrivateKey, sign as cryptoSign, randomBytes } from 'crypto'

const DEMO_ADDRESS = process.env.DEMO_AGENT_ADDRESS ?? ''
// Two ways to provide the PEM in .env without newline-escaping drama:
//  1. DEMO_AGENT_PRIVATE_KEY_B64  — base64 of the raw PEM (single safe ASCII line)
//  2. DEMO_AGENT_PRIVATE_KEY      — PEM with literal \n in place of real newlines
// Prefer the b64 form; fall back to the \n form for backwards-compat.
const DEMO_PRIVATE_KEY = (() => {
  const b64 = process.env.DEMO_AGENT_PRIVATE_KEY_B64
  if (b64) return Buffer.from(b64, 'base64').toString('utf-8')
  return (process.env.DEMO_AGENT_PRIVATE_KEY ?? '').replace(/\\n/g, '\n')
})()
const BASE_URL = process.env.BASE_URL ?? 'https://envoys.me'

// Rotated through randomly so visitors get something different on repeat clicks —
// reinforces that a fresh signature is generated every call (created/nonce change).
const SAMPLE_REQUESTS = [
  { method: 'POST', path: '/api/task',        body: { task: 'summarize',        url: 'https://example.com/article'    } },
  { method: 'POST', path: '/api/echo',        body: { message: 'Hello, peer.'                                          } },
  { method: 'POST', path: '/api/sentiment',   body: { text:    'Envoys ships RFC 9421 by default.'                    } },
  { method: 'POST', path: '/api/summarize',   body: { url:     'https://envoys.me/specs/signature/v1', max_words: 200 } },
]

function signSampleRequest() {
  const sample = SAMPLE_REQUESTS[Math.floor(Math.random() * SAMPLE_REQUESTS.length)]
  const { method, path, body } = sample

  const keyid      = `${BASE_URL}/agents/${DEMO_ADDRESS}`
  const components = ['"@method"', '"@path"', '"content-digest"']
  const created    = Math.floor(Date.now() / 1000)
  const nonce      = randomBytes(16).toString('base64url')

  const bodyStr = JSON.stringify(body)
  const digest  = createHash('sha256').update(bodyStr).digest('base64')

  let sigBase = ''
  sigBase += `"@method": ${method.toUpperCase()}\n`
  sigBase += `"@path": ${path}\n`
  sigBase += `"content-digest": sha-256=:${digest}:\n`
  const params = `;keyid="${keyid}";created=${created};nonce="${nonce}"`
  sigBase += `"@signature-params": (${components.join(' ')})${params}`

  const key = createPrivateKey(DEMO_PRIVATE_KEY)
  const sig = cryptoSign(null, Buffer.from(sigBase), key).toString('base64')

  return {
    method,
    path,
    body,
    headers: {
      'Content-Type':     'application/json',
      'Content-Digest':   `sha-256=:${digest}:`,
      'Signature-Input':  `sig1=(${components.join(' ')})${params}`,
      'Signature':        `sig1=:${sig}:`,
    },
    address: DEMO_ADDRESS,
    keyid,
    created,
  }
}

export async function demoRoutes(app: FastifyInstance) {
  app.get('/demo/sample-signed-request', async (_req, reply) => {
    if (!DEMO_ADDRESS || !DEMO_PRIVATE_KEY) {
      return reply.code(503).send({
        error:   'Demo not configured',
        message: 'Set DEMO_AGENT_ADDRESS and DEMO_AGENT_PRIVATE_KEY environment variables.',
      })
    }
    return signSampleRequest()
  })
}
