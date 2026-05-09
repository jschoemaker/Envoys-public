/**
 * A2A Receiver — uses @envoys/a2a to verify Envoys-signed JSON-RPC requests.
 *
 * Run:  pnpm receiver
 * Then: AGENT_KEY=agt_... ADDRESS=... PRIVATE_KEY=... pnpm sender
 */

import Fastify from 'fastify'
import { buildAgentCard, createA2AHandler } from '@envoys/a2a'

const PORT     = parseInt(process.env.PORT ?? '3001')
const BASE_URL = process.env.BASE_URL ?? `http://localhost:${PORT}`

const app = Fastify({ logger: false })

// ── Agent Card — A2A discovery endpoint ──────────────────────────────────────
const agentCard = buildAgentCard({
  name:        'Echo Agent',
  description: 'A simple A2A agent that echoes messages. Requires Envoys RFC 9421 signatures.',
  url:         BASE_URL,
  skills: [
    {
      id:          'echo',
      name:        'Echo',
      description: "Echoes the message text back, confirming the sender's verified identity.",
      inputModes:  ['text'],
      outputModes: ['text'],
    },
  ],
  requireEnvoysSignature: true,
})

app.get('/.well-known/agent.json', async (_req, reply) => {
  reply.header('Content-Type', 'application/json')
  return agentCard
})

// ── A2A endpoint ──────────────────────────────────────────────────────────────
const handle = createA2AHandler({
  onUnverified: reason => console.log(`[recv] REJECTED — ${reason}`),
  onMessage: ({ sender, text }) => {
    console.log(`[recv] message/send from ${sender}: "${text}"`)
    return `Echo (verified sender: ${sender}): ${text}`
  },
})

app.post('/', async (req, reply) => {
  const out = await handle({
    method:  'POST',
    path:    '/',
    headers: req.headers as Record<string, string | string[] | undefined>,
    body:    req.body,
  })
  return reply.code(out.status).send(out.body)
})

await app.listen({ port: PORT, host: '0.0.0.0' })
console.log(`A2A receiver listening on ${BASE_URL}`)
console.log(`Agent Card: ${BASE_URL}/.well-known/agent.json`)
