/**
 * A2A Sender — uses @envoys/a2a to send a signed JSON-RPC message.
 *
 * Required env vars (from your Envoys dashboard or POST /agents/register):
 *   ENVOYS_AGENT_KEY    — agt_...
 *   ENVOYS_ADDRESS      — name@handle.envoys.me
 *   ENVOYS_PUBLIC_KEY   — -----BEGIN PUBLIC KEY-----...
 *   ENVOYS_PRIVATE_KEY  — -----BEGIN PRIVATE KEY-----...
 *
 * Optional:
 *   RECEIVER          — URL of the A2A receiver (default: http://localhost:3001)
 *   ENVOYS_BASE_URL   — Envoys registry URL (default: https://envoys.me)
 *   MESSAGE           — text to send (default: "Hello from a verified Envoys agent!")
 */

import { Envoys }          from '@envoys/sdk'
import { createA2AClient } from '@envoys/a2a'

const RECEIVER = process.env.RECEIVER ?? 'http://localhost:3001'
const MESSAGE  = process.env.MESSAGE  ?? 'Hello from a verified Envoys agent!'

const envoys = Envoys.fromEnv()

// Pick up any pending key rotation before sending.
const sync = await envoys.syncKeys()
if (sync.rotated) console.log('[send] Keys rotated — updated to new keypair')

const a2a = createA2AClient({ envoys, endpoint: RECEIVER })

console.log(`[send] Sending signed A2A request to ${RECEIVER}`)
console.log(`[send] Sender identity: ${envoys.address}`)
console.log(`[send] keyid: https://envoys.me/agents/${envoys.address}`)
console.log()

try {
  const reply = await a2a.send(MESSAGE)
  console.log(`[send] Response: ${reply.text}`)
} catch (err: any) {
  console.error(`[send] Error:`, err.message)
  process.exit(1)
}
