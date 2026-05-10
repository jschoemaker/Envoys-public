# @envoys/a2a

Cryptographic identity for Agent2Agent (A2A) interactions. Signed JSON-RPC, verified senders, framework-agnostic.

A thin adapter on top of [`@envoys/sdk`](https://www.npmjs.com/package/@envoys/sdk) that implements the [Envoys Signature Extension v1](https://envoys.me/specs/signature/v1) for A2A.

## Install

```bash
npm install @envoys/sdk @envoys/a2a
```

## Quickstart

### Receiver — verify incoming signatures

```ts
import Fastify from 'fastify'
import { buildAgentCard, createA2AHandler } from '@envoys/a2a'

const app = Fastify()

// Discovery — declares the Envoys signature requirement per spec §3
const card = buildAgentCard({
  name: 'Echo Agent',
  url:  'https://echo.example.com',
  skills: [{ id: 'echo', name: 'Echo' }],
  requireEnvoysSignature: true,
})

app.get('/.well-known/agent.json', () => card)

// Framework-agnostic. Returns { status, body } the framework writes back.
const handle = createA2AHandler({
  onMessage: ({ sender, text }) => `Echo from ${sender}: ${text}`,
})

app.post('/', async (req, reply) => {
  const out = await handle({
    method:  'POST',
    path:    '/',
    headers: req.headers,
    body:    req.body,
  })
  return reply.code(out.status).send(out.body)
})

app.listen({ port: 3001 })
```

### Sender — sign outgoing requests

```ts
import { Envoys }          from '@envoys/sdk'
import { createA2AClient } from '@envoys/a2a'

// Reads ENVOYS_AGENT_KEY / ADDRESS / PUBLIC_KEY / PRIVATE_KEY from process.env.
// Set ENVOYS_BASE_URL to point at a non-default registry.
const envoys = Envoys.fromEnv()

const a2a = createA2AClient({
  envoys,
  endpoint: 'https://echo.example.com/',
})

const reply = await a2a.send('Hello, peer.')
console.log(reply.text)        // verified response text
console.log(reply.taskId)      // A2A task id
console.log(reply.status)      // "completed"
```

## API

### `createA2AClient({ envoys, endpoint })`

Returns `{ send }`. The `send` function takes a string or `SendOptions`:

```ts
// All of these work:
await client.send('hello')
await client.send({ text: 'hello' })
await client.send({ file: { name: 'photo.jpg', mimeType: 'image/jpeg', bytes: '<base64>' } })
await client.send({ data: { tool: 'search', args: { q: 'envoys' } } })
await client.send({ parts: [
  { kind: 'text', text: 'analyze this' },
  { kind: 'file', file: { name: 'doc.pdf', mimeType: 'application/pdf', bytes: '<base64>' } },
] })
```

`file` follows the A2A `FileContent` shape — either `{ ..., bytes }` (base64) or `{ ..., uri }`. `data` is any structured value. Mix freely via the `parts` array.

Returns:

```ts
interface SendResult {
  text:      string         // first text part of the first artifact
  parts:     A2APart[]      // all parts of the first artifact
  artifacts: A2AArtifact[]  // all artifacts from the response
  taskId:    string
  status:    string
  raw:       A2AResponseEnvelope
}
```

Outgoing requests are RFC 9421-signed and include `A2A-Extensions: https://envoys.me/specs/signature/v1` per [spec §4.1](https://envoys.me/specs/signature/v1).

### `createA2AHandler({ onMessage, onUnverified?, onMissingExtensionHeader? })`

Returns a `handle({ method, path, headers, body }) → { status, body }` function. The signature gate runs before `onMessage` is called, so `ctx.sender` in `onMessage` is always cryptographically verified.

```ts
interface A2AContext {
  sender:   string         // verified Envoys address
  text:     string         // first text part, for convenience
  parts:    A2APart[]      // all message parts
  message:  A2AMessage     // raw A2A message
  envelope: A2ARequestEnvelope
}
```

`onMessage` may return:
- a `string` — wrapped as a text artifact, status `completed`
- `{ text }` / `{ file }` / `{ data }` — single-part artifact shorthands
- `{ parts }` — full control over a single artifact's parts
- `{ artifacts }` — full control over multiple artifacts
- any of the above with `{ status: 'submitted' | 'completed' | 'failed' | 'canceled' }`

Hooks:
- `onUnverified(reason)` — fired before the handler returns 401. Use for logging.
- `onMissingExtensionHeader(sender)` — fired on a verified request that did not declare the extension URI. Informational only — the signature itself is the gate; the request still proceeds.

### Task lifecycle (`tasks/get`, `tasks/cancel`)

Every successful `message/send` produces a Task. The handler stores it in a `TaskStore` so subsequent `tasks/get` and `tasks/cancel` calls return real data instead of method-not-found.

The default store is in-memory and bounded to 1000 entries (oldest evicted past that). Replace it for multi-process or durable deployments:

```ts
import { createA2AHandler, InMemoryTaskStore } from '@envoys/a2a'

// Default — in-memory, max 1000 tasks
createA2AHandler({ onMessage: ... })

// Tune the in-memory cap
createA2AHandler({
  onMessage: ...,
  tasks: new InMemoryTaskStore({ maxSize: 10_000 }),
})

// Bring your own (Redis, SQL, etc.)
createA2AHandler({
  onMessage: ...,
  tasks: {
    async get(id) { /* ... */ },
    async set(id, task) { /* ... */ },
    async cancel(id) { /* ... */ },
  },
})

// Disable entirely — tasks/get and tasks/cancel return -32601
createA2AHandler({ onMessage: ..., tasks: null })
```

`tasks/cancel` semantics: a task in `submitted` state transitions to `canceled`. Tasks already in a terminal state (`completed`, `failed`, `canceled`) are returned unchanged. Async/long-running task execution (where the handler returns `submitted` and finishes work later) is not built in — bring your own runner that calls `store.set(id, completedTask)` when done.

### `buildAgentCard(opts)`

Builds an A2A v1.0 Agent Card. When `requireEnvoysSignature: true` is set, the card emits the extension URI in `capabilities.extensions` and a `securitySchemes.envoysSignature` entry per [spec §3](https://envoys.me/specs/signature/v1).

### Constants

```ts
import { ENVOYS_SIGNATURE_EXT_URI, ENVOYS_SECURITY_SCHEME } from '@envoys/a2a'

ENVOYS_SIGNATURE_EXT_URI  // 'https://envoys.me/specs/signature/v1'
ENVOYS_SECURITY_SCHEME    // 'envoysSignature'
```

## Spec

Behaviour is normative against [Envoys Signature Extension v1](https://envoys.me/specs/signature/v1). The URI is stable and versioned via path; this package targets `v1`.

## License

Apache-2.0
