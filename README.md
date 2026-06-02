# Envoys

Cryptographic identity for AI agents. Ed25519 keypairs, RFC 9421 HTTP Message Signatures, self-resolving public keys.

Live at **[envoys.me](https://envoys.me)** · Spec: [`/specs/signature/v1`](./specs/signature/v1.md) · Source: **[github.com/jschoemaker/Envoys-public](https://github.com/jschoemaker/Envoys-public)**

---

## What it is

Agents on the internet have no standard way to prove who they are. Envoys fixes that.

Register once to get an Ed25519 keypair. Your address (`name@handle.envoys.me`) becomes a resolvable public key URL. Sign any outgoing HTTP request with RFC 9421. Any recipient can verify — no prior relationship with Envoys required, no API keys, no shared secrets.

**The private key is generated in your process and never transmitted to Envoys.**

---

## Install

```bash
npm install @envoys/sdk
# Optional — adapter for the Agent2Agent (A2A) protocol
npm install @envoys/a2a
```

---

## Quickstart

```ts
import { Envoys } from '@envoys/sdk'

// 1. Register once (generates keypair locally; private key never leaves)
const { result } = await Envoys.register({
  accountKey: 'ak_...',
  name:       'researcher',
})
// → { address, agentKey, publicKey, privateKey }
// Save all four — privateKey is shown once.

// 2. Construct from env vars in your running agent
//    Reads ENVOYS_AGENT_KEY / ADDRESS / PUBLIC_KEY / PRIVATE_KEY
const agent = Envoys.fromEnv()

// 3. Sign any outgoing HTTP request (RFC 9421 + Content-Digest)
const body    = { task: 'summarize', url: 'https://example.com/doc' }
const headers = agent.signRequest('POST', '/api/task', body)

await fetch('https://other-agent.example.com/api/task', {
  method:  'POST',
  headers: { 'Content-Type': 'application/json', ...headers },
  body:    JSON.stringify(body),
})

// 4. Verify incoming signed requests in any HTTP handler.
//    Public-key pinning is on by default; pass an allowlist to gate authorization.
const result = await Envoys.verifyRequest(
  req.method, req.path, req.headers, req.body,
  { allowlist: ['researcher@trusted-peer.envoys.me'] }, // optional
)
if (!result.verified) return res.status(401).json({ error: result.error })
console.log(`Verified ${result.address}`, result.keyid, result.publicKey)
```

---

## A2A integration

[`@envoys/a2a`](./packages/a2a) is a drop-in adapter for the Agent2Agent (A2A) protocol. It wraps the SDK with helpers for signed JSON-RPC, file/data parts, and task lifecycle methods.

```ts
import { Envoys }                              from '@envoys/sdk'
import { createA2AClient, createA2AHandler,
         buildAgentCard }                      from '@envoys/a2a'

// Receiver — verifies inbound signatures, dispatches verified messages
const handle = createA2AHandler({
  onMessage: ({ sender, text }) => `Echo from ${sender}: ${text}`,
})

app.get('/.well-known/agent.json', () => buildAgentCard({
  name:                   'Echo Agent',
  url:                    'https://echo.example.com',
  skills:                 [{ id: 'echo', name: 'Echo' }],
  requireEnvoysSignature: true,    // declares the spec at /specs/signature/v1
}))

app.post('/', async (req, reply) => {
  const out = await handle({ method: 'POST', path: '/', headers: req.headers, body: req.body })
  return reply.code(out.status).send(out.body)
})

// Sender — signs + sends an A2A JSON-RPC message
const a2a   = createA2AClient({ envoys: Envoys.fromEnv(), endpoint: 'https://echo.example.com/' })
const reply = await a2a.send('Hello, peer.')
console.log(reply.text)        // verified response text
```

`@envoys/a2a` also handles `tasks/get`, `tasks/cancel`, and file/data parts. See [its README](./packages/a2a/README.md) for the full API.

---

## Using Envoys with…

The handler is framework-agnostic — `handle({ method, path, headers, body })` returns `{ status, body }` that you write back through your framework's response API. A few shims:

**Fastify** (used in the canonical example)
```ts
app.post('/', async (req, reply) => {
  const out = await handle({ method: 'POST', path: '/', headers: req.headers, body: req.body })
  return reply.code(out.status).send(out.body)
})
```

**Express**
```ts
app.post('/', express.json(), async (req, res) => {
  const out = await handle({ method: 'POST', path: '/', headers: req.headers, body: req.body })
  res.status(out.status).json(out.body)
})
```

**Hono / Cloudflare Workers** (any Web-standard `Request`)
```ts
app.post('/', async (c) => {
  const body = await c.req.json()
  const out  = await handle({ method: 'POST', path: '/', headers: Object.fromEntries(c.req.raw.headers), body })
  return c.json(out.body, out.status)
})
```

**Microsoft Foundry / Azure Functions / hosted A2A runtimes** — load the agent's keypair from the runtime's secret store, construct `Envoys.fromEnv()`, and use `createA2AClient` to sign outbound A2A calls. Recipients on any platform (open-source, Anthropic, OpenAI Agents, etc.) verify the signature without trusting the host's IdP. The signature spec is the contract; nothing about Foundry's auth model interferes.

**Any other language** — the [signature spec](./specs/signature/v1.md) is normative. RFC 9421 + Ed25519 implementations exist in Python, Go, Rust, and most languages. The verifier-side is just one HTTP GET (the keyid URL) plus a stdlib signature check — no SDK required.

---

## How it works

1. **Register** — Envoys stores your public key, indexed by your address.
2. **Sign** — Attach `Signature-Input`, `Signature`, `Content-Digest` headers (RFC 9421). The `keyid` is your address URL: `https://envoys.me/agents/you@your-handle.envoys.me`. Each signature includes a fresh `nonce`.
3. **Verify** — The recipient GETs your keyid URL to fetch your public key, reconstructs the signature base, and verifies. No Envoys account needed to verify.

Replay protection: the SDK rejects signatures older than 5 minutes, more than 30 seconds in the future, with a tampered `Content-Digest`, or any signature already accepted (in-process dedup cache keyed by `(keyid, created, signature)`).

### Verifier-side safety defaults (SDK 0.6.0+)

`Envoys.verifyRequest()` enforces two additional checks on top of the cryptographic verification, both designed to make the safe pattern the easy pattern:

- **Public-key pinning (on by default)** — first-seen public key is auto-recorded per address; subsequent contact with a different key fails verification with a clear `Envoys.resetPin('<address>')` hint. Catches account-compromise rotations that would otherwise resolve cleanly.
- **Optional allowlist** — pass `{ allowlist: [...] }` to reject cryptographically-valid requests from senders not on your list. The allowlist matches against keyid OR address. Use this as the authorization layer separate from the identity check — a verified signature proves *who*, not *whether-allowed*.

Pin storage is pluggable via the `PinStore` interface; default is in-process Map. Pair with the `/agents/revocations` feed (below) to invalidate pins on confirmed rotations.

---

## Protocol spec

The on-the-wire behaviour is normative against the **Envoys Signature Extension v1** at [`/specs/signature/v1`](./specs/signature/v1.md). The URI is stable and versioned via path. Implementations should reference it from their A2A Agent Cards and treat it as the contract.

---

## Key rotation

Rotations are initiated via the API. The new private key is **always generated client-side** — Envoys never sees it.

```ts
// Account holder triggers rotation:
//   POST /agents/:id/rotate-keys   (account key auth)

// On next agent startup, syncKeys() detects the flag, generates a new keypair
// locally, confirms with the server, and returns the new keys:
const { rotated, publicKey, privateKey } = await agent.syncKeys()
if (rotated) saveToStorage({ publicKey, privateKey })
```

---

## Custom domains

Use `name@yourteam.com` instead of `name@yourteam.envoys.me`. Add a DNS TXT record for verification, then pass `domain` when registering agents.

## Verified handles

Anchor your handle to a real-world domain via DNS TXT record. Resolvers surface `verified_handle: { domain, verified_at }` in `/agents/:address` responses — a real-world identity claim outside the first-come-first-served handle pool. Required record: `_envoys-handle.<domain>` IN TXT `envoys-handle-verify=<token>`. Initiate via `POST /accounts/me/verify-handle` (account key auth).

Custom-domain addresses (`name@example.com`) get the parallel `verified_domain: { domain, verified_at }` field, populated when the domain has been DNS-verified per the Custom domains section above. At most one of `verified_handle` / `verified_domain` is non-null per response.

---

## Access

Envoys is in **closed beta** while the public-key resolver is hardened and capacity is tuned. Request access at [envoys.me](https://envoys.me) — slots open regularly.

The signature spec, SDK, and `@envoys/a2a` adapter are public. **Verifying signatures requires no Envoys account, no API key, no registration** — read the [spec](./specs/signature/v1.md) and `npm install @envoys/sdk` to build a verifier today.

---

## API reference

Base URL: `https://envoys.me`

### Identity

| Method | Endpoint                       | Auth         | Description                                       |
|--------|--------------------------------|--------------|---------------------------------------------------|
| POST   | `/accounts/register`           | —            | Create account — returns `account_key`, shown once (no recovery) |
| DELETE | `/accounts/me`                 | account key  | Delete your account (agents revoked, key history preserved)      |
| POST   | `/agents/register`             | account key  | Register agent (send your generated public key)   |
| GET    | `/agents/:address`             | —            | Resolve public key (this is the keyid URL)        |
| GET    | `/agent/keys`                  | agent key    | Check for pending rotation                        |
| POST   | `/agent/rotate-keys`           | agent key    | Confirm rotation with new public key              |
| POST   | `/agents/:id/rotate-keys`      | account key  | Request rotation for an agent                     |
| DELETE | `/agents/:id`                  | account key  | Revoke an agent (address permanently bound)       |

### Transparency (for verifiers)

| Method | Endpoint                              | Auth | Description                                                                  |
|--------|---------------------------------------|------|------------------------------------------------------------------------------|
| GET    | `/agents/:address/key-history`        | —    | Every public key ever bound to an address with validity periods              |
| GET    | `/agents/revocations?since=<unix_ms>` | —    | CRL-style feed — addresses whose key changed (rotated/revoked) since `since` |

### Domain attestation

| Method | Endpoint                                | Auth        | Description                                                  |
|--------|-----------------------------------------|-------------|--------------------------------------------------------------|
| POST   | `/accounts/me/verify-handle`            | account key | Initiate DNS-TXT proof; returns the TXT record to add        |
| POST   | `/accounts/me/verify-handle/check`      | account key | Check DNS and mark verified                                  |
| GET    | `/accounts/me/verify-handle`            | account key | Read current verification state                              |
| DELETE | `/accounts/me/verify-handle`            | account key | Remove the attestation                                       |

Machine-readable onboarding for agents: [`/.well-known/agent-skill`](https://envoys.me/.well-known/agent-skill) · [`/.well-known/agent-skill.md`](https://envoys.me/.well-known/agent-skill.md)

---

## Monorepo structure

```
envoys/
├── packages/
│   ├── sdk/        @envoys/sdk — Ed25519 + RFC 9421 + JWS card signing
│   ├── a2a/        @envoys/a2a — Agent2Agent protocol adapter
│   └── api/        Fastify server backing envoys.me (node:sqlite)
├── examples/
│   └── a2a/        Signed sender + verifying receiver demo
└── specs/
    └── signature/v1.md   Protocol spec (stable, versioned URI)
```

---

## Development

```bash
pnpm install
pnpm --filter envoys-api dev      # API on :3000
pnpm -r build                     # build all packages
pnpm -r test                      # run all tests (~142 across the workspace)
```

---

## License

Apache-2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
