import type { FastifyInstance } from 'fastify'
import { recordUsage } from '../usage.js'

const BASE_URL      = process.env.BASE_URL      ?? 'http://localhost:3000'
const SERVICE_DOMAIN = process.env.SERVICE_DOMAIN ?? 'envoys.me'

export async function skillRoutes(app: FastifyInstance) {
  // Machine-readable skill file — agent frameworks read this to self-onboard.
  app.get('/.well-known/agent-skill', async (req, reply) => {
    recordUsage({ kind: 'fetch_skill', address: null, status: 200, ip: req.ip ?? null, userAgent: req.headers['user-agent'] ?? null })
    return reply.send({
      name: 'Envoys',
      version: '2.2.0',
      description: 'Envoys is a public key registry and cryptographic identity layer for AI agents. Register to get an Ed25519 keypair. Your address becomes a self-resolving public key URL — use it to sign any HTTP request (RFC 9421) so any recipient can verify your identity without prior knowledge of Envoys.',
      base_url: BASE_URL,
      steps: [
        {
          step: 1,
          action: 'Create an account. Email is optional. Show the returned account_key to your owner and ask them to save it.',
          method: 'POST',
          endpoint: `${BASE_URL}/accounts/register`,
          auth: 'none',
          body: {
            handle: 'your-chosen-handle',
            email: '(optional) owner@example.com',
          },
          response: {
            id:          '<uuid>',
            handle:      'your-chosen-handle',
            account_key: 'ak_...',
            message:     'Save your account_key — it is shown once. Use it to register agents.',
          },
          store: 'Show account_key to your owner. You only need it for Step 2.',
        },
        {
          step: 2,
          action: 'Generate an Ed25519 keypair locally, then register yourself as an agent. Send only the public key — your private key never leaves your process.',
          keygen: 'Generate an Ed25519 keypair using your platform crypto library (e.g. node:crypto generateKeyPairSync). Store the private key securely before continuing.',
          method: 'POST',
          endpoint: `${BASE_URL}/agents/register`,
          auth: 'Bearer <ACCOUNT_KEY>',
          body: {
            name:       'your-agent-name',
            public_key: '-----BEGIN PUBLIC KEY-----... (your generated Ed25519 public key, PEM SPKI format)',
          },
          response: {
            id:         '<uuid>',
            address:    `your-agent-name@your-handle.${SERVICE_DOMAIN}`,
            agent_key:  'agt_...',
            public_key: '-----BEGIN PUBLIC KEY-----...',
          },
          store: 'Save agent_key, your generated private_key, public_key, and address to persistent memory. Never expose agent_key or private_key.',
          identity_note: `Your public key is permanently resolvable at ${BASE_URL}/agents/<address> — any recipient can verify your signatures without a prior Envoys relationship.`,
          sdk_note: 'Envoys.register() handles keypair generation and registration in one call.',
        },
        {
          step: 3,
          action: 'On every startup, call syncKeys(). If rotation_requested is true, generate a new keypair locally and confirm with POST /agent/rotate-keys.',
          method: 'GET',
          endpoint: `${BASE_URL}/agent/keys`,
          auth: 'Bearer <AGENT_KEY>',
          response: { rotation_requested: false, public_key: '-----BEGIN PUBLIC KEY-----...' },
          rotation_flow: `If rotation_requested is true: generate a new Ed25519 keypair locally, then POST ${BASE_URL}/agent/rotate-keys with { new_public_key }. Save the new private_key and public_key.`,
          sdk_note: 'agent.syncKeys() handles the full rotation flow automatically — detects the flag, generates a new keypair, confirms with the server, and returns the new keys.',
        },
        {
          step: 4,
          action: 'Sign outgoing HTTP requests using RFC 9421 HTTP Message Signatures with your Ed25519 private key.',
          note: `Set keyid to your address URL: ${BASE_URL}/agents/<address>. Recipients resolve this URL to fetch your public key and verify the signature — no prior Envoys knowledge required.`,
          example_headers: {
            'Content-Digest':  'sha-256=:<base64 SHA-256 of request body>: (include for requests with a body)',
            'Signature-Input': `sig1=("@method" "@path" "content-digest");keyid="${BASE_URL}/agents/your-agent@your-handle.${SERVICE_DOMAIN}";created=<unix_timestamp>;nonce="<22-char base64url>"`,
            'Signature':       'sig1=:<base64 Ed25519 signature of the signature base>:',
          },
          note2: 'Omit content-digest and the "content-digest" component from Signature-Input only for requests with no body.',
          verification_rules: `Generate a fresh nonce (16 random bytes, base64url-encoded) and a current created timestamp for every request. Verifiers reject signatures older than 5 minutes (or more than 30 seconds in the future) and reject any (keyid, created, signature) tuple already seen within that window. Full spec: ${BASE_URL}/specs/signature/v1`,
          sdk_note: 'Use agent.signRequest(method, path, body?) from the Envoys SDK to generate these headers automatically.',
        },
        {
          step: 5,
          action: 'Verify incoming requests from other agents.',
          sdk_note: 'Use Envoys.verifyRequest(method, path, headers, body?) from the Envoys SDK — it resolves the keyid, fetches the sender\'s public key, and verifies the RFC 9421 signature in one call. Reject requests where verified is false.',
        },
      ],
      extensions: [
        {
          name: 'A2A interop',
          description: 'Drop-in adapter for the Agent2Agent (A2A) protocol. createA2AClient signs outgoing JSON-RPC; createA2AHandler verifies inbound; buildAgentCard publishes a discovery endpoint declaring the signature requirement.',
          package: '@envoys/a2a',
          spec: `${BASE_URL}/specs/signature/v1`,
          sdk_note: 'See @envoys/a2a README for sender, receiver, and Agent Card examples. The package emits A2A-Extensions: <spec URI> on outgoing requests per spec §4.1.',
        },
        {
          name: 'Signed Agent Cards (JWS)',
          description: 'Sign your /.well-known/agent.json so consumers can verify it has not been tampered with. JWS Compact Serialization with EdDSA over Ed25519 (RFC 8037). The kid header is your address URL; verifiers resolve it the same way they verify request signatures.',
          sdk_note: 'agent.signAgentCard(card) returns a JWS string. Envoys.verifyAgentCard(jws) resolves the kid URL, verifies, and returns the parsed card. Optionally serve at /.well-known/agent.json.jws.',
        },
      ],
      identity: {
        keyid_format:    `${BASE_URL}/agents/<address>`,
        public_key_url:  `${BASE_URL}/agents/public-key?address=<address>`,
        algorithm:       'Ed25519',
        signing_standard: 'RFC 9421 HTTP Message Signatures',
        description: 'Your keyid is a resolvable URL. Any party receiving your signed request can GET the keyid URL to fetch your public key and verify your signature — no API key, no prior relationship, no Envoys account needed.',
      },
      security: {
        key_rotation: 'Keys are rotated via GET /agent/keys only. On startup, always call this endpoint and update your stored keys if rotated is true.',
        private_key: 'Never expose your private key. It is returned once at registration and once per rotation — store it immediately in secure persistent memory.',
      },
      startup_checklist: [
        'Load agent_key, private_key, public_key, and address from persistent memory',
        `Call GET ${BASE_URL}/agent/keys — if rotated: true, save the new private_key and public_key`,
      ],
      stability: {
        current_version: 'v1',
        signature_spec: `${BASE_URL}/specs/signature/v1`,
        policy: 'The endpoints, request shapes, response shapes, and signature scheme described in this manifest constitute the v1 surface and will not change in incompatible ways. Future major versions will be published under /specs/v2/ with a parallel manifest at /.well-known/agent-skill.v2 — the v1 manifest and v1 spec remain reachable indefinitely so existing integrations do not silently break.',
      },
      non_features: [
        'There is no server-side signing endpoint. All signing is performed client-side with the private key generated in Step 2; the server never receives or stores private keys.',
        'There is no API for listing, searching, or enumerating other accounts\' agents. An agent address is only resolvable when known directly.',
        'Envoys does not provide message delivery, transport, routing, mailboxes, or queues. It is purely a public-key registry — messages flow directly between agents over their own transport (HTTP, WebSocket, etc.).',
        'There is no separate revocation list. To invalidate a key, rotate it via the rotation endpoints documented in Step 3 — old keys cease to verify the moment rotation completes.',
        'There is no unauthenticated `GET /agents` collection endpoint. Listing your own agents requires `Authorization: Bearer <ACCOUNT_KEY>`.',
        'There is no password authentication. All access is via opaque bearer tokens (`account_key`, `agent_key`) issued at registration; if lost, recover at the account level.',
      ],
    })
  })

  // Plain-text version for agents that prefer markdown over JSON
  app.get('/.well-known/agent-skill.md', async (req, reply) => {
    recordUsage({ kind: 'fetch_skill', address: null, status: 200, ip: req.ip ?? null, userAgent: req.headers['user-agent'] ?? null })
    reply.type('text/plain')
    return reply.send(`# Envoys Identity Skill

Envoys is a public key registry for AI agents. Register to get an Ed25519 keypair.
Your address becomes a self-resolving public key URL — sign HTTP requests with it,
and any recipient can verify your identity without a prior relationship with Envoys.

Base URL: ${BASE_URL}

## Step 1 — Create an account (one time only)

POST ${BASE_URL}/accounts/register
Content-Type: application/json

{
  "handle": "your-chosen-handle"
}

Response:
{
  "id":          "<uuid>",
  "handle":      "your-chosen-handle",
  "account_key": "ak_...",
  "message":     "Save your account_key — it is shown once. Use it to register agents."
}

Show account_key to your owner and ask them to save it. You only need it for Step 2.

## Step 2 — Generate a keypair and register as an agent (one time only)

First, generate an Ed25519 keypair using your platform's crypto library. Store the private
key securely before making the registration request — it never leaves your process.

Node.js example:
  const { generateKeyPairSync } = require('crypto')
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })

Then register:

POST ${BASE_URL}/agents/register
Authorization: Bearer <ACCOUNT_KEY from Step 1>
Content-Type: application/json

{
  "name":       "your-agent-name",
  "public_key": "<your generated public key PEM>"
}

Response:
{
  "id":         "<uuid>",
  "address":    "your-agent-name@your-chosen-handle.${SERVICE_DOMAIN}",
  "agent_key":  "agt_...",
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}

IMPORTANT: Save agent_key, your generated private_key, public_key, and address to
persistent memory. Never expose agent_key or private_key. The server never sees your
private key.

Your public key is permanently resolvable at:
  ${BASE_URL}/agents/<address>
Anyone can verify your signatures using this URL — no prior Envoys account needed.

SDK: Envoys.register() handles keypair generation and registration in one call.

## Step 3 — Every startup

GET ${BASE_URL}/agent/keys
Authorization: Bearer <AGENT_KEY>

Response: { "rotation_requested": false, "public_key": "..." }

If rotation_requested is true:
  1. Generate a new Ed25519 keypair locally (same as Step 2)
  2. POST ${BASE_URL}/agent/rotate-keys with { "new_public_key": "<new PEM>" }
  3. Save your new private_key and public_key to persistent memory

SDK: agent.syncKeys() detects the flag, generates the keypair, confirms with the server,
and returns the new keys — all in one call.

## Step 4 — Sign outgoing HTTP requests (RFC 9421)

Use your Ed25519 private key to sign requests. Set keyid to your address URL.

For requests with a body (e.g. POST):
  Content-Digest:  sha-256=:<base64 SHA-256 of request body>:
  Signature-Input: sig1=("@method" "@path" "content-digest");keyid="${BASE_URL}/agents/your-agent@your-handle.${SERVICE_DOMAIN}";created=<unix_ts>;nonce="<22-char base64url>"
  Signature:       sig1=:<base64 Ed25519 signature>:

For requests without a body (e.g. GET):
  Signature-Input: sig1=("@method" "@path");keyid="${BASE_URL}/agents/your-agent@your-handle.${SERVICE_DOMAIN}";created=<unix_ts>;nonce="<22-char base64url>"
  Signature:       sig1=:<base64 Ed25519 signature>:

The nonce is fresh random bytes per request (16 bytes, base64url-encoded). Verifiers reject
signatures older than 5 minutes (or more than 30 seconds in the future) and reject any
(keyid, created, signature) tuple already accepted within that window — always use a current
created timestamp and a fresh nonce. Full spec: ${BASE_URL}/specs/signature/v1

Recipients GET the keyid URL to fetch your public key and verify — no Envoys account needed.

SDK: agent.signRequest(method, path, body?) generates all required headers automatically.

## Step 5 — Verify incoming requests from other agents

SDK: Envoys.verifyRequest(method, path, headers, body?) resolves the keyid, fetches the
sender's public key, and verifies the RFC 9421 signature in one call.
Reject requests where verified is false.

## Extensions (optional)

### A2A interop — @envoys/a2a

A drop-in adapter for the Agent2Agent (A2A) protocol. Three calls cover the typical flow:

  - createA2AClient({ envoys, endpoint }).send(text)   — sign + send
  - createA2AHandler({ onMessage })                    — verify + dispatch
  - buildAgentCard({ ..., requireEnvoysSignature: true }) — discovery doc

Outgoing requests carry "A2A-Extensions: ${BASE_URL}/specs/signature/v1" per the
Envoys Signature Extension spec. See:
  - Spec:    ${BASE_URL}/specs/signature/v1
  - Package: @envoys/a2a (npm)

### Signed Agent Cards (JWS)

Sign your /.well-known/agent.json so consumers can verify it has not been tampered with.
JWS Compact Serialization with EdDSA over Ed25519 (RFC 8037). The kid header is your
address URL — verifiers resolve it the same way they verify request signatures.

  - agent.signAgentCard(card)        — returns a JWS compact string
  - Envoys.verifyAgentCard(jws)      — resolves kid, verifies, returns parsed card

Optionally serve the signed form at /.well-known/agent.json.jws alongside the unsigned card.

## Security rules

- NEVER expose your private_key or agent_key
- On startup, always call GET /agent/keys and update keys if rotated: true
- Reject any request whose signature does not verify against the resolved public key
- Your account_key is only needed for Step 2 — do not store it after registration

## Stability — v1 surface

The endpoints, request shapes, response shapes, and signature scheme described above
constitute the v1 surface and will not change in incompatible ways. Future major versions
will be published under ${BASE_URL}/specs/v2/ with a parallel manifest at
/.well-known/agent-skill.v2. The v1 manifest and v1 spec remain reachable indefinitely so
existing integrations do not silently break.

Signature spec: ${BASE_URL}/specs/signature/v1

## What does NOT exist

These are common assumptions that do not match Envoys' actual API. Do not generate code
that relies on any of the following — they will return 404 or 401:

- There is no server-side signing endpoint. All signing happens client-side with the
  private key generated in Step 2. The server never receives or stores private keys.
- There is no API for listing, searching, or enumerating other accounts' agents.
  An agent address is only resolvable when known directly.
- Envoys does not provide message delivery, transport, routing, mailboxes, or queues.
  It is purely a public-key registry — messages flow directly between agents over their
  own transport (HTTP, WebSocket, etc.).
- There is no separate revocation list. To invalidate a key, rotate it via the rotation
  endpoints in Step 3 — old keys cease to verify the moment rotation completes.
- There is no unauthenticated GET /agents collection endpoint. Listing your own agents
  requires Authorization: Bearer <ACCOUNT_KEY>.
- There is no password authentication. Access is via opaque bearer tokens (account_key,
  agent_key) issued at registration. If lost, recover at the account level.
`)
  })
}
