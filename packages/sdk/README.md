# @envoys/sdk

Cryptographic identity for AI agents. Ed25519 keypairs, RFC 9421 HTTP Message Signatures, self-resolving public keys.

Live at **[envoys.me](https://envoys.me)** · Spec: [`/specs/signature/v1`](https://envoys.me/specs/signature/v1)

---

## What it is

Agents on the internet have no standard way to prove who they are. Envoys fixes that.

Register once to get an Ed25519 keypair. Your address (`name@handle.envoys.me`) becomes a resolvable public key URL. Sign any outgoing HTTP request with RFC 9421. Any recipient can verify — no prior relationship with Envoys required, no API keys, no shared secrets.

**The private key is generated in your process and never transmitted to Envoys.**

---

## Install

```bash
npm install @envoys/sdk
```

For the [Agent2Agent (A2A) protocol](https://envoys.me/specs/signature/v1) adapter:

```bash
npm install @envoys/a2a
```

---

## Quickstart

```ts
import { Envoys } from '@envoys/sdk'

// 1. Register once (generates keypair locally; private key never leaves)
const { result } = await Envoys.register({
  accountKey: process.env.ENVOYS_ACCOUNT_KEY,
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

## How it works

1. **Register** — Envoys stores your public key, indexed by your address.
2. **Sign** — Attach `Signature-Input`, `Signature`, `Content-Digest` headers (RFC 9421). The `keyid` is your address URL: `https://envoys.me/agents/you@your-handle.envoys.me`. Each signature includes a fresh `nonce`. Bodies ≥4KB auto-promote from `sha-256` to `sha-512` for the digest.
3. **Verify** — The recipient GETs your keyid URL to fetch your public key, reconstructs the signature base, and verifies. No Envoys account needed to verify.

Replay protection: the SDK rejects signatures older than 5 minutes, more than 30 seconds in the future, with a tampered `Content-Digest`, or any signature already accepted (in-process dedup cache keyed by `(keyid, created, signature)`).

### Verifier-side safety defaults

`Envoys.verifyRequest()` enforces two checks on top of cryptographic verification:

- **Public-key pinning (on by default)** — first-seen public key is auto-recorded per address; subsequent contact with a different key fails verification with a clear `Envoys.resetPin('<address>')` hint. Catches account-compromise rotations that would otherwise resolve cleanly.
- **Optional allowlist** — pass `{ allowlist: [...] }` to reject cryptographically-valid requests from senders not on your list. The allowlist matches against keyid OR address.

Pin storage is pluggable via the `PinStore` interface; default is in-process Map.

### Dual-shape keyid resolution (W3C DID interop)

The verifier accepts either shape served at a `keyid` URL:

- **`application/did+json`** → W3C DID Document with an Ed25519 `verificationMethod` (`publicKeyJwk`)
- **`application/json`** or any other JSON content type → Envoys-native `{ address, public_key }`

No caller-side opt-in is required — `Envoys.verifyRequest()` sniffs `Content-Type` (with structural fallback) and routes to the right parser. Signatures from agents whose `keyid` happens to serve a DID Document verify the same as signatures from Envoys-native agents. Both ship with spec `/specs/signature/v1` §6.

For explicit did:web bridging, `Envoys.resolveDidWeb(domain)` returns a PEM SPKI from a `https://<domain>/.well-known/did.json` document. The lower-level `Envoys.resolveKeyFromKeyid(keyidUrl)` does the dual-shape fetch directly and is what the verifier calls internally.

### Optional: per-signature `tag`

`signRequest` accepts an optional `tag` parameter (RFC 9421 §2.3) to disambiguate signing purpose under one `keyid` — for example `"task"`, `"heartbeat"`, or `"delegation"`. Verifiers MAY enforce that the tag matches the expected context. Absence is equivalent to `tag="a2a-message"`.

```ts
const headers = agent.signRequest('POST', '/api/task', body, { tag: 'task' })
```

---

## Key rotation

Rotations are initiated from the dashboard or the API. The new private key is **always generated client-side** — Envoys never sees it.

```ts
const { rotated, publicKey, privateKey } = await agent.syncKeys()
if (rotated) saveToStorage({ publicKey, privateKey })
```

---

## Use it from any language

The verifier-side is just one HTTP GET (the keyid URL) plus a stdlib Ed25519 signature check. The [signature spec](https://envoys.me/specs/signature/v1) is normative — RFC 9421 + Ed25519 implementations exist in Python, Go, Rust, and most major languages.

---

## License

Apache-2.0
