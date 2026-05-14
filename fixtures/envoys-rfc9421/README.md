# envoys-rfc9421 conformance fixtures

Cross-extension byte-match fixtures for the Envoys signature extension
(`https://envoys.me/specs/signature/v1` v1.5.0). Companion to the CTEF
v0.3.3 cross-extension fixture matrix
(`agentgraph-co/agentgraph/blob/main/docs/standards/v0.3.3-working-doc.md`,
Artifact 3, Envoys row).

## What this fixture set is

Reproducible RFC 9421 + Ed25519 signed-request vectors pinned to the
RFC 8032 §7.1 Test 1 keypair. Any conformant verifier can:

1. Load `keypair.json` (public, intentional — published RFC test vector).
2. Read a vector from `positive/` or `negative/`.
3. Reconstruct the signature base per RFC 9421 from the declared components
   and parameters.
4. For positive vectors: assert the computed signature equals
   `expected.signature` byte-for-byte.
5. For negative vectors: assert the verifier rejects the request with the
   declared `expected.error_code`.

The positive set covers spec §4–§6 wire format and the v1.5 additions
(`tag` parameter, SHA-512 auto-promotion, dual-shape `keyid` resolution).
The negative set covers §5.1–§5.3 + §7 rejection paths.

Pairs with `aeoess/aps-conformance-suite/fixtures/composition/envoys-rfc9421/`
(commit `c16aa04`) which independently validates against Envoys §14 Vector 2.

## Format

`manifest.json` indexes every vector with its file path, the spec section
it exercises, and a one-line description. Each vector file is a
self-contained JSON document; you do not need to read the manifest to
verify any single vector.

Positive-vector files have this shape:

```json
{
  "id": "vec-1-get-no-body",
  "spec_ref": "v1.5.0 §14 Vector 1",
  "description": "GET request, no body — minimal signed request shape.",
  "inputs": {
    "method": "GET",
    "path": "/api/health",
    "body": null,
    "keyid": "https://envoys.me/agents/test@rfc8032-vec1.example",
    "created": 1714000000,
    "nonce": "AAECAwQFBgcICQoLDA0ODw"
  },
  "expected": {
    "content_digest": "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    "signature_input": "sig1=(\"@method\" \"@path\" \"content-digest\");keyid=\"https://envoys.me/agents/test@rfc8032-vec1.example\";created=1714000000;nonce=\"AAECAwQFBgcICQoLDA0ODw\"",
    "signature_base": "\"@method\": GET\n\"@path\": /api/health\n\"content-digest\": sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:\n\"@signature-params\": (\"@method\" \"@path\" \"content-digest\");keyid=\"https://envoys.me/agents/test@rfc8032-vec1.example\";created=1714000000;nonce=\"AAECAwQFBgcICQoLDA0ODw\"",
    "signature": "XUpjUHt36NbHgAZrQkFY2fSNUR19tgmRlGO1dBhaZDgBv4wb55qgJf2buv3wgnTYwtT+1sH2jzSbcgG6FLGKCA=="
  }
}
```

Negative-vector files add `expected.error_code` and replace
`expected.signature` with a description of what should fail and where:

```json
{
  "id": "vec-n1-content-digest-mismatch",
  "spec_ref": "v1.5.0 §5.3",
  "description": "Body bytes differ from the signed Content-Digest; verifier MUST reject before signature check.",
  "inputs": { ... },
  "expected": {
    "error_code": "-32001",
    "http_status": 401,
    "failure_layer": "wire",
    "failure_field": "content-digest",
    "rejection_stage": "pre-signature-verification"
  }
}
```

## Reproducibility

All six positive vectors are computed by `scripts/gen-fixtures.mjs` from a
single set of canonical inputs. `node scripts/gen-fixtures.mjs --check`
re-derives every `content_digest` / `signature_input` / `signature_base` /
`signature` and asserts the committed fixture JSON matches — run it after
any edit to confirm nothing drifted.

| File | State | Notes |
|---|---|---|
| `positive/vec-1-get-no-body.json` | ✅ computed | Mirrors spec §14 Vector 1 verbatim |
| `positive/vec-2-post-json-body.json` | ✅ computed | Mirrors spec §14 Vector 2; matches `aeoess@c16aa04` |
| `positive/vec-3-post-empty-body.json` | ✅ computed | Mirrors spec §14 Vector 3 |
| `positive/vec-4-tag-param.json` | ✅ computed | `tag="task"` in Signature-Input and signature base |
| `positive/vec-5-sha512-large-body.json` | ✅ computed | JSON body serializing to exactly 4096 bytes, SHA-512 auto-promotion per §4.2 |
| `positive/vec-6-dual-shape-did-document.json` | ✅ computed | Same wire signature as Vector 2; keyid serves a DID Document under `keyid_response` |
| `negative/vec-n1-content-digest-mismatch.json` | ✅ defined | No signature to compute — verifier must reject pre-signature |
| `negative/vec-n2-expired-timestamp.json` | ✅ defined | `created` older than 300s before "now" reference |
| `negative/vec-n3-replay.json` | ✅ defined | Same `(keyid, created, signature)` tuple as a vector seen earlier |

Status: **first draft** for the CTEF v0.3.3 cross-extension matrix
(target May 22, 2026). All positive vectors carry computed signatures
pinned to the RFC 8032 §7.1 keypair.

## Verifying

```bash
node scripts/verify-fixtures.mjs fixtures/envoys-rfc9421/
```

`verify-fixtures.mjs` walks `manifest.json` and, for each vector:

- **positive** — reconstructs the RFC 9421 signature base from `inputs`,
  recomputes the Content-Digest, asserts both match the committed
  `expected` values, then verifies the Ed25519 `signature` against the
  public key in `keypair.json`.
- **negative** — asserts the declared rejection condition holds (digest
  mismatch, timestamp outside the window, or a replayed
  `(keyid, created, signature)` tuple).

It exits non-zero on any failure, so it drops straight into CI or an
aggregate `npm test`. The vector format is implementation-neutral — a
verifier in any language can consume the same `manifest.json` + vector
files.

### Cross-walking other suites

`verify-fixtures.mjs` is pluggable per fixture format — a `--format`
adapter normalizes each source into one internal vector shape, and the
verification core is shared:

```bash
node scripts/verify-fixtures.mjs <path-to-aim-fixtures> --format aim
```

`aim` walks the AIM `aim-did-rfc9421` composition fixtures
(`opena2a-org/a2a-idf-conformance`) and verifies their wire layer — the
RFC 9421 signature, which is where the cross-suite byte-match lives. The
envelope (bilateral receipt, delegation chain) is framework-layer and
out of scope for this check, matching how AIM's own fixtures scope the
conformance claim. A `hippo` adapter is stubbed pending
`opena2a-org/a2a-idf-conformance#2` merging — the format is still under
revision.

This is **mesh participation, not an arbiter**: the Envoys verifier
validating AIM's wire layer is one node checking another, the same way
AIM's verifiers and aeoess's suite cross-check Envoys. It is not a
neutral central validator — that role wants a clean-room implementation
independent of every provider.

### SDK cross-check

`scripts/sdk-cross-check.mjs` runs the same fixtures through
`@envoys/sdk`'s `Envoys.verifyRequest()` — a separate signature-base
reconstruction from `verify-fixtures.mjs`. Build the SDK first
(`pnpm --filter @envoys/sdk build`), then `node
scripts/sdk-cross-check.mjs`. Both passing means two independent Envoys
implementations agree on the vector set, not the generator agreeing
with itself.

## License

Apache-2.0. Same as `@envoys/sdk`.
