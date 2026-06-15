// DID Document resolution tests — verify extractEd25519FromDidDocument
// accepts both legacy Ed25519VerificationKey* types AND the W3C-standard
// JsonWebKey2020 wrapper used by modern did:web deployments (AlgoVoi etc).

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { Envoys } from '../index.js'

// The keyid/did:web resolution SSRF guard does a real DNS lookup on the host.
// Stub it so these fetch-stubbed tests stay hermetic — every host resolves to
// a public address, letting the DID-document parsing logic be exercised.
vi.mock('dns/promises', () => ({
  lookup: vi.fn(async () => [{ address: '93.184.216.34', family: 4 }]),
}))

// RFC 8032 §7.1 Test 1 public key in JWK form (base64url 32 bytes)
const TEST_JWK_X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'

function makeDidDoc(verificationMethod: any[]) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: 'did:web:test.example',
    verificationMethod,
  }
}

function stubFetch(doc: object) {
  const realFetch = globalThis.fetch
  globalThis.fetch = (async () => ({
    ok: true,
    status: 200,
    headers: { get: (n: string) => n.toLowerCase() === 'content-type' ? 'application/did+json' : null },
    json: async () => doc,
  })) as any
  return () => { globalThis.fetch = realFetch }
}

describe('resolveDidWeb / extractEd25519FromDidDocument', () => {
  beforeEach(() => Envoys.clearKeyCache())
  afterEach(() => Envoys.clearKeyCache())

  it('accepts Ed25519VerificationKey2020 (W3C SUITES form)', async () => {
    const restore = stubFetch(makeDidDoc([{
      id:         'did:web:test.example#k1',
      type:       'Ed25519VerificationKey2020',
      controller: 'did:web:test.example',
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: TEST_JWK_X },
    }]))
    try {
      const pem = await Envoys.resolveDidWeb('test.example')
      expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----/)
      expect(pem).toMatch(/-----END PUBLIC KEY-----\s*$/)
    } finally { restore() }
  })

  it('accepts JsonWebKey2020 (W3C generic JWK wrapper, AlgoVoi pattern)', async () => {
    const restore = stubFetch(makeDidDoc([{
      id:         'did:web:test.example#k1',
      type:       'JsonWebKey2020',
      controller: 'did:web:test.example',
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: TEST_JWK_X },
    }]))
    try {
      const pem = await Envoys.resolveDidWeb('test.example')
      expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----/)
    } finally { restore() }
  })

  it('rejects JsonWebKey2020 wrapping a non-Ed25519 JWK', async () => {
    const restore = stubFetch(makeDidDoc([{
      id:         'did:web:test.example#k1',
      type:       'JsonWebKey2020',
      controller: 'did:web:test.example',
      publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    }]))
    try {
      await expect(Envoys.resolveDidWeb('test.example')).rejects.toThrow(/No Ed25519 verification method/)
    } finally { restore() }
  })

  it('surfaces clear error for publicKeyMultibase (unsupported encoding)', async () => {
    const restore = stubFetch(makeDidDoc([{
      id:         'did:web:test.example#k1',
      type:       'Ed25519VerificationKey2020',
      controller: 'did:web:test.example',
      publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    }]))
    try {
      await expect(Envoys.resolveDidWeb('test.example')).rejects.toThrow(/publicKeyMultibase/)
    } finally { restore() }
  })
})
