export interface EnvoysConfig {
  agentKey: string
  address: string
  publicKey: string
  privateKey?: string  // enables signing
  baseUrl?: string
}

export interface RegisterOptions {
  accountKey: string
  name: string
  capabilities?: string[]
  baseUrl?: string
}

export interface RegisterResult {
  id: string
  address: string
  agentKey: string
  publicKey: string
  privateKey: string  // store securely — shown once
}

export interface KeySyncResult {
  rotated: boolean
  publicKey: string
  privateKey?: string  // present only if rotated
}

export interface VerifyRequestResult {
  // True only if every check passed: signature valid, timestamp in window,
  // no replay, public key still matches the pin (if pinning is on), and the
  // keyid is in the allowlist (if one was provided).
  verified: boolean
  // Identity fields are populated whenever the data is available, even on a
  // failed verification — so callers can log or surface "we tried to verify
  // a request claiming to be from X" rather than a bare boolean. Always check
  // `verified` AND `keyid` (or `address`) before trusting the request.
  keyid: string | null
  address: string | null
  publicKey: string | null
  error: string | null
}

// Pluggable storage for first-seen public keys. Default implementation is an
// in-process Map; for production use a persistent store so a process restart
// doesn't reset every counterparty's pin and re-open the silent-takeover gap.
export interface PinStore {
  get(address: string): string | null | Promise<string | null>
  set(address: string, publicKey: string): void | Promise<void>
  delete(address: string): void | Promise<void>
  clear(): void | Promise<void>
}

// Controls the guarded fetch the verifier performs when resolving a keyid URL.
// The keyid is sender-controlled, so its resolution is treated as an untrusted
// outbound request (SSRF surface). Defaults are safe; override only when you
// know what you're doing (e.g. allowPrivateHosts for local integration tests).
export interface ResolverGuardOptions {
  // Abort the resolution fetch after this many milliseconds. Default 5000.
  timeoutMs?: number

  // Reject resolution responses larger than this many bytes (a public key fits
  // in <1 kB; a single-key DID Document in <2 kB). Default 16384.
  maxResponseBytes?: number

  // Allow the keyid host to resolve to a loopback/private/link-local address.
  // Default false — such hosts are rejected to prevent SSRF into internal
  // services and cloud metadata endpoints. Set true ONLY for local testing.
  allowPrivateHosts?: boolean

  // Allow non-HTTPS (http:) keyid URLs. Default false — https is required so a
  // network attacker cannot strip transport security from key resolution. Set
  // true ONLY for local testing.
  allowInsecureHttp?: boolean
}

export interface VerifyRequestOptions {
  // Restrict acceptable senders. Each entry is either an address
  // ("alice@acme.envoys.me") or a full keyid URL. A signed request from any
  // counterparty not in this list is rejected even if cryptographically valid.
  // Bootstrap your allowlist out-of-band — DNS, a published contract, or a
  // manual handshake. Do not infer trust from a successful signature alone.
  allowlist?: string[]

  // Pin the first-seen public key per address. On every subsequent contact,
  // raise a verification failure if the resolved key differs. Catches account
  // compromise → silent rotation. Default: true. Disable only if you're
  // explicitly tolerating rotations (and have a separate detection signal).
  pinByPublicKey?: boolean

  // Override the default in-process pin store with persistent storage.
  pinStore?: PinStore

  // The authority (host, optionally host:port) this verifier is serving.
  // Used to reconstruct the @authority component when a signature covers it.
  // If omitted, the request's Host header is used. Set this explicitly when
  // running behind a proxy that rewrites Host.
  authority?: string

  // SSRF guards applied when fetching the (sender-controlled) keyid URL.
  // See ResolverGuardOptions. Defaults are safe; usually leave unset.
  resolver?: ResolverGuardOptions
}

export interface VerifyAgentCardResult {
  verified: boolean
  card?: Record<string, unknown>
  keyid?: string
  address?: string
  error?: string
}
