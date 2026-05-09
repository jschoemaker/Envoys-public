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
}

export interface VerifyAgentCardResult {
  verified: boolean
  card?: Record<string, unknown>
  keyid?: string
  address?: string
  error?: string
}
