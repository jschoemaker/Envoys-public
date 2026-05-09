import {
  generateKeyPairSync,
  randomBytes,
  createHash,
} from 'crypto'

export interface Keypair {
  publicKey: string  // PEM SPKI
  privateKey: string // PEM PKCS8
}

export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
  return { publicKey, privateKey }
}

export function generateToken(prefix: string): string {
  return `${prefix}_${randomBytes(24).toString('hex')}`
}

// SHA-256 hash of a token for safe storage.
// Tokens are already high-entropy (192 bits) so bcrypt is unnecessary.
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

