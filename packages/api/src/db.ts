import { DatabaseSync } from 'node:sqlite'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DB_PATH = process.env.DB_PATH ?? join(__dirname, '../../envoys.db')

export const db = new DatabaseSync(DB_PATH)

db.exec('PRAGMA journal_mode = WAL')
db.exec('PRAGMA foreign_keys = ON')

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id                  TEXT PRIMARY KEY,
    email               TEXT UNIQUE,
    account_key         TEXT UNIQUE NOT NULL,
    handle              TEXT UNIQUE NOT NULL,
    created_at          INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS agents (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id),
    name         TEXT NOT NULL,
    address      TEXT UNIQUE NOT NULL,
    agent_key    TEXT UNIQUE NOT NULL,
    public_key   TEXT NOT NULL,
    capabilities TEXT NOT NULL DEFAULT '[]',
    revoked      INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS pending_keys (
    agent_id    TEXT PRIMARY KEY REFERENCES agents(id),
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL,
    expires_at  INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS custom_domains (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL REFERENCES accounts(id),
    domain       TEXT UNIQUE NOT NULL,
    verify_token TEXT NOT NULL,
    verified     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_agents_account   ON agents(account_id);
  CREATE INDEX IF NOT EXISTS idx_domains_account  ON custom_domains(account_id);

  CREATE TABLE IF NOT EXISTS usage_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    address    TEXT,
    status     INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_usage_events_ts      ON usage_events(ts);
  CREATE INDEX IF NOT EXISTS idx_usage_events_address ON usage_events(address);
  CREATE INDEX IF NOT EXISTS idx_usage_events_kind_ts ON usage_events(kind, ts);

  -- Append-only history of every public key ever bound to an address.
  -- Each row represents a validity period: valid_from is set at insertion;
  -- valid_until is null while the key is current and gets stamped on the next
  -- rotation or on revocation. Verifiers can query this to detect silent
  -- identity takeover (key changed unexpectedly) and to audit historical state.
  CREATE TABLE IF NOT EXISTS public_key_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    address     TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    valid_from  INTEGER NOT NULL,
    valid_until INTEGER,
    reason      TEXT NOT NULL  -- 'register' | 'rotation'
  );
  CREATE INDEX IF NOT EXISTS idx_pkh_address ON public_key_history(address);
  CREATE INDEX IF NOT EXISTS idx_pkh_agent   ON public_key_history(agent_id);

  -- DNS-TXT proof that an account's handle is associated with a real-world
  -- domain. Anchors trust outside the envoys.me registry — verifiers can
  -- treat agents under a verified-domain handle as having a stronger identity
  -- claim than first-come-first-served handles. One verification per account;
  -- handle is captured at verify-init time and the row is reset when the
  -- account changes its handle.
  CREATE TABLE IF NOT EXISTS handle_verifications (
    account_id    TEXT PRIMARY KEY REFERENCES accounts(id),
    handle        TEXT NOT NULL,
    domain        TEXT NOT NULL,
    verify_token  TEXT NOT NULL,
    verified      INTEGER NOT NULL DEFAULT 0,
    verified_at   INTEGER,
    initiated_at  INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_hv_handle ON handle_verifications(handle);

  -- Account-scoped audit log. Surfaces security-relevant events (sign-ins, key
  -- rotations, agent register/revoke/rotation-request) on the user's dashboard
  -- so they can spot unauthorised activity. Distinct from usage_events, which
  -- is keyed by address and tracks resolver traffic.
  CREATE TABLE IF NOT EXISTS audit_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    detail     TEXT,
    ip         TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_audit_account_ts ON audit_events(account_id, ts DESC);
`)

// Safe migrations — ALTER TABLE is idempotent; "already exists" errors are expected and ignored.
// Any other error is logged so unexpected failures aren't silently swallowed.
function migrate(sql: string) {
  try { db.exec(sql) } catch (e: any) {
    if (!e?.message?.includes('already exists') && !e?.message?.includes('no such column')) {
      console.error('[db] Migration warning:', e?.message, '|', sql)
    }
  }
}

migrate("ALTER TABLE accounts ADD COLUMN tier TEXT NOT NULL DEFAULT 'free'")
migrate("ALTER TABLE accounts RENAME COLUMN slug TO handle")
migrate("ALTER TABLE agents DROP COLUMN private_key")
migrate("ALTER TABLE agents ADD COLUMN rotation_requested INTEGER NOT NULL DEFAULT 0")
migrate("ALTER TABLE custom_domains ADD COLUMN resend_domain_id TEXT")
migrate("ALTER TABLE custom_domains ADD COLUMN verified_at INTEGER")
// Backfill verified_at for rows that were verified before the column existed.
// created_at is the only timestamp available pre-migration, so we use it as a
// best-effort lower bound for "verified at or after this point".
migrate("UPDATE custom_domains SET verified_at = created_at WHERE verified = 1 AND verified_at IS NULL")
// Drop tables removed in pivot to identity-registry model
migrate("DROP TABLE IF EXISTS webhooks")
migrate("DROP TABLE IF EXISTS messages")
migrate("DROP TABLE IF EXISTS threads")
// pending_keys held server-generated private keys during rotation — replaced by client-side key generation
migrate("DROP TABLE IF EXISTS pending_keys")

// Backfill public_key_history for any pre-existing agents — one 'register' row per
// agent using their current public_key and created_at. Idempotent: only inserts
// rows for agents that have no history entry yet. For agents that are already
// revoked we don't know the exact revocation timestamp, so we stamp valid_until
// with backfill time — the timeline is monotonic, not historically accurate.
db.prepare(`
  INSERT INTO public_key_history (agent_id, address, public_key, valid_from, valid_until, reason)
  SELECT a.id, a.address, a.public_key, a.created_at,
         CASE WHEN a.revoked = 1 THEN ? ELSE NULL END,
         'register'
  FROM agents a
  WHERE NOT EXISTS (SELECT 1 FROM public_key_history h WHERE h.agent_id = a.id)
`).run(Date.now())

export type Account = {
  id: string
  email: string | null
  account_key: string
  handle: string
  tier: string
  created_at: number
}

export type Agent = {
  id: string
  account_id: string
  name: string
  address: string
  agent_key: string
  public_key: string
  capabilities: string
  revoked: number
  rotation_requested: number
  created_at: number
}

export type CustomDomain = {
  id: string
  account_id: string
  domain: string
  verify_token: string
  verified: number
  resend_domain_id: string | null
  created_at: number
}

