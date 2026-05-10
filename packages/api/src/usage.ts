import { db } from './db.js'

export type UsageKind =
  | 'resolve_public_key'
  | 'resolve_agent'
  | 'fetch_skill'
  | 'fetch_spec'

const insertStmt = db.prepare(
  'INSERT INTO usage_events (ts, kind, address, status, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
)

// Recording usage must never fail a real request. Wrap and swallow errors —
// a missed log row is preferable to a 500 on /agents/public-key.
export function recordUsage(opts: {
  kind: UsageKind
  address: string | null
  status: number
  ip: string | null
  userAgent: string | null
}): void {
  try {
    insertStmt.run(
      Date.now(),
      opts.kind,
      opts.address,
      opts.status,
      opts.ip,
      opts.userAgent,
    )
  } catch (e: any) {
    console.error('[usage] failed to record event:', e?.message)
  }
}

export type AuditKind =
  | 'account.signin'
  | 'account.key_rotated'
  | 'account.handle_changed'
  | 'account.email_changed'
  | 'agent.registered'
  | 'agent.register_failed'
  | 'agent.rotation_requested'
  | 'agent.revoked'
  | 'handle_verification.verified'

const auditStmt = db.prepare(
  'INSERT INTO audit_events (account_id, ts, kind, detail, ip) VALUES (?, ?, ?, ?, ?)',
)

// Audit events surface security-relevant actions on the user's Settings panel.
// Same fail-soft policy as recordUsage — we never block a real request to log.
export function recordAudit(opts: {
  accountId: string
  kind: AuditKind
  detail?: string | null
  ip?: string | null
}): void {
  try {
    auditStmt.run(opts.accountId, Date.now(), opts.kind, opts.detail ?? null, opts.ip ?? null)
  } catch (e: any) {
    console.error('[audit] failed to record event:', e?.message)
  }
}
