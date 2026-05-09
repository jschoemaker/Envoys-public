import type { FastifyInstance } from 'fastify'
import { randomUUID, randomBytes } from 'crypto'
import { db } from '../db.js'
import type { Account } from '../db.js'
import { generateToken, hashToken } from '../crypto.js'
import { validateHandle, checkHandleConflict } from './accounts.js'
import { recordAudit } from '../usage.js'

const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     ?? ''
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET ?? ''
const BASE_URL             = process.env.BASE_URL ?? 'http://localhost:3000'
const REDIRECT_URI         = `${BASE_URL}/auth/google/callback`

// Short-lived in-memory store for OAuth state tokens (CSRF protection).
// Each entry expires after 10 minutes. Fine for single-instance; use Redis for multi-instance.
const pendingStates = new Map<string, number>()

// Pending Google setups: new users who completed OAuth but haven't picked a handle yet.
// Token → { googleId, email, suggestedHandle }. Expires after 30 minutes.
type PendingSetup = { googleId: string; email: string; suggestedHandle: string; exp: number }
const pendingSetups = new Map<string, PendingSetup>()

function cleanExpiredStates() {
  const now = Date.now()
  for (const [state, exp] of pendingStates) {
    if (exp < now) pendingStates.delete(state)
  }
  for (const [token, setup] of pendingSetups) {
    if (setup.exp < now) pendingSetups.delete(token)
  }
}

setInterval(cleanExpiredStates, 10 * 60 * 1000)

export async function authRoutes(app: FastifyInstance) {
  // Step 1 — Redirect user to Google's consent screen.
  app.get('/auth/google', async (req, reply) => {
    if (!GOOGLE_CLIENT_ID) {
      return reply.code(503).send({ error: 'Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.' })
    }

    cleanExpiredStates()
    const state = randomBytes(16).toString('hex')
    pendingStates.set(state, Date.now() + 10 * 60 * 1000) // 10 min TTL

    const params = new URLSearchParams({
      client_id:     GOOGLE_CLIENT_ID,
      redirect_uri:  REDIRECT_URI,
      response_type: 'code',
      scope:         'openid email profile',
      state,
      access_type:   'online',
      prompt:        'select_account',
    })

    return reply.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`)
  })

  // Step 2 — Google redirects back here with a code.
  // Exchange code → tokens → user info → find or create account → send back to dashboard.
  app.get('/auth/google/callback', async (req, reply) => {
    const { code, state, error } = req.query as {
      code?: string
      state?: string
      error?: string
    }

    if (error) {
      return reply.redirect(`/app?auth_error=${encodeURIComponent(error)}`)
    }

    if (!code || !state) {
      return reply.redirect('/app?auth_error=missing_params')
    }

    // Validate state — prevents CSRF
    if (!pendingStates.has(state)) {
      return reply.redirect('/app?auth_error=invalid_state')
    }
    pendingStates.delete(state)

    // Exchange authorization code for tokens
    let googleId: string
    let email: string
    let name: string

    try {
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id:     GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          redirect_uri:  REDIRECT_URI,
          grant_type:    'authorization_code',
        }),
      })

      if (!tokenRes.ok) throw new Error('Token exchange failed')
      const tokens = await tokenRes.json() as { access_token: string }

      // Fetch the user's Google profile
      const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      })

      if (!userRes.ok) throw new Error('Failed to fetch user info')
      const user = await userRes.json() as { sub: string; email: string; name: string }

      googleId = user.sub
      email    = user.email.toLowerCase()
      name     = user.name
    } catch (err) {
      return reply.redirect('/app?auth_error=google_failed')
    }

    // Find existing account by Google ID or email
    let account = (
      db.prepare('SELECT * FROM accounts WHERE google_id = ?').get(googleId) ??
      db.prepare('SELECT * FROM accounts WHERE email = ?').get(email)
    ) as Account | undefined

    if (account) {
      // Existing user — link Google ID if not already linked.
      // Generate a fresh account_key on every Google login (session rotation).
      const fresh_key = generateToken('ak')
      db.prepare('UPDATE accounts SET account_key = ?, google_id = COALESCE(google_id, ?) WHERE id = ?')
        .run(hashToken(fresh_key), googleId, account.id)
      recordAudit({ accountId: account.id, kind: 'account.signin', detail: 'google', ip: req.ip ?? null })
      return reply.redirect(`/app?ak=${fresh_key}`)
    }

    // New user — send them to the handle picker before creating the account.
    // Build a suggested handle from their Google display name.
    const suggestedHandle = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 30)

    const setupToken = randomBytes(24).toString('hex')
    pendingSetups.set(setupToken, {
      googleId,
      email,
      suggestedHandle,
      exp: Date.now() + 30 * 60 * 1000,
    })

    return reply.redirect(`/app?setup=${setupToken}&suggested=${encodeURIComponent(suggestedHandle)}`)
  })

  // Final step for new Google users — they've picked a handle, create the account.
  app.post('/auth/google/complete', async (req, reply) => {
    const { setup_token, handle } = req.body as { setup_token?: string; handle?: string }

    if (!setup_token || !handle) {
      return reply.code(400).send({ error: 'setup_token and handle required' })
    }
    if (setup_token.length > 256) return reply.code(400).send({ error: 'Invalid setup token' })

    const pending = pendingSetups.get(setup_token)
    if (!pending) return reply.code(400).send({ error: 'Setup token invalid or expired — please sign in with Google again' })
    if (pending.exp < Date.now()) {
      pendingSetups.delete(setup_token)
      return reply.code(400).send({ error: 'Setup token expired — please sign in with Google again' })
    }

    const handleErr = validateHandle(handle)
    if (handleErr) return reply.code(400).send({ error: handleErr })

    const conflict = checkHandleConflict(handle)
    if (conflict) return reply.code(409).send({ error: conflict })

    const id          = randomUUID()
    const account_key = generateToken('ak')

    db.prepare(`
      INSERT INTO accounts (id, email, account_key, handle, google_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, pending.email, hashToken(account_key), handle, pending.googleId, Date.now())

    pendingSetups.delete(setup_token)
    recordAudit({ accountId: id, kind: 'account.signin', detail: 'google (new account)', ip: req.ip ?? null })

    return reply.send({ account_key, handle, email: pending.email })
  })
}
