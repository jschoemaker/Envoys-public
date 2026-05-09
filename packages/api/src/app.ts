import Fastify, { type FastifyRequest } from 'fastify'
import fastifyStatic from '@fastify/static'
import rateLimit from '@fastify/rate-limit'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { accountRoutes } from './routes/accounts.js'
import { agentRoutes } from './routes/agents.js'
import { domainRoutes } from './routes/domains.js'
import { authRoutes } from './routes/auth.js'
import { skillRoutes } from './routes/skill.js'
import { adminRoutes } from './routes/admin.js'
import { waitlistRoutes } from './routes/waitlist.js'
import { demoRoutes } from './routes/demo.js'
import { db } from './db.js'
import { getLimits } from './limits.js'
import { hashToken } from './crypto.js'
import { recordUsage } from './usage.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Spec source lives at the repo root (one level up from packages/api/),
// not bundled with marketing HTML. Read once at startup — small file,
// rarely changes, no point re-reading per request.
const SIGNATURE_SPEC_V1 = readFileSync(
  join(__dirname, '../../../specs/signature/v1.md'),
  'utf-8',
)

export function buildApp(opts: { logger?: boolean | object; rateLimit?: boolean } = {}) {
  const app = Fastify({ logger: (opts.logger ?? true) as any, trustProxy: true })

  // Rate limiting can be disabled for tests — request counts in a test file
  // can easily exceed per-minute limits and produce noisy failures unrelated
  // to the behaviour under test. Production code paths always pass through.
  const rateLimitEnabled = opts.rateLimit !== false

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (rateLimitEnabled) app.register(rateLimit as any, {
    global: true,
    timeWindow: '1 minute',
    keyGenerator: (req: FastifyRequest) => {
      const auth = req.headers.authorization
      if (auth?.startsWith('Bearer ')) return `token:${hashToken(auth.slice(7))}`
      return `ip:${req.ip}`
    },
    max: async (req: FastifyRequest) => {
      const auth = req.headers.authorization
      if (auth?.startsWith('Bearer ')) {
        const token = auth.slice(7)
        const hashed = hashToken(token)
        const account = db.prepare('SELECT tier FROM accounts WHERE account_key = ?').get(hashed) as any
        if (account) {
          const limit = getLimits(account.tier).ratePerMinute
          return limit === Infinity ? 1_000_000 : limit
        }
        const agent = db.prepare(`
          SELECT a.tier FROM accounts a
          JOIN agents ag ON ag.account_id = a.id
          WHERE ag.agent_key = ?
        `).get(hashed) as any
        if (agent) {
          const limit = getLimits(agent.tier).ratePerMinute
          return limit === Infinity ? 1_000_000 : limit
        }
      }
      return getLimits('free').ratePerMinute
    },
    errorResponseBuilder: (_req: FastifyRequest, context: any) => ({
      error: 'Rate limit exceeded',
      limit: context.max,
      remaining: 0,
      reset_at: new Date(Date.now() + context.ttl).toISOString(),
    }),
    skip: (req: FastifyRequest) =>
      req.url === '/health' ||
      req.url === '/' ||
      req.url === '/app' ||
      req.url === '/privacy' ||
      req.url === '/terms' ||
      req.url === '/sitemap.xml' ||
      req.url === '/favicon.svg' ||
      req.url.startsWith('/.well-known/'),
  })

  app.register(fastifyStatic, {
    root: join(__dirname, '../public'),
    prefix: '/',
  })

  app.register(authRoutes)
  app.register(skillRoutes)
  app.register(accountRoutes)
  app.register(agentRoutes)
  app.register(domainRoutes)
  app.register(adminRoutes)
  app.register(waitlistRoutes)
  app.register(demoRoutes)

  app.get('/', async (_req, reply) => reply.sendFile('home.html'))
  app.get('/app', async (_req, reply) => reply.sendFile('app.html'))
  app.get('/privacy', async (_req, reply) => reply.sendFile('legal.html'))
  app.get('/terms',   async (_req, reply) => reply.sendFile('legal.html'))

  app.get('/sitemap.xml', async (_req, reply) => {
    reply.type('application/xml; charset=utf-8')
    return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://envoys.me/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://envoys.me/specs/signature/v1</loc><changefreq>monthly</changefreq><priority>0.9</priority></url>
  <url><loc>https://envoys.me/privacy</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
  <url><loc>https://envoys.me/terms</loc><changefreq>yearly</changefreq><priority>0.3</priority></url>
</urlset>
`
  })

  // Stable, versioned extension specs served as markdown.
  // The URI is the contract — never rename or move it.
  const respondWithSpecV1 = async (req: FastifyRequest, reply: any) => {
    recordUsage({ kind: 'fetch_spec', address: null, status: 200, ip: req.ip ?? null, userAgent: req.headers['user-agent'] ?? null })
    reply.type('text/markdown; charset=utf-8')
    return SIGNATURE_SPEC_V1
  }
  app.get('/specs/signature/v1',    respondWithSpecV1)
  app.get('/specs/signature/v1.md', respondWithSpecV1)

  app.get('/health', async () => ({ status: 'ok', ts: Date.now() }))

  return app
}
