import Fastify, { type FastifyRequest } from 'fastify'
import fastifyStatic from '@fastify/static'
import rateLimit from '@fastify/rate-limit'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { accountRoutes } from './routes/accounts.js'
import { agentRoutes } from './routes/agents.js'
import { domainRoutes } from './routes/domains.js'
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

// Service-level W3C DID Document for did:web:envoys.me. Identifies the
// Envoys agent-registry service (not the org behind it) with one Ed25519
// verification method and the public service endpoints the service exposes.
// Resolvers (@envoys/sdk's resolveDidWeb / W3C DID resolvers / etc.) fetch
// this at /.well-known/did.json.
//
// The public-key JWK x value comes from ENVOYS_SERVICE_DID_PUBLIC_JWK_X.
// The matching private key never lives on the server — it's held on the
// maintainer's machine for occasional org/service-level signing only.
// If the env var is unset, the route returns 503 (same fail-soft pattern
// as the home-page demo agent).
const ENVOYS_SERVICE_DID_PUBLIC_JWK_X = process.env.ENVOYS_SERVICE_DID_PUBLIC_JWK_X
const SERVICE_DID_DOC = ENVOYS_SERVICE_DID_PUBLIC_JWK_X
  ? {
      '@context':         ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id:                 'did:web:envoys.me',
      verificationMethod: [{
        id:           'did:web:envoys.me#service-key-1',
        type:         'JsonWebKey2020',
        controller:   'did:web:envoys.me',
        publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: ENVOYS_SERVICE_DID_PUBLIC_JWK_X },
      }],
      service: [
        { id: 'did:web:envoys.me#registry',    type: 'EnvoysAgentRegistry', serviceEndpoint: 'https://envoys.me/agents/' },
        { id: 'did:web:envoys.me#spec',        type: 'EnvoysSpec',          serviceEndpoint: 'https://envoys.me/specs/signature/v1' },
        { id: 'did:web:envoys.me#agent-skill', type: 'EnvoysAgentSkill',    serviceEndpoint: 'https://envoys.me/.well-known/agent-skill' },
      ],
    }
  : null

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

  app.register(skillRoutes)
  app.register(accountRoutes)
  app.register(agentRoutes)
  app.register(domainRoutes)
  app.register(adminRoutes)
  app.register(waitlistRoutes)
  app.register(demoRoutes)

  app.get('/', async (_req, reply) => reply.sendFile('home.html'))
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

  // W3C DID Document for did:web:envoys.me. See SERVICE_DID_DOC above.
  app.get('/.well-known/did.json', async (req, reply) => {
    const ip = req.ip ?? null
    const ua = req.headers['user-agent'] ?? null
    if (!SERVICE_DID_DOC) {
      recordUsage({ kind: 'fetch_did_doc', address: null, status: 503, ip, userAgent: ua })
      return reply.code(503).send({ error: 'Service DID Document not configured' })
    }
    recordUsage({ kind: 'fetch_did_doc', address: null, status: 200, ip, userAgent: ua })
    reply.type('application/did+json')
    reply.header('cache-control', 'public, max-age=300')
    return SERVICE_DID_DOC
  })

  app.get('/health', async () => ({ status: 'ok', ts: Date.now() }))

  return app
}
