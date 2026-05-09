import type { FastifyRequest, FastifyReply, HookHandlerDoneFunction } from 'fastify'
import { db } from '../db.js'
import type { Account, Agent } from '../db.js'
import { hashToken } from '../crypto.js'

declare module 'fastify' {
  interface FastifyRequest {
    account?: Account
    agent?: Agent
  }
}

function extractBearer(req: FastifyRequest): string | null {
  const auth = req.headers.authorization
  if (!auth?.startsWith('Bearer ')) return null
  return auth.slice(7)
}

export function requireAccountKey(
  req: FastifyRequest,
  reply: FastifyReply,
  done: HookHandlerDoneFunction
) {
  const key = extractBearer(req)
  if (!key) return reply.code(401).send({ error: 'Missing authorization' })

  const account = db
    .prepare('SELECT * FROM accounts WHERE account_key = ?')
    .get(hashToken(key)) as Account | undefined

  if (!account) return reply.code(401).send({ error: 'Invalid account key' })

  req.account = account
  done()
}

export function requireAgentKey(
  req: FastifyRequest,
  reply: FastifyReply,
  done: HookHandlerDoneFunction
) {
  const key = extractBearer(req)
  if (!key) return reply.code(401).send({ error: 'Missing authorization' })

  const agent = db
    .prepare('SELECT * FROM agents WHERE agent_key = ? AND revoked = 0')
    .get(hashToken(key)) as Agent | undefined

  if (!agent) return reply.code(401).send({ error: 'Invalid or revoked agent key' })

  req.agent = agent
  done()
}
