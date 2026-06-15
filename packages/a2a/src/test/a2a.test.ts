import { describe, it, expect, vi, beforeEach } from 'vitest'
import { generateKeyPairSync, randomUUID } from 'crypto'
import { Envoys } from '@envoys/sdk'

// The SDK's keyid-resolution SSRF guard does a real DNS lookup on the keyid
// host. Stub it so these fetch-stubbed handler tests stay hermetic (no network).
vi.mock('dns/promises', () => ({
  lookup: vi.fn(async () => [{ address: '93.184.216.34', family: 4 }]),
}))
import { createA2AClient } from '../client.js'
import { createA2AHandler } from '../handler.js'
import { buildAgentCard } from '../card.js'
import { A2AError } from '../errors.js'
import { InMemoryTaskStore } from '../task-store.js'
import type { TaskStore } from '../task-store.js'
import type { A2ATaskResult } from '../types.js'
import { ENVOYS_SIGNATURE_EXT_URI, ENVOYS_SECURITY_SCHEME } from '../spec.js'

function makeEd25519() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

function makeAgent(address = 'sender@team.envoys.me') {
  const { publicKey, privateKey } = makeEd25519()
  return {
    publicKey,
    privateKey,
    envoys: new Envoys({ agentKey: 'agt_test', address, publicKey, privateKey }),
  }
}

// Pipe a client.send() through the handler in the same process.
// Stubs fetch to: (1) feed the signed request into the handler, (2) return the handler's response.
function pipeClientToHandler(
  endpoint: string,
  publicKeyPem: string,
  handler: ReturnType<typeof createA2AHandler>,
) {
  return vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
    // Key resolution — both the legacy query-string endpoint and the keyid URL
    // (GET /agents/<address>) that verifyRequest's resolveKeyFromKeyid fetches.
    if (url.includes('/agents/public-key')) {
      return { ok: true, json: async () => ({ public_key: publicKeyPem }) }
    }
    if (url.includes('/agents/') && (init?.method ?? 'GET') === 'GET') {
      return {
        ok: true,
        headers: { get: () => 'application/json' },
        json: async () => ({ public_key: publicKeyPem }),
      }
    }
    const u = new URL(url)
    const out = await handler({
      method:  init.method ?? 'POST',
      path:    u.pathname || '/',
      // A real server sees the Host header from the connection — synthesize it
      // from the URL so @authority-bound signatures reconstruct correctly.
      headers: { host: u.host, ...(init.headers as Record<string, string>) },
      body:    JSON.parse(init.body as string),
    })
    return {
      ok:     out.status >= 200 && out.status < 300,
      status: out.status,
      json:   async () => out.body,
    }
  })
}

beforeEach(() => {
  vi.unstubAllGlobals()
  Envoys.clearKeyCache()
  Envoys.clearReplayCache()
  Envoys.clearPins()
})

// ── Round-trip: signed client → verifying handler ────────────────────────────

describe('createA2AClient + createA2AHandler', () => {
  it('round-trips: client sends signed message, handler verifies and replies', async () => {
    const sender   = makeAgent('alice@team.envoys.me')
    const handler  = createA2AHandler({
      onMessage: ({ sender: from, text }) => `Echo (verified ${from}): ${text}`,
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const reply  = await client.send('hello world')

    expect(reply.text).toBe('Echo (verified alice@team.envoys.me): hello world')
    expect(reply.status).toBe('completed')
  })

  it('round-trips with bindAuthority — signature covers @authority and the handler verifies via Host', async () => {
    const sender  = makeAgent('alice@team.envoys.me')
    const handler = createA2AHandler({ onMessage: ({ text }) => `bound: ${text}` })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/', bindAuthority: true })
    const reply  = await client.send('hello')
    expect(reply.text).toBe('bound: hello')

    // The signed request actually covered @authority.
    const calls = (globalThis.fetch as any).mock.calls
    const sendCall = calls.find(([u]: [string]) => u === 'http://recv/')
    expect(sendCall[1].headers['Signature-Input']).toContain('"@authority"')
  })

  it('handler exposes the verified sender address to onMessage', async () => {
    const sender = makeAgent('bob@team.envoys.me')
    const seen: string[] = []
    const handler = createA2AHandler({
      onMessage: ({ sender: from }) => { seen.push(from); return 'ok' },
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send('hi')
    expect(seen).toEqual(['bob@team.envoys.me'])
  })

  it('client.send accepts SendOptions with text', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({ onMessage: ({ text }) => `got: ${text}` })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const reply  = await client.send({ text: 'opts form' })
    expect(reply.text).toBe('got: opts form')
  })

  it('client.send accepts SendOptions with custom parts', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({
      onMessage: ({ parts }) => parts.find(p => p.kind === 'text')?.text ?? '',
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const reply  = await client.send({ parts: [{ kind: 'text', text: 'parts form' }] })
    expect(reply.text).toBe('parts form')
  })

  it('handler handles object return with explicit artifacts', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({
      onMessage: () => ({
        artifacts: [{ parts: [{ kind: 'text', text: 'custom artifact' }] }],
        status: 'completed' as const,
      }),
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const reply  = await client.send('x')
    expect(reply.text).toBe('custom artifact')
  })
})

// ── Extension header negotiation (spec §4.1) ─────────────────────────────────

describe('A2A-Extensions header', () => {
  it('client includes the Envoys signature extension URI on outgoing requests', async () => {
    const sender = makeAgent()
    let capturedHeaders: Record<string, string> | null = null

    vi.stubGlobal('fetch', vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedHeaders = init.headers as Record<string, string>
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: '1', result: { id: 'x', status: { state: 'completed' }, artifacts: [] } }) }
    }))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send('hi')

    expect(capturedHeaders!['A2A-Extensions']).toBe(ENVOYS_SIGNATURE_EXT_URI)
  })

  it('handler fires onMissingExtensionHeader hook when client did not negotiate', async () => {
    const sender = makeAgent()
    const sigHeaders = sender.envoys.signRequest('POST', '/', {
      jsonrpc: '2.0', id: '1', method: 'message/send',
      params: { message: { role: 'user', messageId: '1', parts: [{ kind: 'text', text: 'x' }] } },
    })

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ public_key: sender.publicKey }) }))

    const seen: string[] = []
    const handler = createA2AHandler({
      onMessage: () => 'ok',
      onMissingExtensionHeader: who => seen.push(who),
    })

    // Note: NO A2A-Extensions header set here — should still process the request,
    // but the hook should fire.
    await handler({
      method:  'POST',
      path:    '/',
      headers: sigHeaders,
      body:    { jsonrpc: '2.0', id: '1', method: 'message/send', params: { message: { role: 'user', messageId: '1', parts: [{ kind: 'text', text: 'x' }] } } },
    })

    expect(seen).toEqual(['sender@team.envoys.me'])
  })

  it('handler does not fire onMissingExtensionHeader when client did negotiate', async () => {
    const sender = makeAgent()
    const seen: string[] = []
    const handler = createA2AHandler({
      onMessage:                () => 'ok',
      onMissingExtensionHeader: who => seen.push(who),
    })

    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send('hi')

    expect(seen).toEqual([])
  })
})

// ── Task lifecycle: tasks/get, tasks/cancel ──────────────────────────────────

describe('task lifecycle', () => {
  // Helper: sign an arbitrary JSON-RPC method and call it on the handler.
  // Stubs fetch so verifyRequest's keyid resolution returns sender's public key.
  async function callMethod(
    sender:    ReturnType<typeof makeAgent>,
    handler:   ReturnType<typeof createA2AHandler>,
    method:    string,
    params:    any,
  ) {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok:   true,
      json: async () => ({ public_key: sender.publicKey }),
    }))
    const body       = { jsonrpc: '2.0', id: randomUUID(), method, params }
    const sigHeaders = sender.envoys.signRequest('POST', '/', body)
    return handler({
      method:  'POST',
      path:    '/',
      headers: { ...sigHeaders, 'A2A-Extensions': ENVOYS_SIGNATURE_EXT_URI },
      body,
    })
  }

  it('message/send stores the task; tasks/get returns it', async () => {
    const sender   = makeAgent()
    const handler  = createA2AHandler({ onMessage: () => 'reply text' })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const send   = await client.send('hi')
    const taskId = send.taskId

    const got = await callMethod(sender, handler, 'tasks/get', { id: taskId })
    expect(got.status).toBe(200)
    const task = (got.body as any).result as A2ATaskResult
    expect(task.id).toBe(taskId)
    expect(task.status.state).toBe('completed')
    expect((task.artifacts[0].parts[0] as any).text).toBe('reply text')
  })

  it('tasks/get returns -32602 for unknown id', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({ onMessage: () => 'ok' })

    const out = await callMethod(sender, handler, 'tasks/get', { id: 'does-not-exist' })
    expect(out.status).toBe(404)
    expect((out.body as any).error.code).toBe(-32602)
    expect((out.body as any).error.message).toMatch(/not found/i)
  })

  it('tasks/get returns -32602 when params.id missing', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({ onMessage: () => 'ok' })

    const out = await callMethod(sender, handler, 'tasks/get', {})
    expect(out.status).toBe(400)
    expect((out.body as any).error.code).toBe(-32602)
  })

  it('tasks/cancel on a completed task returns it unchanged', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({ onMessage: () => 'fast reply' })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const send   = await client.send('hi')

    const out = await callMethod(sender, handler, 'tasks/cancel', { id: send.taskId })
    expect(out.status).toBe(200)
    const task = (out.body as any).result as A2ATaskResult
    expect(task.id).toBe(send.taskId)
    expect(task.status.state).toBe('completed')  // already terminal — unchanged
  })

  it('tasks/cancel on submitted task transitions to canceled', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({
      onMessage: () => ({ status: 'submitted' as const, text: 'queued' }),
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const send   = await client.send('start work')
    expect(send.status).toBe('submitted')

    const out = await callMethod(sender, handler, 'tasks/cancel', { id: send.taskId })
    expect(out.status).toBe(200)
    const task = (out.body as any).result as A2ATaskResult
    expect(task.status.state).toBe('canceled')

    // Subsequent tasks/get reflects the canceled state
    const got = await callMethod(sender, handler, 'tasks/get', { id: send.taskId })
    expect(((got.body as any).result as A2ATaskResult).status.state).toBe('canceled')
  })

  it('tasks/cancel returns -32602 for unknown id', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({ onMessage: () => 'ok' })

    const out = await callMethod(sender, handler, 'tasks/cancel', { id: 'nope' })
    expect(out.status).toBe(404)
    expect((out.body as any).error.code).toBe(-32602)
  })

  it('caller-supplied TaskStore is used for storage and lookup', async () => {
    const sender = makeAgent()
    const calls: string[] = []
    const customStore: TaskStore = {
      async get(id) { calls.push(`get:${id}`); return null },
      async set(id) { calls.push(`set:${id}`) },
      async cancel(id) { calls.push(`cancel:${id}`); return null },
    }

    const handler = createA2AHandler({ onMessage: () => 'reply', tasks: customStore })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const send   = await client.send('hi')

    expect(calls).toContainEqual(`set:${send.taskId}`)
  })

  it('tasks: null disables tasks/get and tasks/cancel (-32601)', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({ onMessage: () => 'ok', tasks: null })

    const get = await callMethod(sender, handler, 'tasks/get', { id: 'x' })
    expect((get.body as any).error.code).toBe(-32601)

    const cancel = await callMethod(sender, handler, 'tasks/cancel', { id: 'x' })
    expect((cancel.body as any).error.code).toBe(-32601)
  })
})

// ── InMemoryTaskStore unit tests ─────────────────────────────────────────────

describe('InMemoryTaskStore', () => {
  function task(id: string, state: A2ATaskResult['status']['state'] = 'completed'): A2ATaskResult {
    return { id, status: { state }, artifacts: [] }
  }

  it('get returns null for unknown ids', async () => {
    const store = new InMemoryTaskStore()
    expect(await store.get('x')).toBeNull()
  })

  it('round-trips set → get', async () => {
    const store = new InMemoryTaskStore()
    await store.set('a', task('a'))
    expect((await store.get('a'))!.id).toBe('a')
  })

  it('cancel on terminal task returns task unchanged', async () => {
    const store = new InMemoryTaskStore()
    await store.set('a', task('a', 'completed'))
    const out = await store.cancel('a')
    expect(out!.status.state).toBe('completed')
  })

  it('cancel on submitted task transitions to canceled', async () => {
    const store = new InMemoryTaskStore()
    await store.set('a', task('a', 'submitted'))
    const out = await store.cancel('a')
    expect(out!.status.state).toBe('canceled')
    expect((await store.get('a'))!.status.state).toBe('canceled')
  })

  it('cancel returns null for unknown id', async () => {
    const store = new InMemoryTaskStore()
    expect(await store.cancel('nope')).toBeNull()
  })

  it('evicts oldest entry past maxSize', async () => {
    const store = new InMemoryTaskStore({ maxSize: 3 })
    await store.set('a', task('a'))
    await store.set('b', task('b'))
    await store.set('c', task('c'))
    await store.set('d', task('d'))  // should evict 'a'

    expect(await store.get('a')).toBeNull()
    expect((await store.get('d'))!.id).toBe('d')
    expect(store.size()).toBe(3)
  })
})

// ── File and data parts ──────────────────────────────────────────────────────

describe('file and data parts', () => {
  it('client sends a file part end-to-end', async () => {
    const sender  = makeAgent()
    let received: any = null
    const handler = createA2AHandler({
      onMessage: ({ parts }) => {
        received = parts
        return 'received file'
      },
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send({
      file: { name: 'photo.jpg', mimeType: 'image/jpeg', bytes: 'aGVsbG8=' },
    })

    expect(received).toHaveLength(1)
    expect(received[0].kind).toBe('file')
    expect(received[0].file.name).toBe('photo.jpg')
    expect(received[0].file.bytes).toBe('aGVsbG8=')
  })

  it('client sends a data part end-to-end', async () => {
    const sender  = makeAgent()
    let received: any = null
    const handler = createA2AHandler({
      onMessage: ({ parts }) => {
        received = parts
        return 'ok'
      },
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send({ data: { tool: 'search', args: { q: 'envoys' } } })

    expect(received).toHaveLength(1)
    expect(received[0].kind).toBe('data')
    expect(received[0].data).toEqual({ tool: 'search', args: { q: 'envoys' } })
  })

  it('client sends mixed text+file in a single message via parts', async () => {
    const sender  = makeAgent()
    let received: any = null
    const handler = createA2AHandler({
      onMessage: ({ parts }) => { received = parts; return 'ok' },
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send({
      parts: [
        { kind: 'text', text: 'analyze this' },
        { kind: 'file', file: { name: 'doc.pdf', mimeType: 'application/pdf', bytes: 'cGRm' } },
      ],
    })

    expect(received).toHaveLength(2)
    expect(received[0].kind).toBe('text')
    expect(received[1].kind).toBe('file')
  })

  it('client returns parts and text from response', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({
      onMessage: () => ({
        parts: [
          { kind: 'text', text: 'caption' },
          { kind: 'file', file: { name: 'out.png', mimeType: 'image/png', bytes: 'cG5n' } },
        ],
      }),
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const reply  = await client.send('go')

    expect(reply.text).toBe('caption')
    expect(reply.parts).toHaveLength(2)
    expect(reply.parts[1].kind).toBe('file')
  })

  it('handler return shorthand: { file } produces a file artifact', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({
      onMessage: () => ({
        file: { name: 'r.bin', bytes: 'YmluYXJ5' },
      }),
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const reply  = await client.send('x')

    expect(reply.artifacts[0].parts[0].kind).toBe('file')
    expect((reply.artifacts[0].parts[0] as any).file.bytes).toBe('YmluYXJ5')
  })

  it('handler return shorthand: { data } produces a data artifact', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({
      onMessage: () => ({ data: [1, 2, 3] }),
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    const reply  = await client.send('x')

    expect(reply.artifacts[0].parts[0].kind).toBe('data')
    expect((reply.artifacts[0].parts[0] as any).data).toEqual([1, 2, 3])
  })

  it('ctx.text shortcut still resolves to the first text part when mixed', async () => {
    const sender  = makeAgent()
    let seenText = ''
    const handler = createA2AHandler({
      onMessage: ({ text }) => { seenText = text; return 'ok' },
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send({
      parts: [
        { kind: 'data', data: {} },
        { kind: 'text', text: 'find me' },
      ],
    })
    expect(seenText).toBe('find me')
  })

  it('ctx.text is empty string when no text part is present', async () => {
    const sender  = makeAgent()
    let seenText = 'unset'
    const handler = createA2AHandler({
      onMessage: ({ text }) => { seenText = text; return 'ok' },
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await client.send({ data: { only: 'data' } })
    expect(seenText).toBe('')
  })
})

// ── Verification rejections ──────────────────────────────────────────────────

describe('handler rejects unverified or malformed requests', () => {
  it('rejects requests with no signature headers', async () => {
    const handler = createA2AHandler({ onMessage: () => 'should not run' })
    const out = await handler({
      method:  'POST',
      path:    '/',
      headers: { 'content-type': 'application/json' },
      body:    { jsonrpc: '2.0', id: '1', method: 'message/send', params: { message: { role: 'user', messageId: '1', parts: [{ kind: 'text', text: 'x' }] } } },
    })
    expect(out.status).toBe(401)
    expect((out.body as any).error.code).toBe(-32001)
  })

  it('rejects when verification public key does not match signer', async () => {
    const sender = makeAgent()
    const { publicKey: wrong } = makeEd25519()
    const handler = createA2AHandler({ onMessage: () => 'no' })

    vi.stubGlobal('fetch', vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
      if (url.includes('/agents/public-key')) {
        return { ok: true, json: async () => ({ public_key: wrong }) }
      }
      const path = new URL(url).pathname || '/'
      const out = await handler({ method: init.method ?? 'POST', path, headers: init.headers as Record<string, string>, body: JSON.parse(init.body as string) })
      return { ok: out.status < 400, status: out.status, json: async () => out.body }
    }))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await expect(client.send('hello')).rejects.toThrow(A2AError)
  })

  it('rejects unknown JSON-RPC methods', async () => {
    const sender = makeAgent()
    const body = { jsonrpc: '2.0', id: '1', method: 'message/stream' }  // not implemented
    const sigHeaders = sender.envoys.signRequest('POST', '/', body)

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ public_key: sender.publicKey }) }))

    const handler = createA2AHandler({ onMessage: () => 'no' })
    const out = await handler({
      method:  'POST',
      path:    '/',
      headers: sigHeaders,
      body,
    })
    expect(out.status).toBe(400)
    expect((out.body as any).error.code).toBe(-32601)
  })

  it('rejects malformed JSON-RPC envelopes', async () => {
    const sender = makeAgent()
    const sigHeaders = sender.envoys.signRequest('POST', '/', { not: 'jsonrpc' })

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ public_key: sender.publicKey }) }))

    const handler = createA2AHandler({ onMessage: () => 'no' })
    const out = await handler({
      method:  'POST',
      path:    '/',
      headers: sigHeaders,
      body:    { not: 'jsonrpc' },
    })
    expect(out.status).toBe(400)
    expect((out.body as any).error.code).toBe(-32600)
  })

  it('returns -32000 when handler throws', async () => {
    const sender  = makeAgent()
    const handler = createA2AHandler({
      onMessage: () => { throw new Error('boom') },
    })
    vi.stubGlobal('fetch', pipeClientToHandler('http://recv/', sender.publicKey, handler))

    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await expect(client.send('hello')).rejects.toThrow(/boom/)
  })

  it('calls onUnverified hook when verification fails', async () => {
    const reasons: string[] = []
    const handler = createA2AHandler({
      onMessage:    () => 'no',
      onUnverified: r => reasons.push(r),
    })
    await handler({ method: 'POST', path: '/', headers: {}, body: { jsonrpc: '2.0', id: '1', method: 'message/send' } })
    expect(reasons).toHaveLength(1)
    expect(reasons[0]).toMatch(/Signature/)
  })
})

// ── Client throws on bad input ───────────────────────────────────────────────

describe('createA2AClient input validation', () => {
  it('throws if no text and no parts provided', async () => {
    const sender = makeAgent()
    const client = createA2AClient({ envoys: sender.envoys, endpoint: 'http://recv/' })
    await expect(client.send({})).rejects.toThrow(/text.*parts/)
  })
})

// ── buildAgentCard ───────────────────────────────────────────────────────────

describe('buildAgentCard', () => {
  it('returns minimal card with sane defaults', () => {
    const card = buildAgentCard({ name: 'X', url: 'https://x' })
    expect(card.name).toBe('X')
    expect(card.version).toBe('1.0.0')
    expect(card.capabilities.streaming).toBe(false)
    expect(card.skills).toEqual([])
    expect(card.securitySchemes).toBeUndefined()
  })

  it('declares Envoys security scheme matching spec §3 when requested', () => {
    const card = buildAgentCard({ name: 'X', url: 'https://x', requireEnvoysSignature: true })
    expect(card.capabilities.extensions).toContain(ENVOYS_SIGNATURE_EXT_URI)
    expect(card.securitySchemes).toBeDefined()
    const scheme = (card.securitySchemes as any)[ENVOYS_SECURITY_SCHEME]
    expect(scheme.type).toBe('extension')
    expect(scheme.extensionUri).toBe(ENVOYS_SIGNATURE_EXT_URI)
    expect(card.security).toEqual([{ [ENVOYS_SECURITY_SCHEME]: [] }])
  })

  it('preserves user-supplied extensions when adding the Envoys URI', () => {
    const card = buildAgentCard({
      name: 'X',
      url: 'https://x',
      capabilities: { streaming: false, extensions: ['https://example.com/ext/v1'] } as any,
      requireEnvoysSignature: true,
    })
    expect(card.capabilities.extensions).toEqual([
      'https://example.com/ext/v1',
      ENVOYS_SIGNATURE_EXT_URI,
    ])
  })

  it('merges extra fields onto the card', () => {
    const card = buildAgentCard({ name: 'X', url: 'https://x', extra: { provider: { name: 'Acme' } } })
    expect((card as any).provider).toEqual({ name: 'Acme' })
  })
})
