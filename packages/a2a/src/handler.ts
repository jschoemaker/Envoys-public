import { Envoys } from '@envoys/sdk'
import { randomUUID } from 'crypto'
import { ENVOYS_SIGNATURE_EXT_URI } from './spec.js'
import { InMemoryTaskStore } from './task-store.js'
import type { TaskStore } from './task-store.js'
import type {
  A2AArtifact,
  A2AContext,
  A2AMessage,
  A2AMessageHandler,
  A2APart,
  A2ARequestEnvelope,
  A2AResponseEnvelope,
  A2ATaskResult,
  TextPart,
} from './types.js'

export interface HandlerInput {
  method:  string
  path:    string
  headers: Record<string, string | string[] | undefined>
  body:    unknown
}

export interface HandlerOutput {
  status: number
  body:   A2AResponseEnvelope | { error: { code: number; message: string }; jsonrpc: '2.0'; id: string | null }
}

export interface CreateHandlerOptions {
  onMessage: A2AMessageHandler
  // Pluggable task storage. Default: in-memory, bounded to 1000 entries.
  // Pass `null` to disable — tasks/get and tasks/cancel will return -32601.
  tasks?: TaskStore | null
  // Hook called when verification fails — useful for logging.
  onUnverified?: (reason: string) => void
  // Hook called when a signed request is verified but missing the
  // A2A-Extensions: <envoys signature uri> negotiation header. The
  // signature itself is the gate, so the request is still accepted —
  // this is for telemetry on non-conformant clients.
  onMissingExtensionHeader?: (sender: string) => void
}

function flattenHeaders(h: HandlerInput['headers']): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(h)) {
    if (v == null) continue
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v)
  }
  return out
}

function jsonRpcError(id: string | null, code: number, message: string, status: number): HandlerOutput {
  return { status, body: { jsonrpc: '2.0', id, error: { code, message } } }
}

function isRequestEnvelope(b: unknown): b is A2ARequestEnvelope {
  return !!b && typeof b === 'object'
    && (b as any).jsonrpc === '2.0'
    && typeof (b as any).method === 'string'
    && typeof (b as any).id === 'string'
}

// Translate the user-facing return value into A2A artifact + status.
// Precedence: artifacts > parts > {text|file|data} shortcuts > string.
function resolveReturn(r: unknown): {
  artifacts: A2AArtifact[]
  state:     'submitted' | 'completed' | 'failed' | 'canceled'
} {
  if (typeof r === 'string') {
    return { artifacts: [{ parts: [{ kind: 'text', text: r }] }], state: 'completed' }
  }
  if (r && typeof r === 'object') {
    const o = r as any
    const state: 'submitted' | 'completed' | 'failed' | 'canceled' = o.status ?? 'completed'
    if (o.artifacts) return { artifacts: o.artifacts, state }
    if (o.parts)     return { artifacts: [{ parts: o.parts }], state }

    const parts: A2APart[] = []
    if (o.text != null)      parts.push({ kind: 'text', text: o.text })
    if (o.file != null)      parts.push({ kind: 'file', file: o.file })
    if (o.data !== undefined) parts.push({ kind: 'data', data: o.data })
    return { artifacts: parts.length ? [{ parts }] : [], state }
  }
  return { artifacts: [], state: 'completed' }
}

// Framework-agnostic A2A request handler. Verifies the RFC 9421 signature
// using the keyid embedded in Signature-Input, then dispatches verified
// JSON-RPC methods (message/send, tasks/get, tasks/cancel) to the right
// internal handler. Returns { status, body } that any HTTP server can write.
export function createA2AHandler(opts: CreateHandlerOptions) {
  const { onMessage, onUnverified, onMissingExtensionHeader } = opts
  // tasks: undefined → default in-memory; null → disable; otherwise use given.
  const tasks: TaskStore | null = opts.tasks === undefined ? new InMemoryTaskStore() : opts.tasks

  return async function handle(input: HandlerInput): Promise<HandlerOutput> {
    const headers = flattenHeaders(input.headers)
    const body    = input.body
    const id      = (body as any)?.id ?? null

    const verification = await Envoys.verifyRequest(input.method, input.path, headers, body as object | undefined)
    if (!verification.verified) {
      onUnverified?.(verification.error ?? 'unknown')
      return jsonRpcError(id, -32001, `Unauthorized: ${verification.error ?? 'signature verification failed'}`, 401)
    }

    // Spec §4.1 — clients should declare the extension via A2A-Extensions.
    // We don't reject when missing (signature is the actual gate) but expose
    // the gap so operators can spot non-conformant clients.
    const extHeader = headers['a2a-extensions'] ?? ''
    if (!extHeader.split(',').map(s => s.trim()).includes(ENVOYS_SIGNATURE_EXT_URI)) {
      onMissingExtensionHeader?.(verification.address!)
    }

    if (!isRequestEnvelope(body)) {
      return jsonRpcError(id, -32600, 'Invalid JSON-RPC 2.0 request', 400)
    }

    switch (body.method) {
      case 'message/send':
        return handleMessageSend(body, verification.address!, onMessage, tasks)
      case 'tasks/get':
        return handleTasksGet(body, tasks)
      case 'tasks/cancel':
        return handleTasksCancel(body, tasks)
      default:
        return jsonRpcError(id, -32601, `Method not found: ${body.method}`, 400)
    }
  }
}

async function handleMessageSend(
  envelope: A2ARequestEnvelope,
  sender:   string,
  onMessage: A2AMessageHandler,
  tasks:    TaskStore | null,
): Promise<HandlerOutput> {
  const message: A2AMessage | undefined = envelope.params?.message
  if (!message || !Array.isArray(message.parts)) {
    return jsonRpcError(envelope.id, -32602, 'Invalid params: message.parts required', 400)
  }

  const text = message.parts.find((p): p is TextPart => p.kind === 'text')?.text ?? ''

  const ctx: A2AContext = {
    sender,
    text,
    parts:    message.parts,
    message,
    envelope,
  }

  let handlerResult
  try {
    handlerResult = await onMessage(ctx)
  } catch (err: any) {
    return jsonRpcError(envelope.id, -32000, err?.message ?? 'Handler error', 500)
  }

  const { artifacts, state } = resolveReturn(handlerResult)
  const task: A2ATaskResult = {
    id:     randomUUID(),
    status: { state },
    artifacts,
  }

  if (tasks) await tasks.set(task.id, task)

  return { status: 200, body: { jsonrpc: '2.0', id: envelope.id, result: task } }
}

async function handleTasksGet(envelope: A2ARequestEnvelope, tasks: TaskStore | null): Promise<HandlerOutput> {
  if (!tasks) return jsonRpcError(envelope.id, -32601, 'Method not found: tasks/get (task store disabled)', 400)

  const params = envelope.params as any
  const taskId = params?.id
  if (typeof taskId !== 'string') {
    return jsonRpcError(envelope.id, -32602, 'Invalid params: id required', 400)
  }

  const task = await tasks.get(taskId)
  if (!task) return jsonRpcError(envelope.id, -32602, `Task not found: ${taskId}`, 404)

  return { status: 200, body: { jsonrpc: '2.0', id: envelope.id, result: task } }
}

async function handleTasksCancel(envelope: A2ARequestEnvelope, tasks: TaskStore | null): Promise<HandlerOutput> {
  if (!tasks) return jsonRpcError(envelope.id, -32601, 'Method not found: tasks/cancel (task store disabled)', 400)

  const params = envelope.params as any
  const taskId = params?.id
  if (typeof taskId !== 'string') {
    return jsonRpcError(envelope.id, -32602, 'Invalid params: id required', 400)
  }

  const task = await tasks.cancel(taskId)
  if (!task) return jsonRpcError(envelope.id, -32602, `Task not found: ${taskId}`, 404)

  return { status: 200, body: { jsonrpc: '2.0', id: envelope.id, result: task } }
}
