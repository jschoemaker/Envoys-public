import { Envoys } from '@envoys/sdk'
import { randomUUID } from 'crypto'
import { A2AError } from './errors.js'
import { ENVOYS_SIGNATURE_EXT_URI } from './spec.js'
import type {
  A2APart,
  A2AArtifact,
  A2ARequestEnvelope,
  A2AResponseEnvelope,
  FileContent,
} from './types.js'

export interface A2AClientOptions {
  envoys:    Envoys
  endpoint:  string  // remote A2A URL, e.g. https://other.example.com/
  // Cover RFC 9421 @authority (the endpoint's host) in the signature, scoping
  // it to that one receiving service — a relayed signature fails on any other
  // host. Opt-in: receivers verifying with @envoys/sdk < 0.9.0 reject
  // signatures covering components they don't reconstruct, so enable this only
  // when you know the receiver is current. Spec v1.6.0 §4.2.
  bindAuthority?: boolean
}

export interface SendOptions {
  text?:  string
  file?:  FileContent
  data?:  unknown
  parts?: A2APart[]
  // Optional message metadata passthrough. The adapter does not interpret these.
  metadata?: Record<string, unknown>
}

export interface SendResult {
  text:      string         // first text artifact, "" if none
  parts:     A2APart[]      // all parts of the first artifact, for convenience
  artifacts: A2AArtifact[]
  taskId:    string
  status:    string
  raw:       A2AResponseEnvelope
}

export interface A2AClient {
  send(opts: string | SendOptions): Promise<SendResult>
}

// Resolve SendOptions into the canonical A2APart[] shape.
// Precedence: explicit parts > text+file+data shortcuts.
function resolveParts(input: string | SendOptions): A2APart[] {
  if (typeof input === 'string') {
    return [{ kind: 'text', text: input }]
  }
  if (input.parts) return input.parts

  const parts: A2APart[] = []
  if (input.text != null) parts.push({ kind: 'text', text: input.text })
  if (input.file != null) parts.push({ kind: 'file', file: input.file })
  if (input.data !== undefined) parts.push({ kind: 'data', data: input.data })
  return parts
}

// Build a JSON-RPC 2.0 message/send envelope.
function buildEnvelope(parts: A2APart[]): A2ARequestEnvelope {
  return {
    jsonrpc: '2.0',
    id:      randomUUID(),
    method:  'message/send',
    params: {
      message: {
        role:      'user',
        messageId: randomUUID(),
        parts,
      },
    },
  }
}

// Sign + send an A2A message. The signature covers @method, @path, and
// the body's content-digest, so any tampering on the wire is detected.
export function createA2AClient(opts: A2AClientOptions): A2AClient {
  const { envoys, endpoint } = opts
  const url  = new URL(endpoint)
  const path = url.pathname && url.pathname !== '' ? url.pathname : '/'
  const authority = opts.bindAuthority ? url.host : undefined

  return {
    async send(input) {
      const parts = resolveParts(input)
      if (parts.length === 0) {
        throw new A2AError('send() requires text, file, data, parts, or a string')
      }

      const envelope   = buildEnvelope(parts)
      const sigHeaders = envoys.signRequest('POST', path, envelope, authority ? { authority } : undefined)

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type':   'application/json',
          'A2A-Extensions': ENVOYS_SIGNATURE_EXT_URI,
          ...sigHeaders,
        },
        body: JSON.stringify(envelope),
      })

      const data = (await res.json().catch(() => null)) as A2AResponseEnvelope | null
      if (!res.ok || !data || data.error) {
        const msg  = data?.error?.message ?? `A2A request failed: ${res.status}`
        const code = data?.error?.code
        throw new A2AError(msg, code, res.status)
      }

      const result = data.result
      if (!result) throw new A2AError('A2A response missing result')

      const artifacts  = result.artifacts ?? []
      const firstParts = artifacts[0]?.parts ?? []
      const firstText  = firstParts.find((p): p is import('./types.js').TextPart => p.kind === 'text')?.text ?? ''

      return {
        text:      firstText,
        parts:     firstParts,
        artifacts,
        taskId:    result.id,
        status:    result.status?.state ?? 'completed',
        raw:       data,
      }
    },
  }
}
