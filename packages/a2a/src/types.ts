// A2A protocol types — JSON-RPC 2.0 envelopes and message shapes.
// Pared to message/send and the parts the spec defines (text, file, data).

// ── Parts ────────────────────────────────────────────────────────────────────

export interface TextPart {
  kind:     'text'
  text:     string
  metadata?: Record<string, unknown>
}

export interface FileWithBytes {
  name?:     string
  mimeType?: string
  bytes:     string  // base64-encoded
}

export interface FileWithUri {
  name?:     string
  mimeType?: string
  uri:       string
}

export type FileContent = FileWithBytes | FileWithUri

export interface FilePart {
  kind:      'file'
  file:      FileContent
  metadata?: Record<string, unknown>
}

export interface DataPart {
  kind:      'data'
  data:      unknown
  metadata?: Record<string, unknown>
}

export type A2APart = TextPart | FilePart | DataPart

// ── Messages, artifacts, tasks ──────────────────────────────────────────────

export interface A2AMessage {
  role:      'user' | 'agent'
  messageId: string
  parts:     A2APart[]
  metadata?: Record<string, unknown>
}

export interface A2AArtifact {
  parts:     A2APart[]
  metadata?: Record<string, unknown>
}

export interface A2ATaskStatus {
  state: 'submitted' | 'completed' | 'failed' | 'canceled'
}

export interface A2ATaskResult {
  id:        string
  status:    A2ATaskStatus
  artifacts: A2AArtifact[]
}

// ── JSON-RPC envelopes ──────────────────────────────────────────────────────

export interface A2ARequestEnvelope {
  jsonrpc: '2.0'
  id:      string
  method:  string
  params:  { message: A2AMessage }
}

export interface A2AResponseEnvelope {
  jsonrpc: '2.0'
  id:      string
  result?: A2ATaskResult
  error?:  { code: number; message: string }
}

// ── Handler context + return ────────────────────────────────────────────────

export interface A2AContext {
  sender:   string          // verified Envoys address
  text:     string           // first text part, "" if none
  parts:    A2APart[]        // all message parts
  message:  A2AMessage
  envelope: A2ARequestEnvelope
}

export type A2AHandlerReturn =
  | string
  | {
      text?:      string
      file?:      FileContent
      data?:      unknown
      parts?:     A2APart[]
      artifacts?: A2AArtifact[]
      status?:    A2ATaskStatus['state']
    }

export type A2AMessageHandler = (ctx: A2AContext) => Promise<A2AHandlerReturn> | A2AHandlerReturn
