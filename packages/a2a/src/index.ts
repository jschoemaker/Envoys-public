export { createA2AClient } from './client.js'
export type { A2AClient, A2AClientOptions, SendOptions, SendResult } from './client.js'

export { createA2AHandler } from './handler.js'
export type { CreateHandlerOptions, HandlerInput, HandlerOutput } from './handler.js'

export { buildAgentCard } from './card.js'
export type { AgentCard, AgentCardOptions, AgentCardCapabilities, AgentSkill } from './card.js'

export { A2AError } from './errors.js'

export { ENVOYS_SIGNATURE_EXT_URI, ENVOYS_SECURITY_SCHEME } from './spec.js'

export { InMemoryTaskStore } from './task-store.js'
export type { TaskStore, InMemoryTaskStoreOptions } from './task-store.js'

export type {
  A2APart,
  TextPart,
  FilePart,
  DataPart,
  FileContent,
  FileWithBytes,
  FileWithUri,
  A2AMessage,
  A2AArtifact,
  A2ATaskResult,
  A2ATaskStatus,
  A2ARequestEnvelope,
  A2AResponseEnvelope,
  A2AContext,
  A2AMessageHandler,
  A2AHandlerReturn,
} from './types.js'
