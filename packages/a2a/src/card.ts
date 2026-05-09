// Helpers for building and serving A2A Agent Cards.
// When requireEnvoysSignature is set, the card declares the Envoys Signature
// Extension per https://envoys.me/specs/signature/v1 §3.

import { ENVOYS_SECURITY_SCHEME, ENVOYS_SIGNATURE_EXT_URI } from './spec.js'

export interface AgentSkill {
  id:           string
  name:         string
  description?: string
  inputModes?:  string[]
  outputModes?: string[]
}

export interface AgentCardOptions {
  name:          string
  description?:  string
  url:           string
  version?:      string
  skills?:       AgentSkill[]
  capabilities?: { streaming?: boolean; pushNotifications?: boolean }
  // If true, declares the Envoys Signature Extension on the card.
  requireEnvoysSignature?: boolean
  // Extra fields merged into the card (e.g. provider, contact).
  extra?: Record<string, unknown>
}

export interface AgentCardCapabilities {
  streaming:          boolean
  pushNotifications?: boolean
  extensions?:        string[]
}

export interface AgentCard {
  name:        string
  description: string
  url:         string
  version:     string
  capabilities: AgentCardCapabilities
  skills:      AgentSkill[]
  securitySchemes?: Record<string, unknown>
  security?:       Array<Record<string, string[]>>
  [key: string]: unknown
}

export function buildAgentCard(opts: AgentCardOptions): AgentCard {
  const card: AgentCard = {
    name:         opts.name,
    description:  opts.description ?? '',
    url:          opts.url,
    version:      opts.version ?? '1.0.0',
    capabilities: { streaming: false, ...(opts.capabilities ?? {}) },
    skills:       opts.skills ?? [],
  }

  if (opts.requireEnvoysSignature) {
    card.capabilities.extensions = [
      ...(card.capabilities.extensions ?? []),
      ENVOYS_SIGNATURE_EXT_URI,
    ]
    card.securitySchemes = {
      [ENVOYS_SECURITY_SCHEME]: {
        type:         'extension',
        extensionUri: ENVOYS_SIGNATURE_EXT_URI,
        description:  'RFC 9421 Ed25519 signatures with self-resolving keyid.',
      },
    }
    card.security = [{ [ENVOYS_SECURITY_SCHEME]: [] }]
  }

  if (opts.extra) Object.assign(card, opts.extra)
  return card
}
