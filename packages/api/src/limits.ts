export type Tier = 'free' | 'pro' | 'max' | 'enterprise'

export const TIER_LIMITS: Record<Tier, {
  agents: number       // max active (non-revoked) agents
  customDomains: number // verified custom domains
  ratePerMinute: number // API requests per minute
}> = {
  free: {
    agents:       5,
    customDomains: 0,
    ratePerMinute: 30,
  },
  pro: {
    agents:       30,
    customDomains: 3,
    ratePerMinute: 300,
  },
  max: {
    agents:       Infinity,
    customDomains: Infinity,
    ratePerMinute: 2_000,
  },
  enterprise: {
    agents:       Infinity,
    customDomains: Infinity,
    ratePerMinute: Infinity,
  },
}

export function getLimits(tier: string) {
  return TIER_LIMITS[tier as Tier] ?? TIER_LIMITS.free
}
