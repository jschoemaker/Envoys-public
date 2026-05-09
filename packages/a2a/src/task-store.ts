// Task lifecycle storage. Holds completed tasks so clients can call
// tasks/get / tasks/cancel after the message/send round-trip ends.
//
// The default in-memory store is bounded — once `maxSize` is reached,
// the oldest entry is evicted. Replace with a Redis/SQL-backed store
// for multi-process deployments by passing your own implementation.

import type { A2ATaskResult } from './types.js'

export interface TaskStore {
  get(id: string):    Promise<A2ATaskResult | null>
  set(id: string, task: A2ATaskResult): Promise<void>
  // Returns the new task state if the task existed and was eligible for
  // cancellation. Returns the unchanged task if it was already terminal.
  // Returns null if no task with that id exists.
  cancel(id: string): Promise<A2ATaskResult | null>
}

export interface InMemoryTaskStoreOptions {
  // Soft cap on stored tasks. When exceeded, oldest entries are evicted.
  // Default: 1000.
  maxSize?: number
}

export class InMemoryTaskStore implements TaskStore {
  private readonly tasks   = new Map<string, A2ATaskResult>()
  private readonly maxSize: number

  constructor(opts: InMemoryTaskStoreOptions = {}) {
    this.maxSize = opts.maxSize ?? 1000
  }

  async get(id: string): Promise<A2ATaskResult | null> {
    return this.tasks.get(id) ?? null
  }

  async set(id: string, task: A2ATaskResult): Promise<void> {
    if (this.tasks.size >= this.maxSize && !this.tasks.has(id)) {
      // Map preserves insertion order — evict the oldest.
      const oldest = this.tasks.keys().next().value
      if (oldest !== undefined) this.tasks.delete(oldest)
    }
    this.tasks.set(id, task)
  }

  async cancel(id: string): Promise<A2ATaskResult | null> {
    const task = this.tasks.get(id)
    if (!task) return null

    const state = task.status.state
    if (state === 'completed' || state === 'failed' || state === 'canceled') {
      return task  // already terminal, unchanged
    }

    const updated: A2ATaskResult = { ...task, status: { state: 'canceled' } }
    this.tasks.set(id, updated)
    return updated
  }

  // Test/debug helpers — not part of the TaskStore interface.
  size(): number { return this.tasks.size }
  clear(): void  { this.tasks.clear() }
}
