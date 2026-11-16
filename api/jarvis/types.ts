/**
 * JARVIS — shared types.
 *
 * Design rule: "Capability before autonomy". Every tool declares a risk level,
 * every agent declares an explicit tool allowlist, and every action is audited.
 */

/** green = read/analyse; amber = side effects, needs approval; red = never automatic. */
export type Risk = 'green' | 'amber' | 'red'

/** 0 observe · 1 assist · 2 supervised · 3 bounded · 4 conditional */
export type AutonomyLevel = 0 | 1 | 2 | 3 | 4

export interface Msg {
  role: 'system' | 'user' | 'assistant'
  content: string
}

export interface LLMOptions {
  tier: 'fast' | 'strong'
  json?: boolean
  maxTokens?: number
  temperature?: number
}

export interface LLM {
  readonly configured: boolean
  complete(messages: Msg[], opts: LLMOptions): Promise<string>
}

export interface ToolContext {
  taskId: string
  agent: string
  workspaceDir: string
  memory: import('./memory').MemoryStore
  fetchImpl: typeof fetch
}

export interface ToolDef {
  name: string
  description: string
  /** Human-readable argument shape shown to the model. */
  args: string
  risk: Risk
  run(args: Record<string, unknown>, ctx: ToolContext): Promise<string>
}

export interface Evidence {
  tool: string
  args: Record<string, unknown>
  result: string
}

export type StepStatus = 'done' | 'failed' | 'awaiting_approval' | 'blocked'

export interface StepResult {
  agent: string
  task: string
  status: StepStatus
  output: string
  evidence: Evidence[]
  approvalId?: string
}

export interface Verification {
  verdict: 'supported' | 'partial' | 'unsupported' | 'not_applicable'
  issues: string[]
}

export interface TaskResult {
  taskId: string
  reply: string
  steps: StepResult[]
  verification: Verification
  pendingApprovals: string[]
  ok: boolean
}
