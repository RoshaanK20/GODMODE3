/**
 * Permission engine + approval queue.
 *
 * Policy:
 *  - red   : never executed automatically, at any autonomy level. (Financial
 *            transactions, live trading, destructive operations.) No red tool
 *            is registered in this build; the rule exists so one can't sneak in.
 *  - amber : side effects. Level < 2 → blocked. Level 2 → needs human approval.
 *            Level >= 3 → auto-allowed ONLY if the tool name is in
 *            JARVIS_AUTO_APPROVE (explicit allowlist), otherwise needs approval.
 *  - green : read/analyse. Allowed at every level.
 */

import { randomUUID } from 'crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs'
import { dirname } from 'path'
import type { AutonomyLevel, Risk } from './types'

export type Decision =
  | { allow: true; reason: string }
  | { allow: false; needsApproval: boolean; reason: string }

export function decide(risk: Risk, level: AutonomyLevel, toolName: string, autoApprove: string[] = []): Decision {
  if (risk === 'red') {
    return { allow: false, needsApproval: false, reason: 'Red-risk actions are never executed automatically.' }
  }
  if (risk === 'green') return { allow: true, reason: 'Read-only / analysis action.' }
  // amber
  if (level < 2) {
    return { allow: false, needsApproval: false, reason: `Autonomy level ${level} is observe/assist only; side effects are blocked.` }
  }
  if (level >= 3 && autoApprove.includes(toolName)) {
    return { allow: true, reason: `Auto-approved: '${toolName}' is on the bounded-autonomy allowlist.` }
  }
  return { allow: false, needsApproval: true, reason: 'Side-effect action requires human approval.' }
}

export interface Approval {
  id: string
  taskId: string
  agent: string
  tool: string
  args: Record<string, unknown>
  status: 'pending' | 'approved' | 'denied' | 'executed' | 'failed'
  createdAt: string
  decidedAt?: string
  result?: string
}

export class ApprovalQueue {
  private items = new Map<string, Approval>()

  constructor(private readonly file: string | null) {
    if (file) {
      mkdirSync(dirname(file), { recursive: true })
      if (existsSync(file)) {
        try {
          for (const a of JSON.parse(readFileSync(file, 'utf8')) as Approval[]) this.items.set(a.id, a)
        } catch {
          // Corrupt file: start empty rather than crash. Audit log still has history.
        }
      }
    }
  }

  private persist(): void {
    if (!this.file) return
    const tmp = this.file + '.tmp'
    writeFileSync(tmp, JSON.stringify([...this.items.values()], null, 2))
    renameSync(tmp, this.file) // atomic replace → no half-written state
  }

  create(taskId: string, agent: string, tool: string, args: Record<string, unknown>): Approval {
    const a: Approval = {
      id: randomUUID(),
      taskId,
      agent,
      tool,
      args,
      status: 'pending',
      createdAt: new Date().toISOString(),
    }
    this.items.set(a.id, a)
    this.persist()
    return a
  }

  get(id: string): Approval | undefined {
    return this.items.get(id)
  }

  list(status?: Approval['status']): Approval[] {
    return [...this.items.values()].filter(a => !status || a.status === status)
  }

  /** Idempotent guard: only a pending approval can be decided, so a double-click can't run a tool twice. */
  transition(id: string, from: Approval['status'], to: Approval['status'], result?: string): Approval | null {
    const a = this.items.get(id)
    if (!a || a.status !== from) return null
    a.status = to
    a.decidedAt = new Date().toISOString()
    if (result !== undefined) a.result = result.slice(0, 4000)
    this.persist()
    return a
  }
}
