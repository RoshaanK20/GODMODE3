/**
 * ZEUS — chief orchestrator.
 *
 *   message → (explicit memory?) → plan → delegate to agents (tool loop, permission-checked)
 *           → SENTINEL verification → NOVA friendly reply → audit
 *
 * Failure policy: never fabricate success. LLM outage, tool errors, exhausted
 * step budgets and unverifiable claims are all surfaced in the reply.
 */

import { randomUUID } from 'crypto'
import { AuditLog } from './audit'
import { AGENTS, AGENT_NAMES, PERSONA, type AgentDef } from './agents'
import { extractJson } from './llm'
import { MemoryStore, extractExplicitMemory } from './memory'
import { ApprovalQueue, decide, type Approval } from './permissions'
import { ToolRegistry } from './tools'
import type {
  AutonomyLevel, Evidence, LLM, Msg, StepResult, TaskResult, ToolContext, Verification,
} from './types'

export interface JarvisDeps {
  llm: LLM
  tools: ToolRegistry
  memory: MemoryStore
  audit: AuditLog
  approvals: ApprovalQueue
  autonomy: AutonomyLevel
  autoApprove: string[]
  workspaceDir: string
  fetchImpl?: typeof fetch
  maxAgentIterations?: number
  toolTimeoutMs?: number
}

const MAX_STEPS = 3

type AgentAction = { tool?: string; args?: Record<string, unknown>; final?: string }

export class Zeus {
  private history = new Map<string, Msg[]>()

  constructor(private readonly d: JarvisDeps) {}

  private ctx(taskId: string, agent: string): ToolContext {
    return {
      taskId,
      agent,
      workspaceDir: this.d.workspaceDir,
      memory: this.d.memory,
      fetchImpl: this.d.fetchImpl ?? fetch,
    }
  }

  // ───────────────────────── public API ─────────────────────────

  async handle(message: string, sessionId = 'default'): Promise<TaskResult> {
    const taskId = randomUUID()
    const { audit } = this.d
    audit.record(taskId, 'USER', 'task.received', { message, sessionId })

    // 1. Explicit "remember ..." never needs a model, so it works offline.
    const mem = extractExplicitMemory(message)
    if (mem) {
      const r = this.d.memory.add(mem, 'user')
      audit.record(taskId, 'LARA', r.ok ? 'memory.stored' : 'memory.rejected', { text: mem, reason: r.ok ? undefined : r.reason })
      const reply = r.ok ? `Got it. I'll remember: "${r.entry.text}"` : `I didn't save that: ${r.reason}`
      return this.finish(taskId, sessionId, message, reply, [], { verdict: 'not_applicable', issues: [] }, r.ok)
    }

    // 2. No model → say so honestly.
    if (!this.d.llm.configured) {
      const reply = "I can't think without a model. Set OPENROUTER_API_KEY (free models work) or OLLAMA_URL on the server and I'm good to go."
      audit.record(taskId, 'ZEUS', 'task.failed', { reason: 'no_llm' })
      return this.finish(taskId, sessionId, message, reply, [], { verdict: 'not_applicable', issues: [] }, false)
    }

    try {
      const memories = this.d.memory.search(message, 4)
      const plan = await this.plan(taskId, message, memories.map(m => m.text))

      const steps: StepResult[] = []
      for (const s of plan.slice(0, MAX_STEPS)) {
        const prior = steps.filter(x => x.status === 'done').map(x => `${x.agent}: ${x.output}`).join('\n')
        const res = await this.runAgent(taskId, AGENTS[s.agent], s.task, prior)
        steps.push(res)
        if (res.status === 'awaiting_approval') break // later steps may depend on it
      }

      const verification = await this.verify(taskId, message, steps)
      const reply = await this.compose(taskId, sessionId, message, memories.map(m => m.text), steps, verification)
      const ok = steps.every(s => s.status === 'done') && verification.verdict !== 'unsupported'
      return this.finish(taskId, sessionId, message, reply, steps, verification, ok)
    } catch (e) {
      const err = (e as Error).message
      audit.record(taskId, 'ZEUS', 'task.failed', { error: err })
      return this.finish(taskId, sessionId, message, `That didn't work, and I'd rather tell you than fake it: ${err}`, [], { verdict: 'not_applicable', issues: [] }, false)
    }
  }

  /** Human decision on a queued amber action. */
  async resolveApproval(id: string, approve: boolean): Promise<Approval | null> {
    const { approvals, audit, tools } = this.d
    const a = approvals.get(id)
    if (!a || a.status !== 'pending') return null

    if (!approve) {
      const denied = approvals.transition(id, 'pending', 'denied')
      if (denied) audit.record(a.taskId, 'USER', 'approval.denied', { id, tool: a.tool })
      return denied
    }

    const tool = tools.get(a.tool)
    if (!approvals.transition(id, 'pending', 'approved')) return null // lost a race → don't double-run
    audit.record(a.taskId, 'USER', 'approval.granted', { id, tool: a.tool, args: a.args })
    if (!tool || tool.risk === 'red') {
      return approvals.transition(id, 'approved', 'failed', 'Tool unavailable or not permitted.')
    }
    try {
      const out = await this.runTool(tool.name, a.args, this.ctx(a.taskId, a.agent))
      audit.record(a.taskId, a.agent, 'tool.executed', { tool: a.tool, approved: true, result: out })
      return approvals.transition(id, 'approved', 'executed', out)
    } catch (e) {
      audit.record(a.taskId, a.agent, 'tool.failed', { tool: a.tool, error: (e as Error).message })
      return approvals.transition(id, 'approved', 'failed', (e as Error).message)
    }
  }

  // ───────────────────────── planning ─────────────────────────

  private isTrivial(m: string): boolean {
    const t = m.trim()
    return t.length < 25 && !/[?]/.test(t) && !/\d/.test(t)
  }

  private async plan(taskId: string, message: string, memories: string[]): Promise<{ agent: string; task: string }[]> {
    if (this.isTrivial(message)) {
      this.d.audit.record(taskId, 'ZEUS', 'plan', { steps: [], reason: 'conversational' })
      return []
    }
    const agentList = AGENT_NAMES.map(n => `- ${n}: ${AGENTS[n].role} (tools: ${AGENTS[n].tools.join(', ')})`).join('\n')
    const prompt: Msg[] = [
      {
        role: 'system',
        content:
          `You are ZEUS, the planner of JARVIS. Decide whether the user's request needs specialist agents with tools.\n` +
          `Delegate ONLY when tools are genuinely required (current/web information, calculations, reading repos or files, stored memory, automations). ` +
          `Chat, opinions, advice and explanations need NO steps.\nAgents:\n${agentList}\n` +
          `Reply with JSON only: {"steps":[{"agent":"ATLAS","task":"specific instruction"}]}. Max ${MAX_STEPS} steps. Empty steps array = answer directly.`,
      },
      { role: 'user', content: `Request: ${message}${memories.length ? `\nKnown context: ${memories.join('; ')}` : ''}` },
    ]
    let raw = ''
    try {
      raw = await this.d.llm.complete(prompt, { tier: 'fast', json: true, temperature: 0.1, maxTokens: 400 })
    } catch (e) {
      this.d.audit.record(taskId, 'ZEUS', 'plan.failed', { error: (e as Error).message })
      throw e
    }
    const parsed = extractJson<{ steps?: { agent?: string; task?: string }[] }>(raw)
    const steps = (parsed?.steps ?? [])
      .filter(s => s && typeof s.agent === 'string' && typeof s.task === 'string' && AGENTS[s.agent.toUpperCase()])
      .map(s => ({ agent: s.agent!.toUpperCase(), task: s.task! }))
    this.d.audit.record(taskId, 'ZEUS', 'plan', { steps, parsed: Boolean(parsed) })
    return steps
  }

  // ───────────────────────── agent tool loop ─────────────────────────

  private async runTool(name: string, args: Record<string, unknown>, ctx: ToolContext): Promise<string> {
    const tool = this.d.tools.get(name)
    if (!tool) throw new Error(`Unknown tool '${name}'`)
    const ms = this.d.toolTimeoutMs ?? 20_000
    return await Promise.race([
      tool.run(args, ctx),
      new Promise<string>((_, rej) => setTimeout(() => rej(new Error(`Tool '${name}' timed out after ${ms}ms`)), ms)),
    ])
  }

  private async runAgent(taskId: string, agent: AgentDef, task: string, prior: string): Promise<StepResult> {
    const { audit, tools, approvals } = this.d
    const allowed = agent.tools.map(n => tools.get(n)).filter((t): t is NonNullable<typeof t> => Boolean(t))
    const toolDocs = allowed.map(t => `- ${t.name} [${t.risk}] ${t.description} args: ${t.args}`).join('\n') || '(none)'
    const messages: Msg[] = [
      {
        role: 'system',
        content:
          `${agent.system}\n\nTools you may call:\n${toolDocs}\n\n` +
          `Protocol — reply with exactly one JSON object each turn:\n` +
          `  call a tool:  {"tool":"<name>","args":{...}}\n` +
          `  finish:       {"final":"<your answer>"}\n` +
          `After each tool call you will receive an OBSERVATION. Do not output anything except the JSON object.`,
      },
      { role: 'user', content: `Task: ${task}${prior ? `\n\nResults from earlier steps:\n${prior}` : ''}` },
    ]
    const evidence: Evidence[] = []
    const max = this.d.maxAgentIterations ?? 5
    audit.record(taskId, agent.name, 'step.start', { task })

    for (let i = 0; i < max; i++) {
      let raw: string
      try {
        raw = await this.d.llm.complete(messages, { tier: 'fast', json: true, temperature: 0.2 })
      } catch (e) {
        audit.record(taskId, agent.name, 'step.failed', { error: (e as Error).message })
        return { agent: agent.name, task, status: 'failed', output: `Model error: ${(e as Error).message}`, evidence }
      }
      const act = extractJson<AgentAction>(raw)

      if (!act || (!act.tool && typeof act.final !== 'string')) {
        // Model ignored the protocol: accept its text as the answer but flag no tool evidence.
        audit.record(taskId, agent.name, 'step.done', { protocolViolation: true })
        return { agent: agent.name, task, status: 'done', output: raw.trim().slice(0, 4000), evidence }
      }
      if (typeof act.final === 'string' && !act.tool) {
        audit.record(taskId, agent.name, 'step.done', { toolCalls: evidence.length })
        return { agent: agent.name, task, status: 'done', output: act.final, evidence }
      }

      const name = String(act.tool)
      const args = (act.args && typeof act.args === 'object' ? act.args : {}) as Record<string, unknown>
      messages.push({ role: 'assistant', content: JSON.stringify({ tool: name, args }) })

      const tool = tools.get(name)
      if (!tool || !agent.tools.includes(name)) {
        audit.record(taskId, agent.name, 'tool.refused', { tool: name, reason: 'not_in_allowlist' })
        messages.push({ role: 'user', content: `OBSERVATION: tool '${name}' is not available to you. Use only: ${agent.tools.join(', ')}.` })
        continue
      }

      const decision = decide(tool.risk, this.d.autonomy, tool.name, this.d.autoApprove)
      if (!decision.allow) {
        if (decision.needsApproval) {
          const a = approvals.create(taskId, agent.name, tool.name, args)
          audit.record(taskId, agent.name, 'approval.requested', { id: a.id, tool: tool.name, args })
          return {
            agent: agent.name, task, status: 'awaiting_approval', approvalId: a.id, evidence,
            output: `Waiting for your approval to run ${tool.name}(${JSON.stringify(args).slice(0, 300)}).`,
          }
        }
        audit.record(taskId, agent.name, 'tool.blocked', { tool: tool.name, reason: decision.reason })
        return { agent: agent.name, task, status: 'blocked', output: `Blocked: ${decision.reason}`, evidence }
      }

      try {
        const result = await this.runTool(tool.name, args, this.ctx(taskId, agent.name))
        evidence.push({ tool: tool.name, args, result: result.slice(0, 3000) })
        audit.record(taskId, agent.name, 'tool.executed', { tool: tool.name, args, result })
        messages.push({ role: 'user', content: `OBSERVATION: ${result.slice(0, 3000)}` })
      } catch (e) {
        const msg = (e as Error).message
        audit.record(taskId, agent.name, 'tool.failed', { tool: tool.name, error: msg })
        messages.push({ role: 'user', content: `OBSERVATION: ERROR from ${tool.name}: ${msg}` })
      }
    }

    audit.record(taskId, agent.name, 'step.failed', { reason: 'iteration_budget_exhausted' })
    return { agent: agent.name, task, status: 'failed', output: `I ran out of attempts (${max}) before finishing this step.`, evidence }
  }

  // ───────────────────────── SENTINEL ─────────────────────────

  /** URLs the answer cites that no tool actually returned = likely fabricated. */
  static unsupportedUrls(answer: string, evidence: Evidence[]): string[] {
    const seen = evidence.map(e => `${JSON.stringify(e.args)} ${e.result}`).join('\n')
    const urls = answer.match(/https?:\/\/[^\s)\]">]+/g) ?? []
    return [...new Set(urls)].filter(u => !seen.includes(u.replace(/[.,;]+$/, '')))
  }

  private async verify(taskId: string, question: string, steps: StepResult[]): Promise<Verification> {
    const done = steps.filter(s => s.status === 'done')
    if (!steps.length) return { verdict: 'not_applicable', issues: [] }
    const evidence = steps.flatMap(s => s.evidence)
    const issues: string[] = []

    for (const s of done) {
      const bad = Zeus.unsupportedUrls(s.output, evidence)
      if (bad.length) issues.push(`${s.agent} cited URLs no tool returned: ${bad.slice(0, 3).join(', ')}`)
      if (!s.evidence.length && /https?:\/\//.test(s.output)) issues.push(`${s.agent} gave links without using any tool.`)
    }
    for (const s of steps) if (s.status === 'failed') issues.push(`${s.agent} step failed.`)

    let verdict: Verification['verdict'] = issues.length ? 'partial' : 'supported'
    if (done.length) {
      try {
        const raw = await this.d.llm.complete(
          [
            { role: 'system', content: 'You are SENTINEL, a strict fact-checker. Given a question, draft answers and the tool evidence, decide if every factual claim is supported by the evidence. Reply JSON only: {"verdict":"supported|partial|unsupported","issues":["..."]}' },
            {
              role: 'user',
              content: `Question: ${question}\n\nDraft answers:\n${done.map(s => `${s.agent}: ${s.output}`).join('\n')}\n\nEvidence:\n${evidence.map(e => `[${e.tool} ${JSON.stringify(e.args)}] ${e.result.slice(0, 1200)}`).join('\n') || '(no tool evidence)'}`,
            },
          ],
          { tier: 'fast', json: true, temperature: 0, maxTokens: 400 },
        )
        const j = extractJson<{ verdict?: string; issues?: string[] }>(raw)
        if (j && ['supported', 'partial', 'unsupported'].includes(String(j.verdict))) {
          for (const x of j.issues ?? []) issues.push(String(x))
          const rank = { supported: 0, partial: 1, unsupported: 2 } as const
          const v = j.verdict as keyof typeof rank
          if (rank[v] > rank[verdict as keyof typeof rank]) verdict = v
        } else {
          issues.push('Automated fact-check output was unreadable.')
          if (verdict === 'supported') verdict = 'partial'
        }
      } catch (e) {
        issues.push(`Automated fact-check unavailable: ${(e as Error).message}`)
        if (verdict === 'supported') verdict = 'partial'
      }
    }
    this.d.audit.record(taskId, 'SENTINEL', 'verification', { verdict, issues })
    return { verdict, issues }
  }

  // ───────────────────────── NOVA ─────────────────────────

  private async compose(
    taskId: string, sessionId: string, message: string, memories: string[], steps: StepResult[], v: Verification,
  ): Promise<string> {
    const hist = (this.history.get(sessionId) ?? []).slice(-10)
    const pending = steps.filter(s => s.status === 'awaiting_approval')
    const facts =
      steps.map(s => `[${s.agent} — ${s.status}] ${s.output}`).join('\n') || '(no specialist work was needed)'
    const sys =
      `${PERSONA}\n\n` +
      (memories.length ? `Things you know about the user (use only if relevant): ${memories.join('; ')}\n\n` : '') +
      (steps.length
        ? `Specialist results (ground truth — do not add facts beyond these):\n${facts}\n\n` +
          `Verification verdict: ${v.verdict}${v.issues.length ? `. Issues: ${v.issues.join(' | ')}` : ''}\n` +
          `If verdict is partial/unsupported or any step failed, lead with that caveat. ` +
          (pending.length ? `Some actions are waiting for the user's approval — tell them clearly. ` : '')
        : '')
    try {
      return await this.d.llm.complete(
        [{ role: 'system', content: sys }, ...hist, { role: 'user', content: message }],
        { tier: steps.length > 1 ? 'strong' : 'fast', temperature: 0.7, maxTokens: 900 },
      )
    } catch (e) {
      this.d.audit.record(taskId, 'NOVA', 'compose.failed', { error: (e as Error).message })
      // Honest degraded mode: raw results, no pretty wrapper.
      return steps.length
        ? `I couldn't phrase this nicely (model error), but here are the raw results:\n${facts}`
        : `I hit a model error and couldn't answer: ${(e as Error).message}`
    }
  }

  // ───────────────────────── wrap up ─────────────────────────

  private finish(
    taskId: string, sessionId: string, message: string, reply: string,
    steps: StepResult[], verification: Verification, ok: boolean,
  ): TaskResult {
    const h = this.history.get(sessionId) ?? []
    h.push({ role: 'user', content: message }, { role: 'assistant', content: reply })
    this.history.set(sessionId, h.slice(-20))
    this.d.audit.record(taskId, 'ZEUS', 'task.completed', { ok, steps: steps.map(s => `${s.agent}:${s.status}`), verdict: verification.verdict })
    return {
      taskId, reply, steps, verification, ok,
      pendingApprovals: steps.filter(s => s.approvalId).map(s => s.approvalId!),
    }
  }
}
