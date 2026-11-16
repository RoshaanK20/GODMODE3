/**
 * JARVIS assembly + HTTP routes (mounted at /v1/jarvis).
 *
 * Env:
 *   OPENROUTER_API_KEY | OLLAMA_URL     model provider (at least one)
 *   JARVIS_DATA_DIR                     default ./data/jarvis  (audit.jsonl, memory.json, approvals.json)
 *   JARVIS_WORKSPACE                    default <data>/workspace
 *   JARVIS_AUTONOMY                     0-4, default 2 (supervised)
 *   JARVIS_AUTO_APPROVE                 comma list of amber tools auto-approved at level>=3
 *   JARVIS_GITHUB_OWNERS, GITHUB_TOKEN  github_read scope/auth
 *   JARVIS_N8N_WEBHOOK_BASE             enables n8n_trigger
 */

import { Router } from 'express'
import { resolve } from 'path'
import { AuditLog } from './audit'
import { AGENTS } from './agents'
import { RoutedLLM } from './llm'
import { MemoryStore } from './memory'
import { ApprovalQueue } from './permissions'
import { ToolRegistry, registerBuiltins } from './tools'
import { Zeus, type JarvisDeps } from './zeus'
import type { AutonomyLevel } from './types'

export function buildDeps(env: NodeJS.ProcessEnv = process.env, overrides: Partial<JarvisDeps> = {}): JarvisDeps {
  const dir = resolve(env.JARVIS_DATA_DIR || './data/jarvis')
  const lvl = Math.max(0, Math.min(4, parseInt(env.JARVIS_AUTONOMY || '2', 10) || 0)) as AutonomyLevel
  return {
    llm: new RoutedLLM(env),
    tools: registerBuiltins(new ToolRegistry(), env),
    memory: new MemoryStore(resolve(dir, 'memory.json')),
    audit: new AuditLog(resolve(dir, 'audit.jsonl')),
    approvals: new ApprovalQueue(resolve(dir, 'approvals.json')),
    autonomy: lvl,
    autoApprove: (env.JARVIS_AUTO_APPROVE || '').split(',').map(s => s.trim()).filter(Boolean),
    workspaceDir: resolve(env.JARVIS_WORKSPACE || resolve(dir, 'workspace')),
    ...overrides,
  }
}

export function createJarvisRouter(deps: JarvisDeps = buildDeps()): { router: Router; zeus: Zeus; deps: JarvisDeps } {
  const zeus = new Zeus(deps)
  const router = Router()

  router.get('/status', (_req, res) => {
    res.json({
      name: 'JARVIS',
      autonomy_level: deps.autonomy,
      model_provider_configured: deps.llm.configured,
      agents: Object.values(AGENTS).map(a => ({ name: a.name, role: a.role, tools: a.tools })),
      tools: deps.tools.list().map(t => ({ name: t.name, risk: t.risk, description: t.description })),
      pending_approvals: deps.approvals.list('pending').length,
      audit: deps.audit.verify(),
    })
  })

  router.post('/chat', async (req, res) => {
    const message = req.body?.message
    if (typeof message !== 'string' || !message.trim() || message.length > 4000) {
      res.status(400).json({ error: "'message' (string, 1-4000 chars) is required" })
      return
    }
    const sessionId = typeof req.body?.session_id === 'string' ? req.body.session_id.slice(0, 64) : 'default'
    const r = await zeus.handle(message.trim(), sessionId)
    res.json({
      task_id: r.taskId,
      reply: r.reply,
      ok: r.ok,
      verification: r.verification,
      pending_approvals: r.pendingApprovals,
      steps: r.steps.map(s => ({ agent: s.agent, status: s.status, tools_used: s.evidence.map(e => e.tool) })),
    })
  })

  router.get('/approvals', (_req, res) => {
    res.json({ approvals: deps.approvals.list() })
  })

  router.post('/approvals/:id/:decision', async (req, res) => {
    const decision = req.params.decision
    if (decision !== 'approve' && decision !== 'deny') {
      res.status(400).json({ error: "decision must be 'approve' or 'deny'" })
      return
    }
    const a = await zeus.resolveApproval(req.params.id, decision === 'approve')
    if (!a) {
      res.status(404).json({ error: 'No pending approval with that id (already decided or unknown).' })
      return
    }
    res.json({ approval: a })
  })

  router.get('/audit', (req, res) => {
    res.json({ records: deps.audit.tail(parseInt(String(req.query.limit || '50'), 10) || 50) })
  })
  router.get('/audit/verify', (_req, res) => {
    res.json(deps.audit.verify())
  })

  router.get('/memory', (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q : ''
    res.json({ memories: q ? deps.memory.search(q, 20) : deps.memory.list() })
  })
  router.delete('/memory/:id', (req, res) => {
    const ok = deps.memory.forget(req.params.id)
    deps.audit.record('-', 'USER', ok ? 'memory.forgotten' : 'memory.forget_miss', { id: req.params.id })
    res.status(ok ? 200 : 404).json({ forgotten: ok })
  })

  return { router, zeus, deps }
}
