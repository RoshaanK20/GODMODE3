/**
 * JARVIS verification suite — run with: npm run jarvis:test
 *
 * Gates covered: functional, security, failure, recovery/idempotency, audit.
 * Model calls are scripted (no network). What this does NOT prove: that a real
 * free model follows the JSON tool protocol well, or that live web search works.
 * See api/jarvis/README.md → "Not verified".
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import express from 'express'
import type { AddressInfo } from 'net'

import { AuditLog } from './audit'
import { ApprovalQueue, decide } from './permissions'
import { MemoryStore, extractExplicitMemory, isStorable } from './memory'
import { ToolRegistry, assertPublicUrl, calculate, htmlToText, isPrivateIp, parseDuckDuckGo, registerBuiltins, resolveInside } from './tools'
import { extractJson } from './llm'
import { Zeus, type JarvisDeps } from './zeus'
import { buildDeps, createJarvisRouter } from './index'
import type { AutonomyLevel, LLM, Msg } from './types'

const tmp = () => mkdtempSync(join(tmpdir(), 'jarvis-'))

// ───────────── scripted LLM ─────────────
interface Script {
  plan?: string
  agent?: string[]
  verdict?: string
  compose?: string | (() => never)
}
class ScriptLLM implements LLM {
  configured = true
  calls: { role: string; system: string }[] = []
  private agentQ: string[]
  constructor(private s: Script) { this.agentQ = [...(s.agent ?? [])] }
  async complete(m: Msg[]): Promise<string> {
    const sys = m[0].content
    const role = sys.includes('You are ZEUS') ? 'plan' : sys.includes('You are SENTINEL') ? 'verify' : sys.includes('You are JARVIS') ? 'compose' : 'agent'
    this.calls.push({ role, system: sys })
    if (role === 'plan') return this.s.plan ?? '{"steps":[]}'
    if (role === 'verify') return this.s.verdict ?? '{"verdict":"supported","issues":[]}'
    if (role === 'compose') {
      if (typeof this.s.compose === 'function') this.s.compose()
      return (this.s.compose as string) ?? 'ok'
    }
    const next = this.agentQ.shift()
    if (next === undefined) throw new Error('script exhausted')
    return next
  }
}

function mkZeus(script: Script, o: { autonomy?: AutonomyLevel; llm?: LLM; fetchImpl?: typeof fetch; maxAgentIterations?: number } = {}) {
  const dir = tmp()
  const deps: JarvisDeps = {
    llm: o.llm ?? new ScriptLLM(script),
    tools: registerBuiltins(new ToolRegistry(), {}),
    memory: new MemoryStore(join(dir, 'memory.json')),
    audit: new AuditLog(join(dir, 'audit.jsonl')),
    approvals: new ApprovalQueue(join(dir, 'approvals.json')),
    autonomy: o.autonomy ?? 2,
    autoApprove: [],
    workspaceDir: join(dir, 'ws'),
    fetchImpl: o.fetchImpl,
    maxAgentIterations: o.maxAgentIterations,
  }
  return { zeus: new Zeus(deps), deps, dir, llm: deps.llm as ScriptLLM }
}

// ───────────── audit ─────────────
test('audit: chain verifies, detects tampering, redacts secrets', () => {
  const dir = tmp()
  const f = join(dir, 'a.jsonl')
  const log = new AuditLog(f)
  log.record('t1', 'ZEUS', 'x', { a: 1 })
  log.record('t1', 'ZEUS', 'y', { key: 'sk-or-v1-abcdefghijklmnopqrstuvwxyz', h: 'Bearer abcdefghijklmnop1234' })
  assert.equal(log.verify().ok, true)
  assert.ok(!readFileSync(f, 'utf8').includes('abcdefghijklmnopqrstuvwxyz'), 'API key must be redacted')
  // restart continues the chain
  const log2 = new AuditLog(f)
  log2.record('t2', 'ZEUS', 'z')
  assert.equal(new AuditLog(f).verify().ok, true)
  // tamper
  writeFileSync(f, readFileSync(f, 'utf8').replace('"event":"x"', '"event":"edited"'))
  const v = new AuditLog(f).verify()
  assert.equal(v.ok, false)
  assert.equal(v.brokenAt, 1)
})

test('audit: deleting a record is detected', () => {
  const f = join(tmp(), 'a.jsonl')
  const log = new AuditLog(f)
  for (const e of ['a', 'b', 'c']) log.record('t', 'ZEUS', e)
  const lines = readFileSync(f, 'utf8').trim().split('\n')
  writeFileSync(f, [lines[0], lines[2]].join('\n') + '\n')
  assert.equal(new AuditLog(f).verify().ok, false)
})

// ───────────── permissions ─────────────
test('permissions: policy matrix', () => {
  const lv = [0, 1, 2, 3, 4] as AutonomyLevel[]
  for (const l of lv) {
    assert.equal(decide('green', l, 't').allow, true)
    assert.deepEqual(decide('red', l, 't', ['t']), { allow: false, needsApproval: false, reason: decide('red', l, 't').reason })
  }
  for (const l of [0, 1] as AutonomyLevel[]) {
    const d = decide('amber', l, 't', ['t'])
    assert.equal(d.allow, false)
    assert.equal('needsApproval' in d && d.needsApproval, false, 'observe/assist: blocked outright, not queued')
  }
  const d2 = decide('amber', 2, 't', ['t'])
  assert.equal(d2.allow === false && d2.needsApproval, true, 'level 2 never auto-approves, even if allowlisted')
  assert.equal(decide('amber', 3, 't', ['t']).allow, true)
  const d3 = decide('amber', 3, 'other', ['t'])
  assert.equal(d3.allow === false && d3.needsApproval, true, 'level 3 only auto-approves allowlisted tools')
})

test('approvals: single decision, persistence across restart', () => {
  const f = join(tmp(), 'ap.json')
  const q = new ApprovalQueue(f)
  const a = q.create('t', 'ENGINEER', 'workspace_write', { path: 'x' })
  assert.ok(q.transition(a.id, 'pending', 'approved'))
  assert.equal(q.transition(a.id, 'pending', 'approved'), null, 'second decision rejected')
  assert.equal(new ApprovalQueue(f).get(a.id)?.status, 'approved')
})

// ───────────── memory ─────────────
test('memory: BM25 relevance, dedupe, forget, privacy filter', () => {
  const m = new MemoryStore(null)
  m.add('Lives in Dublin, Ireland')
  m.add('Builds paper trading systems as a hobby')
  m.add('Prefers dark dashboards with green accents')
  assert.match(m.search('where do I live in Dublin')[0].text, /Dublin/)
  assert.match(m.search('trading hobby')[0].text, /trading/)
  assert.equal(m.search('quantum chromodynamics').length, 0, 'no match → no hallucinated memory')
  const e = m.add('lives in dublin, ireland')
  assert.ok(e.ok)
  assert.equal(m.list().length, 3, 'case-insensitive dedupe')
  const id = m.list()[0].id
  assert.equal(m.forget(id), true)
  assert.equal(m.list().length, 2)
  for (const bad of ['my card is 4111 1111 1111 1111', 'ssn 123-45-6789', 'api key sk-or-v1-abcdefghijklmnopqrstuvwxyz', 'password: hunter2', 'x'.repeat(1001), '  ']) {
    assert.equal(isStorable(bad).ok, false, bad.slice(0, 30))
  }
  assert.equal(extractExplicitMemory('Jarvis, remember that I like tea'), 'I like tea')
  assert.equal(extractExplicitMemory('do you remember my name?'), null)
})

// ───────────── tools: security ─────────────
test('calculator: correct maths, no code execution', () => {
  assert.equal(calculate('2*(3+4)^2'), 98)
  assert.equal(calculate('-2^2'), -4)
  assert.equal(calculate('sqrt(144)+max(1,2,3)'), 15)
  assert.equal(calculate('10%4'), 2)
  assert.ok(Math.abs(calculate('pi*2') - 6.283185307) < 1e-6)
  for (const bad of ['process.exit(1)', 'require("fs")', '1;2', 'constructor', '1/0', '2**', '((1)', 'a+1', '9'.repeat(300)]) {
    assert.throws(() => calculate(bad), /./, bad.slice(0, 30))
  }
})

test('SSRF guard blocks private/loopback/metadata/non-http targets', async () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254', '100.64.0.1', '::1', 'fd00::1', '::ffff:127.0.0.1', '0.0.0.0']) {
    assert.equal(isPrivateIp(ip), true, ip)
  }
  for (const ip of ['8.8.8.8', '93.184.216.34', '2606:4700:4700::1111']) assert.equal(isPrivateIp(ip), false, ip)
  for (const url of ['http://localhost:3000', 'http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data', 'file:///etc/passwd', 'ftp://example.com', 'http://user:pw@8.8.8.8/', 'http://[::1]/', 'http://printer.local/', 'not a url']) {
    await assert.rejects(assertPublicUrl(url), /./, url)
  }
  await assert.doesNotReject(assertPublicUrl('http://8.8.8.8/'))
})

test('fetch_url: redirect into a private address is blocked', async () => {
  const reg = registerBuiltins(new ToolRegistry(), {})
  const f = (async (url: string) => {
    if (String(url).startsWith('http://8.8.8.8')) return new Response(null, { status: 302, headers: { location: 'http://169.254.169.254/latest/meta-data' } })
    throw new Error('should never reach the private address')
  }) as unknown as typeof fetch
  const m = new MemoryStore(null)
  await assert.rejects(
    reg.get('fetch_url')!.run({ url: 'http://8.8.8.8/' }, { taskId: 't', agent: 'ATLAS', workspaceDir: tmp(), memory: m, fetchImpl: f }),
    /Private/,
  )
})

test('fetch_url: returns readable text from a public page', async () => {
  const reg = registerBuiltins(new ToolRegistry(), {})
  const f = (async () => new Response('<html><head><style>x{}</style></head><body><script>evil()</script><h1>Hello</h1><p>World &amp; co</p></body></html>', { status: 200 })) as unknown as typeof fetch
  const out = await reg.get('fetch_url')!.run({ url: 'http://8.8.8.8/' }, { taskId: 't', agent: 'ATLAS', workspaceDir: tmp(), memory: new MemoryStore(null), fetchImpl: f })
  assert.match(out, /Hello World & co/)
  assert.ok(!out.includes('evil()'))
})

test('workspace sandbox: path traversal is refused', () => {
  const root = tmp()
  assert.doesNotThrow(() => resolveInside(root, 'notes/a.md'))
  for (const p of ['../etc/passwd', '/etc/passwd', 'a/../../x', '..']) assert.throws(() => resolveInside(root, p), /escapes/, p)
})

test('github_read: refuses owners outside the allowlist, makes no request', async () => {
  const reg = registerBuiltins(new ToolRegistry(), { JARVIS_GITHUB_OWNERS: 'Rishi1980' })
  let called = false
  const f = (async () => { called = true; return new Response('{}') }) as unknown as typeof fetch
  await assert.rejects(
    reg.get('github_read')!.run({ repo: 'evil/repo' }, { taskId: 't', agent: 'ATLAS', workspaceDir: tmp(), memory: new MemoryStore(null), fetchImpl: f }),
    /not in JARVIS_GITHUB_OWNERS/,
  )
  assert.equal(called, false)
})

test('parsers: DuckDuckGo results + JSON extraction', () => {
  const html = `<div class="result"><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa%3Fx%3D1&amp;rut=zz">Example <b>A</b></a><a class="result__snippet" href="x">First &amp; best</a></div>
  <div class="result"><a class="result__a" href="https://example.org/b">Org B</a><a class="result__snippet" href="x">Second</a></div>`
  const r = parseDuckDuckGo(html)
  assert.equal(r.length, 2)
  assert.equal(r[0].url, 'https://example.com/a?x=1')
  assert.equal(r[0].title, 'Example A')
  assert.equal(htmlToText('<p>a&nbsp;b</p>'), 'a b')
  assert.deepEqual(extractJson('Sure! ```json\n{"a":{"b":"}"},"c":1}\n``` hope that helps'), { a: { b: '}' }, c: 1 })
  assert.equal(extractJson('no json here'), null)
})

// ───────────── ZEUS: functional ─────────────
test('ZEUS: small talk skips planning, replies via NOVA', async () => {
  const { zeus, llm } = mkZeus({ compose: 'Hey! Good to hear from you.' })
  const r = await zeus.handle('hey jarvis')
  assert.equal(r.reply, 'Hey! Good to hear from you.')
  assert.deepEqual(llm.calls.map(c => c.role), ['compose'], 'no planner call, no agent call, no verifier call')
  assert.equal(r.ok, true)
})

test('ZEUS: delegates to ORACLE, uses calculator, verifies, answers', async () => {
  const { zeus, deps, llm } = mkZeus({
    plan: '{"steps":[{"agent":"ORACLE","task":"Compute 12*12"}]}',
    agent: ['{"tool":"calculator","args":{"expression":"12*12"}}', '{"final":"12*12 = 144"}'],
    compose: 'It comes to 144.',
  })
  const r = await zeus.handle('What is 12 times 12? Use maths please.')
  assert.equal(r.steps[0].status, 'done')
  assert.equal(r.steps[0].evidence[0].tool, 'calculator')
  assert.equal(r.steps[0].evidence[0].result, '144')
  assert.equal(r.verification.verdict, 'supported')
  assert.equal(r.reply, 'It comes to 144.')
  assert.ok(llm.calls.find(c => c.role === 'compose')!.system.includes('12*12 = 144'), 'NOVA is given the specialist results')
  const events = deps.audit.read().map(x => x.event)
  for (const e of ['task.received', 'plan', 'step.start', 'tool.executed', 'step.done', 'verification', 'task.completed']) assert.ok(events.includes(e), e)
  assert.equal(deps.audit.verify().ok, true)
})

test('ZEUS: explicit "remember" works with no model configured; memory is then used for recall', async () => {
  const dead: LLM = { configured: false, complete: async () => { throw new Error('unreachable') } }
  const { zeus, deps } = mkZeus({}, { llm: dead })
  const r = await zeus.handle('Jarvis, remember that my favourite chart style is candlesticks')
  assert.match(r.reply, /remember/i)
  assert.equal(deps.memory.list().length, 1)
  const r2 = await zeus.handle('what is the weather like?')
  assert.equal(r2.ok, false)
  assert.match(r2.reply, /OPENROUTER_API_KEY/)
  const r3 = await zeus.handle('remember my card is 4111 1111 1111 1111')
  assert.match(r3.reply, /didn't save/)
  assert.equal(deps.memory.list().length, 1)
})

// ───────────── ZEUS: approvals / autonomy ─────────────
const WRITE_PLAN = '{"steps":[{"agent":"ENGINEER","task":"Save a plan"}]}'
const WRITE_CALL = '{"tool":"workspace_write","args":{"path":"plan.md","content":"hello"}}'

test('amber action pauses for approval; nothing is written until a human approves; approval is single-use', async () => {
  const { zeus, deps } = mkZeus({ plan: WRITE_PLAN, agent: [WRITE_CALL], compose: 'Waiting on you.' })
  const r = await zeus.handle('Please save a plan file in my workspace?')
  assert.equal(r.steps[0].status, 'awaiting_approval')
  assert.equal(r.pendingApprovals.length, 1)
  assert.equal(r.ok, false)
  const file = join(deps.workspaceDir, 'plan.md')
  assert.equal(existsSync(file), false, 'must not write before approval')

  const id = r.pendingApprovals[0]
  const done = await zeus.resolveApproval(id, true)
  assert.equal(done?.status, 'executed')
  assert.equal(readFileSync(file, 'utf8'), 'hello')
  assert.equal(await zeus.resolveApproval(id, true), null, 'replaying an approval must not re-run the tool')
  const ev = deps.audit.read().map(x => x.event)
  assert.ok(ev.includes('approval.requested') && ev.includes('approval.granted') && ev.includes('tool.executed'))
})

test('denied approval never executes', async () => {
  const { zeus, deps } = mkZeus({ plan: WRITE_PLAN, agent: [WRITE_CALL] })
  const r = await zeus.handle('Please save a plan file in my workspace?')
  const a = await zeus.resolveApproval(r.pendingApprovals[0], false)
  assert.equal(a?.status, 'denied')
  assert.equal(existsSync(join(deps.workspaceDir, 'plan.md')), false)
})

test('autonomy level 1 (assist) blocks side effects outright and queues nothing', async () => {
  const { zeus, deps } = mkZeus({ plan: WRITE_PLAN, agent: [WRITE_CALL] }, { autonomy: 1 })
  const r = await zeus.handle('Please save a plan file in my workspace?')
  assert.equal(r.steps[0].status, 'blocked')
  assert.equal(deps.approvals.list().length, 0)
  assert.equal(existsSync(join(deps.workspaceDir, 'plan.md')), false)
})

test('autonomy level 3 auto-runs only allowlisted amber tools', async () => {
  const a = mkZeus({ plan: WRITE_PLAN, agent: [WRITE_CALL, '{"final":"saved"}'] }, { autonomy: 3 })
  a.deps.autoApprove = ['workspace_write']
  const r = await a.zeus.handle('Please save a plan file in my workspace?')
  assert.equal(r.steps[0].status, 'done')
  assert.equal(readFileSync(join(a.deps.workspaceDir, 'plan.md'), 'utf8'), 'hello')
  const b = mkZeus({ plan: WRITE_PLAN, agent: [WRITE_CALL] }, { autonomy: 3 }) // no allowlist
  assert.equal((await b.zeus.handle('Please save a plan file in my workspace?')).steps[0].status, 'awaiting_approval')
})

test('agents cannot call tools outside their allowlist', async () => {
  const { zeus, deps } = mkZeus({
    plan: '{"steps":[{"agent":"ORACLE","task":"x"}]}',
    agent: ['{"tool":"workspace_write","args":{"path":"pwn.txt","content":"x"}}', '{"final":"could not"}'],
  })
  const r = await zeus.handle('Do something clever with files?')
  assert.equal(existsSync(join(deps.workspaceDir, 'pwn.txt')), false)
  assert.ok(deps.audit.read().some(x => x.event === 'tool.refused'))
  assert.equal(deps.approvals.list().length, 0)
  assert.equal(r.steps[0].evidence.length, 0)
})

// ───────────── ZEUS: honesty / failure ─────────────
test('SENTINEL flags links the tools never returned, and the reply is told to caveat', async () => {
  const { zeus, llm } = mkZeus({
    plan: '{"steps":[{"agent":"ATLAS","task":"find docs"}]}',
    agent: ['{"final":"See https://totally-made-up.example/docs for details"}'],
    compose: 'Careful: unverified link.',
  })
  const r = await zeus.handle('Where are the docs for this library?')
  assert.equal(r.verification.verdict, 'partial')
  assert.ok(r.verification.issues.some(i => /made-up|no tool|links/i.test(i)))
  assert.match(llm.calls.find(c => c.role === 'compose')!.system, /partial/)
})

test('SENTINEL: a link that a tool really returned is accepted', () => {
  const ev = [{ tool: 'web_search', args: { query: 'x' }, result: '1. T\n   https://example.com/a?x=1\n   s' }]
  assert.deepEqual(Zeus.unsupportedUrls('Source: https://example.com/a?x=1.', ev), [])
  assert.deepEqual(Zeus.unsupportedUrls('Source: https://other.example/', ev), ['https://other.example/'])
})

test('tool failure is reported, never papered over', async () => {
  const f = (async () => new Response('nope', { status: 500 })) as unknown as typeof fetch
  const { zeus, deps } = mkZeus({
    plan: '{"steps":[{"agent":"ATLAS","task":"read a page"}]}',
    agent: ['{"tool":"fetch_url","args":{"url":"http://8.8.8.8/"}}', '{"final":"The page could not be fetched (HTTP 500)."}'],
    compose: 'The page is down, sorry.',
  }, { fetchImpl: f })
  const r = await zeus.handle('Read this page for me please?')
  assert.equal(r.steps[0].evidence.length, 0, 'failed call is not evidence')
  assert.ok(deps.audit.read().some(x => x.event === 'tool.failed'))
})

test('step budget exhaustion → failed step, ok=false', async () => {
  const loop = Array(10).fill('{"tool":"get_time","args":{}}')
  const { zeus } = mkZeus({ plan: '{"steps":[{"agent":"ORACLE","task":"x"}]}', agent: loop }, { maxAgentIterations: 3 })
  const r = await zeus.handle('What time is it, exactly?')
  assert.equal(r.steps[0].status, 'failed')
  assert.equal(r.ok, false)
})

test('model outage during a task → honest failure, audited', async () => {
  const boom: LLM = { configured: true, complete: async () => { throw new Error('provider down') } }
  const { zeus, deps } = mkZeus({}, { llm: boom })
  const r = await zeus.handle('Tell me something interesting about space?')
  assert.equal(r.ok, false)
  assert.match(r.reply, /provider down/)
  assert.ok(deps.audit.read().some(x => x.event === 'task.failed'))
})

test('NOVA failure falls back to raw results instead of silence', async () => {
  const { zeus } = mkZeus({
    plan: '{"steps":[{"agent":"ORACLE","task":"x"}]}',
    agent: ['{"final":"RAW-RESULT"}'],
    compose: () => { throw new Error('nova down') },
  })
  const r = await zeus.handle('Work something out for me?')
  assert.match(r.reply, /RAW-RESULT/)
  assert.match(r.reply, /model error/)
})

test('garbage planner output degrades to a direct answer, not a crash', async () => {
  const { zeus } = mkZeus({ plan: 'lol no json', compose: 'Direct answer.' })
  const r = await zeus.handle('Explain how bonds work please?')
  assert.equal(r.reply, 'Direct answer.')
  assert.equal(r.steps.length, 0)
})

test('planner cannot invent agents', async () => {
  const { zeus } = mkZeus({ plan: '{"steps":[{"agent":"ROOT","task":"rm -rf"},{"agent":"ORACLE","task":"ok"}]}', agent: ['{"final":"fine"}'], compose: 'k' })
  const r = await zeus.handle('Please do a thing for me?')
  assert.deepEqual(r.steps.map(s => s.agent), ['ORACLE'])
})

// ───────────── HTTP layer ─────────────
test('HTTP: validation, status, approvals 404, audit verify, memory CRUD', async () => {
  const { deps } = mkZeus({})
  const { router } = createJarvisRouter(deps)
  const app = express()
  app.use(express.json())
  app.use('/v1/jarvis', router)
  const server = app.listen(0)
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/jarvis`
  try {
    const bad = await fetch(`${base}/chat`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })
    assert.equal(bad.status, 400)
    const long = await fetch(`${base}/chat`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'x'.repeat(5000) }) })
    assert.equal(long.status, 400)

    const st = await (await fetch(`${base}/status`)).json() as any
    assert.equal(st.name, 'JARVIS')
    assert.equal(st.autonomy_level, 2)
    assert.ok(st.tools.every((t: any) => t.risk !== 'red'), 'no red tools registered')
    assert.deepEqual(st.agents.map((a: any) => a.name).sort(), ['ATLAS', 'AUTOPILOT', 'ENGINEER', 'LARA', 'ORACLE'])

    const chat = await (await fetch(`${base}/chat`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'remember that I like green charts' }) })).json() as any
    assert.equal(chat.ok, true)
    const mem = await (await fetch(`${base}/memory?q=charts`)).json() as any
    assert.equal(mem.memories.length, 1)
    const del = await fetch(`${base}/memory/${mem.memories[0].id}`, { method: 'DELETE' })
    assert.equal(del.status, 200)
    assert.equal((await fetch(`${base}/memory/nope`, { method: 'DELETE' })).status, 404)

    assert.equal((await fetch(`${base}/approvals/unknown/approve`, { method: 'POST' })).status, 404)
    assert.equal((await fetch(`${base}/approvals/unknown/maybe`, { method: 'POST' })).status, 400)
    const v = await (await fetch(`${base}/audit/verify`)).json() as any
    assert.equal(v.ok, true)
    assert.ok(v.records >= 3)
  } finally {
    server.close()
  }
})

test('buildDeps: autonomy is clamped and read from env', () => {
  const dir = tmp()
  assert.equal(buildDeps({ JARVIS_DATA_DIR: dir, JARVIS_AUTONOMY: '99' }).autonomy, 4)
  assert.equal(buildDeps({ JARVIS_DATA_DIR: dir, JARVIS_AUTONOMY: '-3' }).autonomy, 0)
  assert.equal(buildDeps({ JARVIS_DATA_DIR: dir }).autonomy, 2)
  assert.deepEqual(buildDeps({ JARVIS_DATA_DIR: dir, JARVIS_AUTO_APPROVE: 'a, b' }).autoApprove, ['a', 'b'])
  void appendFileSync
})
