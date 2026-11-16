/**
 * Tool registry + built-in tools.
 *
 * Every tool: typed name, risk level, and a real implementation.
 * Green  : get_time, calculator, memory_search, memory_remember, web_search,
 *          fetch_url, github_read, workspace_read
 * Amber  : workspace_write, n8n_trigger   (need approval at autonomy 2)
 * Red    : none registered. Money movement / live trading is deliberately absent.
 */

import { lookup } from 'dns/promises'
import { isIP } from 'net'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'fs'
import { dirname, relative, resolve, sep } from 'path'
import type { ToolContext, ToolDef } from './types'

export class ToolRegistry {
  private tools = new Map<string, ToolDef>()

  register(t: ToolDef): void {
    if (this.tools.has(t.name)) throw new Error(`Tool already registered: ${t.name}`)
    this.tools.set(t.name, t)
  }
  get(name: string): ToolDef | undefined {
    return this.tools.get(name)
  }
  list(): ToolDef[] {
    return [...this.tools.values()]
  }
}

// ───────────────────────── calculator (no eval) ─────────────────────────

export function calculate(expr: string): number {
  if (expr.length > 200) throw new Error('Expression too long')
  const src = expr.replace(/\s+/g, '')
  let i = 0
  const fns: Record<string, (...a: number[]) => number> = {
    sqrt: Math.sqrt, abs: Math.abs, round: Math.round, floor: Math.floor, ceil: Math.ceil,
    ln: Math.log, log10: Math.log10, min: Math.min, max: Math.max,
  }
  function peek() { return src[i] }
  function number(): number {
    const m = /^\d+(\.\d+)?([eE][+-]?\d+)?/.exec(src.slice(i))
    if (!m) throw new Error(`Unexpected '${src[i] ?? 'end'}' at ${i}`)
    i += m[0].length
    return parseFloat(m[0])
  }
  function primary(): number {
    if (peek() === '(') {
      i++
      const v = additive()
      if (peek() !== ')') throw new Error('Missing )')
      i++
      return v
    }
    if (peek() === '-') { i++; return -power() }
    if (peek() === '+') { i++; return power() }
    const id = /^[a-z][a-z0-9]*/.exec(src.slice(i))
    if (id) {
      const name = id[0]
      i += name.length
      if (name === 'pi') return Math.PI
      if (name === 'e') return Math.E
      const fn = fns[name]
      if (!fn || peek() !== '(') throw new Error(`Unknown function '${name}'`)
      i++
      const args: number[] = []
      if (peek() !== ')') {
        args.push(additive())
        while (peek() === ',') { i++; args.push(additive()) }
      }
      if (peek() !== ')') throw new Error('Missing )')
      i++
      return fn(...args)
    }
    return number()
  }
  function power(): number {
    const base = primary()
    if (peek() === '^') { i++; return Math.pow(base, power()) }
    return base
  }
  function multiplicative(): number {
    let v = power()
    while (peek() === '*' || peek() === '/' || peek() === '%') {
      const op = src[i++]
      const r = power()
      if (op === '*') v *= r
      else if (op === '/') { if (r === 0) throw new Error('Division by zero'); v /= r }
      else v %= r
    }
    return v
  }
  function additive(): number {
    let v = multiplicative()
    while (peek() === '+' || peek() === '-') {
      const op = src[i++]
      const r = multiplicative()
      v = op === '+' ? v + r : v - r
    }
    return v
  }
  const result = additive()
  if (i !== src.length) throw new Error(`Unexpected '${src[i]}' at ${i}`)
  if (!Number.isFinite(result)) throw new Error('Result is not finite')
  return result
}

// ───────────────────────── SSRF guard + fetch ─────────────────────────

export function isPrivateIp(ip: string): boolean {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number)
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    )
  }
  const v = ip.toLowerCase()
  if (v === '::1' || v === '::') return true
  if (v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80')) return true
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v)
  if (mapped) return isPrivateIp(mapped[1])
  return false
}

export async function assertPublicUrl(raw: string): Promise<URL> {
  let u: URL
  try { u = new URL(raw) } catch { throw new Error('Invalid URL') }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Only http(s) URLs are allowed')
  if (u.username || u.password) throw new Error('Credentials in URLs are not allowed')
  const host = u.hostname.replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('Private host blocked')
  const addrs = isIP(host) ? [{ address: host }] : await lookup(host, { all: true })
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address))) throw new Error('Private or unresolvable address blocked')
  return u
}

export function htmlToText(html: string): string {
  return html
    .replace(/<(script|style|noscript)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
}

async function safeFetch(url: string, f: typeof fetch, accept = 'text/html,text/plain,application/json'): Promise<{ finalUrl: string; body: string }> {
  let current = await assertPublicUrl(url)
  for (let hop = 0; hop < 4; hop++) {
    const ctl = new AbortController()
    const t = setTimeout(() => ctl.abort(), 10_000)
    try {
      const res = await f(current.toString(), {
        redirect: 'manual',
        signal: ctl.signal,
        headers: { 'User-Agent': 'JARVIS/0.1 (+personal assistant)', Accept: accept },
      })
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        current = await assertPublicUrl(new URL(res.headers.get('location')!, current).toString()) // re-check every hop
        continue
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const buf = await res.text()
      return { finalUrl: current.toString(), body: buf.slice(0, 500_000) }
    } finally {
      clearTimeout(t)
    }
  }
  throw new Error('Too many redirects')
}

export function parseDuckDuckGo(html: string, limit = 6): { title: string; url: string; snippet: string }[] {
  const out: { title: string; url: string; snippet: string }[] = []
  const re = /<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?(?:<a[^>]*class="result__snippet"[^>]*>([\s\S]*?)<\/a>)?/g
  let m: RegExpExecArray | null
  while ((m = re.exec(html)) && out.length < limit) {
    let url = m[1].replace(/&amp;/g, '&')
    const wrapped = /[?&]uddg=([^&]+)/.exec(url)
    if (wrapped) url = decodeURIComponent(wrapped[1])
    if (url.startsWith('//')) url = 'https:' + url
    if (!/^https?:\/\//.test(url)) continue
    out.push({ title: htmlToText(m[2]), url, snippet: htmlToText(m[3] || '') })
  }
  return out
}

// ───────────────────────── workspace sandbox ─────────────────────────

export function resolveInside(root: string, p: string): string {
  const base = resolve(root)
  const full = resolve(base, p)
  if (full !== base && !full.startsWith(base + sep)) throw new Error('Path escapes the workspace')
  return full
}

const str = (v: unknown, name: string): string => {
  if (typeof v !== 'string' || !v.trim()) throw new Error(`'${name}' (string) is required`)
  return v
}

// ───────────────────────── built-in tools ─────────────────────────

export function registerBuiltins(reg: ToolRegistry, env: NodeJS.ProcessEnv = process.env): ToolRegistry {
  reg.register({
    name: 'get_time',
    description: 'Current date and time.',
    args: '{"timezone"?: "Europe/Dublin"}',
    risk: 'green',
    async run(a) {
      const tz = typeof a.timezone === 'string' ? a.timezone : env.JARVIS_TZ || 'Europe/Dublin'
      try {
        return new Intl.DateTimeFormat('en-IE', { dateStyle: 'full', timeStyle: 'long', timeZone: tz }).format(new Date()) + ` (${tz})`
      } catch {
        throw new Error(`Unknown timezone '${tz}'`)
      }
    },
  })

  reg.register({
    name: 'calculator',
    description: 'Exact arithmetic. Supports + - * / % ^ ( ), sqrt abs round floor ceil ln log10 min max, pi, e.',
    args: '{"expression": "2*(3+4)^2"}',
    risk: 'green',
    async run(a) {
      return String(calculate(str(a.expression, 'expression')))
    },
  })

  reg.register({
    name: 'memory_search',
    description: 'Search long-term memory about the user, their projects and decisions.',
    args: '{"query": "..."}',
    risk: 'green',
    async run(a, ctx) {
      const hits = ctx.memory.search(str(a.query, 'query'))
      return hits.length ? hits.map(h => `- ${h.text}`).join('\n') : 'No matching memories.'
    },
  })

  reg.register({
    name: 'memory_remember',
    description: 'Store a short fact the user asked to be remembered. Secrets/IDs are rejected.',
    args: '{"text": "..."}',
    risk: 'green',
    async run(a, ctx) {
      const r = ctx.memory.add(str(a.text, 'text'), 'agent')
      return r.ok ? `Stored: ${r.entry.text}` : `Not stored: ${r.reason}`
    },
  })

  reg.register({
    name: 'web_search',
    description: 'Search the web (DuckDuckGo). Returns titles, URLs and snippets.',
    args: '{"query": "..."}',
    risk: 'green',
    async run(a, ctx) {
      const q = str(a.query, 'query')
      const { body } = await safeFetch(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(q)}`, ctx.fetchImpl)
      const rows = parseDuckDuckGo(body)
      if (!rows.length) return 'No results (the search page may have changed or blocked the request).'
      return rows.map((r, n) => `${n + 1}. ${r.title}\n   ${r.url}\n   ${r.snippet}`).join('\n')
    },
  })

  reg.register({
    name: 'fetch_url',
    description: 'Download a public web page and return its readable text (max ~8000 chars). Private networks are blocked.',
    args: '{"url": "https://..."}',
    risk: 'green',
    async run(a, ctx) {
      const { finalUrl, body } = await safeFetch(str(a.url, 'url'), ctx.fetchImpl)
      const text = /<html|<body|<!doctype/i.test(body.slice(0, 500)) ? htmlToText(body) : body
      return `[${finalUrl}]\n${text.slice(0, 8000)}`
    },
  })

  reg.register({
    name: 'github_read',
    description: 'Read a file or list a directory in a GitHub repo you own. Read-only.',
    args: '{"repo": "Rishi1980/GODMODE3", "path"?: "README.md", "ref"?: "main"}',
    risk: 'green',
    async run(a, ctx) {
      const repo = str(a.repo, 'repo')
      const m = /^([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+)$/.exec(repo)
      if (!m) throw new Error("'repo' must look like owner/name")
      const owners = (env.JARVIS_GITHUB_OWNERS || 'Rishi1980').split(',').map(s => s.trim().toLowerCase())
      if (!owners.includes(m[1].toLowerCase())) throw new Error(`Owner '${m[1]}' is not in JARVIS_GITHUB_OWNERS`)
      const path = typeof a.path === 'string' ? a.path.replace(/^\/+/, '') : ''
      const ref = typeof a.ref === 'string' ? `?ref=${encodeURIComponent(a.ref)}` : ''
      const headers: Record<string, string> = { Accept: 'application/vnd.github+json', 'User-Agent': 'JARVIS' }
      if (env.GITHUB_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`
      const res = await ctx.fetchImpl(`https://api.github.com/repos/${repo}/contents/${path.split('/').map(encodeURIComponent).join('/')}${ref}`, { headers })
      if (!res.ok) throw new Error(`GitHub HTTP ${res.status}`)
      const data = (await res.json()) as any
      if (Array.isArray(data)) return data.map((f: any) => `${f.type === 'dir' ? 'd' : '-'} ${f.path}`).join('\n')
      if (data.encoding === 'base64') return Buffer.from(data.content, 'base64').toString('utf8').slice(0, 8000)
      return JSON.stringify(data).slice(0, 2000)
    },
  })

  reg.register({
    name: 'workspace_read',
    description: 'Read a file, or list a directory, inside the JARVIS workspace folder.',
    args: '{"path": "notes/todo.md"}',
    risk: 'green',
    async run(a, ctx) {
      const p = resolveInside(ctx.workspaceDir, typeof a.path === 'string' && a.path ? a.path : '.')
      if (!existsSync(p)) throw new Error('Not found')
      if (statSync(p).isDirectory()) {
        return readdirSync(p).map(n => (statSync(resolve(p, n)).isDirectory() ? 'd ' : '- ') + relative(ctx.workspaceDir, resolve(p, n))).join('\n') || '(empty)'
      }
      return readFileSync(p, 'utf8').slice(0, 8000)
    },
  })

  reg.register({
    name: 'workspace_write',
    description: 'Create or overwrite a text file inside the JARVIS workspace folder (needs approval).',
    args: '{"path": "notes/plan.md", "content": "..."}',
    risk: 'amber',
    async run(a, ctx) {
      const p = resolveInside(ctx.workspaceDir, str(a.path, 'path'))
      const content = typeof a.content === 'string' ? a.content : ''
      if (content.length > 200_000) throw new Error('Content too large')
      mkdirSync(dirname(p), { recursive: true })
      writeFileSync(p, content)
      return `Wrote ${content.length} chars to ${relative(ctx.workspaceDir, p)}`
    },
  })

  if (env.JARVIS_N8N_WEBHOOK_BASE) {
    reg.register({
      name: 'n8n_trigger',
      description: 'Trigger a named n8n workflow webhook (needs approval).',
      args: '{"workflow": "daily-report", "payload"?: {}}',
      risk: 'amber',
      async run(a, ctx) {
        const name = str(a.workflow, 'workflow')
        if (!/^[A-Za-z0-9_-]{1,60}$/.test(name)) throw new Error('Invalid workflow name')
        const base = env.JARVIS_N8N_WEBHOOK_BASE!.replace(/\/$/, '')
        const res = await ctx.fetchImpl(`${base}/${name}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(a.payload ?? {}),
        })
        if (!res.ok) throw new Error(`n8n HTTP ${res.status}`)
        return `Triggered '${name}' (HTTP ${res.status})`
      },
    })
  }

  return reg
}

export type { ToolContext }
