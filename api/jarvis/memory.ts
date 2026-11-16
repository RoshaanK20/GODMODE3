/**
 * LARA — controlled long-term memory.
 *
 * Local JSON store with BM25-style keyword ranking. No external service needed.
 * (pgvector/Qdrant can replace search() later behind the same interface.)
 *
 * Controls:
 *  - Only explicit "remember ..." statements are stored automatically.
 *  - Obvious secrets / government-ID / card numbers are rejected.
 *  - Every entry is listable and deletable by the user.
 */

import { randomUUID } from 'crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs'
import { dirname } from 'path'

export interface MemoryEntry {
  id: string
  text: string
  createdAt: string
  source: 'user' | 'agent'
}

const STOP = new Set('a an the and or of to in on for with is are was were be been it this that i my me you your we our at as by from'.split(' '))

function tokens(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(t => t.length > 1 && !STOP.has(t))
}

const BLOCKED: RegExp[] = [
  /\b(?:\d[ -]?){13,19}\b/, // payment-card-like numbers
  /\b\d{3}-\d{2}-\d{4}\b/, // SSN-like
  /sk-[A-Za-z0-9_-]{16,}/, // API keys
  /(ghp_|github_pat_)[A-Za-z0-9_]{16,}/,
  /\b(password|passwd|secret|private key|seed phrase)\b\s*[:=]/i,
]

export function isStorable(text: string): { ok: boolean; reason?: string } {
  if (!text.trim()) return { ok: false, reason: 'Empty.' }
  if (text.length > 1000) return { ok: false, reason: 'Too long (max 1000 chars).' }
  for (const re of BLOCKED) {
    if (re.test(text)) return { ok: false, reason: 'Looks like a secret or sensitive identifier; not stored.' }
  }
  return { ok: true }
}

/** Detects an explicit "remember ..." instruction. Returns the thing to remember, or null. */
export function extractExplicitMemory(message: string): string | null {
  const m = message.match(/^\s*(?:jarvis[,:]?\s*)?(?:please\s+)?remember(?:\s+that)?\s+(.{3,})$/i)
  return m ? m[1].trim() : null
}

export class MemoryStore {
  private entries: MemoryEntry[] = []

  constructor(private readonly file: string | null) {
    if (file) {
      mkdirSync(dirname(file), { recursive: true })
      if (existsSync(file)) {
        try {
          this.entries = JSON.parse(readFileSync(file, 'utf8')) as MemoryEntry[]
        } catch {
          this.entries = []
        }
      }
    }
  }

  private persist(): void {
    if (!this.file) return
    const tmp = this.file + '.tmp'
    writeFileSync(tmp, JSON.stringify(this.entries, null, 2))
    renameSync(tmp, this.file)
  }

  add(text: string, source: MemoryEntry['source'] = 'user'): { ok: true; entry: MemoryEntry } | { ok: false; reason: string } {
    const check = isStorable(text)
    if (!check.ok) return { ok: false, reason: check.reason! }
    const norm = text.trim()
    const dup = this.entries.find(e => e.text.toLowerCase() === norm.toLowerCase())
    if (dup) return { ok: true, entry: dup }
    const entry: MemoryEntry = { id: randomUUID(), text: norm, createdAt: new Date().toISOString(), source }
    this.entries.push(entry)
    this.persist()
    return { ok: true, entry }
  }

  list(): MemoryEntry[] {
    return [...this.entries]
  }

  forget(id: string): boolean {
    const n = this.entries.length
    this.entries = this.entries.filter(e => e.id !== id)
    const removed = this.entries.length !== n
    if (removed) this.persist()
    return removed
  }

  /** BM25 ranking over stored entries. Returns only entries with a positive score. */
  search(query: string, limit = 5): MemoryEntry[] {
    const q = tokens(query)
    if (!q.length || !this.entries.length) return []
    const docs = this.entries.map(e => tokens(e.text))
    const N = docs.length
    const avg = docs.reduce((s, d) => s + d.length, 0) / N || 1
    const k1 = 1.5
    const b = 0.75
    const df = new Map<string, number>()
    for (const t of new Set(q)) df.set(t, docs.filter(d => d.includes(t)).length)
    const scored = this.entries.map((e, i) => {
      const d = docs[i]
      let score = 0
      for (const t of new Set(q)) {
        const f = d.filter(x => x === t).length
        if (!f) continue
        const n = df.get(t) || 0
        const idf = Math.log(1 + (N - n + 0.5) / (n + 0.5))
        score += idf * ((f * (k1 + 1)) / (f + k1 * (1 - b + (b * d.length) / avg)))
      }
      return { e, score }
    })
    return scored
      .filter(s => s.score > 0)
      .sort((a, b2) => b2.score - a.score)
      .slice(0, limit)
      .map(s => s.e)
  }
}
