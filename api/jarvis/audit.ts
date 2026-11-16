/**
 * Tamper-evident audit trail.
 *
 * Each record stores the SHA-256 of the previous record, so any edit, deletion
 * or reordering of the JSONL file is detectable by verify().
 * This detects tampering; it does not prevent it (an attacker who can rewrite
 * the whole file can rebuild the chain). Ship the head hash elsewhere if you
 * need stronger guarantees.
 */

import { createHash } from 'crypto'
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'fs'
import { dirname } from 'path'

export interface AuditRecord {
  seq: number
  ts: string
  taskId: string
  actor: string
  event: string
  detail: Record<string, unknown>
  prev: string
  hash: string
}

const GENESIS = '0'.repeat(64)

function digest(r: Omit<AuditRecord, 'hash'>): string {
  return createHash('sha256')
    .update(JSON.stringify([r.seq, r.ts, r.taskId, r.actor, r.event, r.detail, r.prev]))
    .digest('hex')
}

/** Never write secrets into the log. */
function redact(value: unknown): unknown {
  if (typeof value === 'string') {
    return value
      .replace(/(sk-[A-Za-z0-9_-]{10,})/g, '[REDACTED_KEY]')
      .replace(/(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g, '[REDACTED_TOKEN]')
      .replace(/(Bearer\s+)[A-Za-z0-9._-]{10,}/gi, '$1[REDACTED]')
      .slice(0, 2000)
  }
  if (Array.isArray(value)) return value.map(redact)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v)]))
  }
  return value
}

export class AuditLog {
  private seq = 0
  private last = GENESIS

  constructor(private readonly file: string | null) {
    if (file) {
      mkdirSync(dirname(file), { recursive: true })
      if (existsSync(file)) {
        const rows = this.read()
        if (rows.length) {
          const tail = rows[rows.length - 1]
          this.seq = tail.seq
          this.last = tail.hash
        }
      }
    }
  }

  private mem: AuditRecord[] = []

  record(taskId: string, actor: string, event: string, detail: Record<string, unknown> = {}): AuditRecord {
    const base = {
      seq: this.seq + 1,
      ts: new Date().toISOString(),
      taskId,
      actor,
      event,
      detail: redact(detail) as Record<string, unknown>,
      prev: this.last,
    }
    const rec: AuditRecord = { ...base, hash: digest(base) }
    this.seq = rec.seq
    this.last = rec.hash
    if (this.file) appendFileSync(this.file, JSON.stringify(rec) + '\n')
    else this.mem.push(rec)
    return rec
  }

  read(): AuditRecord[] {
    if (!this.file) return [...this.mem]
    if (!existsSync(this.file)) return []
    return readFileSync(this.file, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(l => JSON.parse(l) as AuditRecord)
  }

  tail(n = 50): AuditRecord[] {
    return this.read().slice(-Math.max(1, Math.min(n, 500)))
  }

  /** Returns the first broken sequence number, or null if the chain is intact. */
  verify(): { ok: boolean; brokenAt: number | null; records: number } {
    const rows = this.read()
    let prev = GENESIS
    for (const [i, r] of rows.entries()) {
      const { hash, ...rest } = r
      if (r.prev !== prev || digest(rest) !== hash || r.seq !== i + 1) {
        return { ok: false, brokenAt: r.seq, records: rows.length }
      }
      prev = hash
    }
    return { ok: true, brokenAt: null, records: rows.length }
  }
}
