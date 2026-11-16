/**
 * Model providers + cheap-first routing.
 *
 *  fast   → small/free model for routing, simple answers, tool loops
 *  strong → larger model for planning/verification when needed
 *
 * Providers (tried in order, first success wins):
 *   1. OpenRouter (OPENROUTER_API_KEY)  — free ":free" models by default
 *   2. Ollama     (OLLAMA_URL)          — fully local, no key
 *
 * Model IDs on OpenRouter change often. Override with JARVIS_FAST_MODEL /
 * JARVIS_STRONG_MODEL (comma-separated lists are tried in order).
 */

import type { LLM, LLMOptions, Msg } from './types'

const DEFAULT_FAST = 'meta-llama/llama-3.3-70b-instruct:free,google/gemma-3-27b-it:free'
const DEFAULT_STRONG = 'deepseek/deepseek-r1-distill-llama-70b:free,meta-llama/llama-3.3-70b-instruct:free'

function list(env: string | undefined, fallback: string): string[] {
  return (env || fallback).split(',').map(s => s.trim()).filter(Boolean)
}

async function withTimeout<T>(ms: number, fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort(), ms)
  try {
    return await fn(ctl.signal)
  } finally {
    clearTimeout(t)
  }
}

export class RoutedLLM implements LLM {
  constructor(
    private readonly env: NodeJS.ProcessEnv = process.env,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  get configured(): boolean {
    return Boolean(this.env.OPENROUTER_API_KEY || this.env.OLLAMA_URL)
  }

  async complete(messages: Msg[], opts: LLMOptions): Promise<string> {
    if (!this.configured) {
      throw new Error('No model provider configured. Set OPENROUTER_API_KEY (free models work) or OLLAMA_URL.')
    }
    const errors: string[] = []

    if (this.env.OPENROUTER_API_KEY) {
      const models = opts.tier === 'strong'
        ? list(this.env.JARVIS_STRONG_MODEL, DEFAULT_STRONG)
        : list(this.env.JARVIS_FAST_MODEL, DEFAULT_FAST)
      for (const model of models) {
        try {
          return await this.openrouter(model, messages, opts)
        } catch (e) {
          errors.push(`openrouter:${model}: ${(e as Error).message}`)
        }
      }
    }

    if (this.env.OLLAMA_URL) {
      const model = opts.tier === 'strong'
        ? this.env.JARVIS_OLLAMA_STRONG || this.env.JARVIS_OLLAMA_MODEL || 'llama3.1'
        : this.env.JARVIS_OLLAMA_MODEL || 'llama3.1'
      try {
        return await this.ollama(model, messages, opts)
      } catch (e) {
        errors.push(`ollama:${model}: ${(e as Error).message}`)
      }
    }

    throw new Error(`All model providers failed. ${errors.join(' | ')}`)
  }

  private async openrouter(model: string, messages: Msg[], opts: LLMOptions): Promise<string> {
    const res = await withTimeout(60_000, signal =>
      this.fetchImpl('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        signal,
        headers: {
          Authorization: `Bearer ${this.env.OPENROUTER_API_KEY}`,
          'Content-Type': 'application/json',
          'X-Title': 'JARVIS',
        },
        body: JSON.stringify({
          model,
          messages,
          temperature: opts.temperature ?? 0.4,
          max_tokens: opts.maxTokens ?? 1200,
        }),
      }),
    )
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = (await res.json()) as { choices?: { message?: { content?: string } }[] }
    const text = data.choices?.[0]?.message?.content
    if (!text) throw new Error('empty completion')
    return text
  }

  private async ollama(model: string, messages: Msg[], opts: LLMOptions): Promise<string> {
    const base = this.env.OLLAMA_URL!.replace(/\/$/, '')
    const res = await withTimeout(120_000, signal =>
      this.fetchImpl(`${base}/api/chat`, {
        method: 'POST',
        signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          messages,
          stream: false,
          format: opts.json ? 'json' : undefined,
          options: { temperature: opts.temperature ?? 0.4, num_predict: opts.maxTokens ?? 1200 },
        }),
      }),
    )
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = (await res.json()) as { message?: { content?: string } }
    if (!data.message?.content) throw new Error('empty completion')
    return data.message.content
  }
}

/** Pull the first balanced JSON object out of a model reply (models often wrap JSON in prose/fences). */
export function extractJson<T = unknown>(text: string): T | null {
  const start = text.indexOf('{')
  if (start < 0) return null
  let depth = 0
  let inStr = false
  let esc = false
  for (let i = start; i < text.length; i++) {
    const c = text[i]
    if (inStr) {
      if (esc) esc = false
      else if (c === '\\') esc = true
      else if (c === '"') inStr = false
      continue
    }
    if (c === '"') inStr = true
    else if (c === '{') depth++
    else if (c === '}' && --depth === 0) {
      try {
        return JSON.parse(text.slice(start, i + 1)) as T
      } catch {
        return null
      }
    }
  }
  return null
}
