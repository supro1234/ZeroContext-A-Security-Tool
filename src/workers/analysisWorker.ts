/**
 * analysisWorker.ts
 * ZeroContext Analysis Web Worker
 *
 * SECURITY: This worker has no DOM access, no localStorage, no cookie access.
 * Network access is blocked via CSP (connect-src 'none' in worker context).
 * All analysis runs here — never on the main thread.
 */

import type { WorkerRequest, WorkerMessage } from '../types/worker'
import type { IncidentReport } from '../types/threat'
import { normalizePayload, getAllLayers } from '../engine/normalizer'
import { detectHomoglyphs } from '../engine/homoglyphDetector'
import { matchAllLayers, loadRules, highestSeverity, getRulesVersion } from '../engine/ruleMatcher'
import { parseValidatedRulesFile } from '../engine/schemaValidator'

// ─── State ──────────────────────────────────────────────────────────────────

let rulesLoaded = false
let cancelled = false

// ─── Helper: post typed messages ────────────────────────────────────────────

function post(msg: WorkerMessage) {
  self.postMessage(msg)
}

function progress(stage: string, percent: number) {
  post({ type: 'PROGRESS', data: { status: 'normalizing', stage, percent } })
}

// ─── Rules Loading ──────────────────────────────────────────────────────────

async function ensureRulesLoaded() {
  if (rulesLoaded) return
  try {
    // Use relative URL — worker runs in same origin as app
    const resp = await fetch('/rules/rules.json')
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    const raw = await resp.json()
    const validated = parseValidatedRulesFile(raw)
    loadRules(validated)
    rulesLoaded = true
  } catch (e) {
    post({
      type: 'ERROR',
      error: `Failed to load rules: ${e instanceof Error ? e.message : String(e)}`,
      code: 'RULES_INVALID',
    })
    throw e
  }
}

// ─── Session ID ─────────────────────────────────────────────────────────────

function generateId(): string {
  return crypto.randomUUID()
}

async function sha256(text: string): Promise<string> {
  const buffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text)
  )
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// ─── Main Analysis ──────────────────────────────────────────────────────────

async function analyze(payload: string, sessionId: string) {
  const start = performance.now()
  cancelled = false

  try {
    progress('Loading rules…', 5)
    await ensureRulesLoaded()
    if (cancelled) return

    progress('Normalizing payload…', 20)
    const normResult = normalizePayload(payload)
    if (cancelled) return

    progress('Detecting homoglyphs…', 35)
    const homoglyphResult = detectHomoglyphs(normResult.final)
    if (cancelled) return

    // Also run homoglyph detection on original input
    const rawHomoglyphs = detectHomoglyphs(payload)

    // Merge unique homoglyph matches
    const allHomoglyphs = [...rawHomoglyphs.matches]
    for (const m of homoglyphResult.matches) {
      if (!allHomoglyphs.find(h => h.codepoint === m.codepoint && h.position === m.position)) {
        allHomoglyphs.push(m)
      }
    }

    progress('Matching threat rules…', 50)
    post({ type: 'PROGRESS', data: { status: 'matching', stage: 'Matching threat rules…', percent: 50 } })

    // Get all decode layers for multi-pass matching
    const layers = getAllLayers(normResult)

    // Also include homoglyph-normalized version
    if (homoglyphResult.normalized !== normResult.final) {
      layers.push({ text: homoglyphResult.normalized, depth: 99 })
    }

    const threats = matchAllLayers(layers)
    if (cancelled) return

    progress('Computing severity…', 80)
    const severity = highestSeverity(threats)

    progress('Generating report…', 90)
    const inputHash = await sha256(payload)
    if (cancelled) return

    const report: IncidentReport = {
      id: generateId(),
      sessionId,
      timestamp: new Date().toISOString(),
      inputLength: payload.length,
      inputHash,
      severity,
      threats,
      normalizationTrace: normResult.layers,
      homoglyphs: allHomoglyphs,
      aiAnalysis: null,  // filled in by main thread after AI call
      processingTimeMs: Math.round(performance.now() - start),
      rulesVersion: getRulesVersion(),
      engineMode: 'offline',
    }

    post({ type: 'PROGRESS', data: { status: 'complete', stage: 'Analysis complete', percent: 100 } })
    post({ type: 'RESULT', data: report })

  } catch (e) {
    if (!cancelled) {
      post({
        type: 'ERROR',
        error: e instanceof Error ? e.message : String(e),
        code: 'UNKNOWN',
      })
    }
  }
}

// ─── Message Handler ────────────────────────────────────────────────────────

self.addEventListener('message', (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data
  if (!msg || !msg.type) return

  if (msg.type === 'CANCEL') {
    cancelled = true
    return
  }

  if (msg.type === 'ANALYZE') {
    analyze(msg.payload, msg.sessionId)
  }
})

// Signal ready
post({ type: 'READY' })
