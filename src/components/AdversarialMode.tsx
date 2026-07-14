/**
 * AdversarialMode.tsx
 *
 * Adversarial Mode — takes the current payload and generates obfuscation permutations,
 * then runs each one through the client-side detection engine.
 *
 * Techniques applied:
 *   1. Double URL-encoding       %3Cscript%3E → %253Cscript%253E
 *   2. Base64 wrapping           eval(atob("..."))
 *   3. Homoglyph substitution    uses CONFUSABLE_MAP entries
 *   4. Zero-width char insertion  \u200B between every char
 *   5. HTML entity encoding      < → &lt; (and decimal &#60;)
 *   6. Hex encoding              each char → \xNN
 *   7. Unicode escape            each char → \uNNNN
 *
 * Each permuted payload is scored by re-running normalizePayload + matchAllLayers
 * (same engine as the main worker — fully offline, no fetch).
 *
 * The results table shows: Technique | Permuted Snippet | Detected? | Threats | Severity
 * Rows where detection EVADED are highlighted red (SOC interest = which variants bypass rules).
 */

import React, { useState, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Zap, X, ChevronDown, ChevronRight, Shield, AlertTriangle, CheckCircle2 } from 'lucide-react'
import type { IncidentReport, ThreatMatch } from '../types/threat'
import { normalizePayload, getAllLayers } from '../engine/normalizer'
import { matchAllLayers, highestSeverity } from '../engine/ruleMatcher'

interface AdversarialModeProps {
  payload: string
  report: IncidentReport
}

// ─── Permutation functions ────────────────────────────────────────────────────

/**
 * Double URL-encode: encode once, then encode the % signs again
 */
function doubleUrlEncode(s: string): string {
  return encodeURIComponent(s).replace(/%/g, '%25')
}

/**
 * Wrap in base64: window.atob will decode — engines must base64-decode to detect
 */
function base64Wrap(s: string): string {
  try {
    return `eval(atob("${btoa(s)}"))`
  } catch {
    return `eval(atob("${btoa(unescape(encodeURIComponent(s)))}"))`
  }
}

/**
 * Substitute Latin characters with Cyrillic/Greek confusables where possible
 */
const LATIN_TO_CONFUSABLE: Record<string, string> = {
  a: '\u0430', e: '\u0435', o: '\u043e', p: '\u0440', c: '\u0441',
  x: '\u0445', y: '\u0443', i: '\u0456',
  A: '\u0410', B: '\u0412', E: '\u0415', K: '\u041a', M: '\u041c',
  H: '\u041d', O: '\u041e', P: '\u0420', C: '\u0421', T: '\u0422', X: '\u0425',
}
function homoglyphSwap(s: string): string {
  return s.replace(/[aeio pcxy ABCEHKMOPRST]/g, (c) => LATIN_TO_CONFUSABLE[c] ?? c)
}

/**
 * Insert zero-width spaces between every character
 */
function zeroWidthInsert(s: string): string {
  return s.split('').join('\u200B')
}

/**
 * HTML entity encode every character (decimal form)
 */
function htmlEntityEncode(s: string): string {
  return s.split('').map((c) => `&#${c.charCodeAt(0)};`).join('')
}

/**
 * Hex-encode every character: \xNN
 */
function hexEncode(s: string): string {
  return s.split('').map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('')
}

/**
 * Unicode escape every character: \uNNNN
 */
function unicodeEscape(s: string): string {
  return s.split('').map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')
}

const PERMUTATIONS: Array<{
  id: string
  label: string
  description: string
  transform: (s: string) => string
  color: string
}> = [
  { id: 'double-url',  label: 'Double URL-encode',    description: '% chars re-encoded as %25 — bypasses single-decode filters', transform: doubleUrlEncode, color: '#f97316' },
  { id: 'base64',      label: 'Base64 wrapping',       description: 'eval(atob("...")) wrapper — requires base64 decode step',      transform: base64Wrap,      color: '#10b981' },
  { id: 'homoglyph',   label: 'Homoglyph substitution',description: 'Cyrillic/Greek lookalikes replace Latin chars',               transform: homoglyphSwap,   color: '#c084fc' },
  { id: 'zero-width',  label: 'Zero-width insertion',  description: 'U+200B between every character — defeats naive string match',  transform: zeroWidthInsert, color: '#38bdf8' },
  { id: 'html-entity', label: 'HTML entity encoding',  description: '&#NN; decimal form — relies on HTML parser to decode',        transform: htmlEntityEncode, color: '#fbbf24' },
  { id: 'hex',         label: 'Hex encoding',          description: '\\xNN for each char — common in JS obfuscation',              transform: hexEncode,       color: '#fb923c' },
  { id: 'unicode',     label: 'Unicode escape',         description: '\\uNNNN for each char — evades literal string scanners',      transform: unicodeEscape,   color: '#818cf8' },
]

// ─── Severity colours ─────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308',
  LOW: '#3b82f6', INFO: '#64748b', SAFE: '#10b981',
}

// ─── Result type ──────────────────────────────────────────────────────────────

interface PermResult {
  id: string
  label: string
  description: string
  color: string
  permuted: string
  threats: ThreatMatch[]
  severity: string
  detected: boolean
  evaded: boolean       // had threats in original but evades here
  processingMs: number
}

// ─── Row Component ────────────────────────────────────────────────────────────

const PermRow: React.FC<{ result: PermResult; originalHadThreats: boolean; index: number }> = ({
  result, originalHadThreats, index,
}) => {
  const [expanded, setExpanded] = useState(false)
  const evaded = originalHadThreats && !result.detected

  return (
    <>
      <motion.tr
        initial={{ opacity: 0, x: -6 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: index * 0.06 }}
        onClick={() => setExpanded((e) => !e)}
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${result.color}`,
          background: evaded ? 'rgba(239,68,68,0.06)' : result.detected ? 'rgba(16,185,129,0.04)' : 'transparent',
          transition: 'background 0.15s',
        }}
      >
        {/* Technique */}
        <td style={{ padding: '8px 10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {expanded ? <ChevronDown size={10} color="var(--accent)" /> : <ChevronRight size={10} color="var(--text-muted)" />}
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: result.color }}>{result.label}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{result.description}</div>
            </div>
          </div>
        </td>

        {/* Permuted snippet */}
        <td style={{ padding: '8px 6px', maxWidth: 180 }}>
          <code style={{
            fontSize: '0.67rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)',
            display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {result.permuted.slice(0, 60)}{result.permuted.length > 60 ? '…' : ''}
          </code>
        </td>

        {/* Detected */}
        <td style={{ padding: '8px 6px' }}>
          {result.detected ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.72rem', color: '#10b981' }}>
              <CheckCircle2 size={12} /> Detected
            </span>
          ) : (
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.72rem', color: evaded ? '#ef4444' : 'var(--text-muted)' }}>
              {evaded ? <AlertTriangle size={12} /> : <Shield size={12} />}
              {evaded ? '🚨 EVADED' : 'Clean'}
            </span>
          )}
        </td>

        {/* Threats */}
        <td style={{ padding: '8px 6px', fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
          color: result.threats.length > 0 ? SEV_COLOR[result.severity] : 'var(--text-muted)' }}>
          {result.threats.length} findings
        </td>

        {/* Severity */}
        <td style={{ padding: '8px 6px' }}>
          <span style={{
            display: 'inline-block', padding: '2px 7px', borderRadius: 4,
            fontSize: '0.65rem', fontWeight: 700,
            color: SEV_COLOR[result.severity] ?? '#94a3b8',
            background: `${SEV_COLOR[result.severity] ?? '#94a3b8'}15`,
            border: `1px solid ${SEV_COLOR[result.severity] ?? '#94a3b8'}30`,
          }}>
            {result.severity}
          </span>
        </td>
      </motion.tr>

      {/* Expanded detail */}
      {expanded && (
        <tr>
          <td colSpan={5} style={{ padding: 0 }}>
            <div style={{ padding: '10px 16px', background: 'rgba(0,0,0,0.2)' }}>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
                Full Permuted Payload
              </div>
              <code style={{
                display: 'block', padding: '8px 12px',
                background: 'rgba(0,0,0,0.25)', border: '1px solid var(--border)',
                borderRadius: 6, fontSize: '0.72rem', color: 'var(--text-secondary)',
                fontFamily: 'var(--font-mono)', wordBreak: 'break-all',
                maxHeight: 120, overflowY: 'auto',
              }}>
                {result.permuted}
              </code>
              {evaded && (
                <div style={{
                  marginTop: 8, padding: '6px 10px',
                  background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: 6,
                  fontSize: '0.7rem', color: '#ef4444',
                }}>
                  ⚠ This technique evaded detection — consider updating rules to cover <strong>{result.label}</strong> encoding.
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export const AdversarialMode: React.FC<AdversarialModeProps> = ({ payload, report }) => {
  const [running, setRunning]     = useState(false)
  const [results, setResults]     = useState<PermResult[]>([])
  const [collapsed, setCollapsed] = useState(false)
  const [done, setDone]           = useState(false)
  const abortRef = useRef(false)

  const originalHadThreats = report.threats.length > 0

  const runAdversarial = useCallback(async () => {
    if (running) return
    setRunning(true)
    setDone(false)
    setResults([])
    abortRef.current = false

    const out: PermResult[] = []

    for (const perm of PERMUTATIONS) {
      if (abortRef.current) break

      const start = performance.now()
      const permuted = perm.transform(payload)

      let threats: ThreatMatch[] = []
      try {
        const norm = normalizePayload(permuted)
        const layers = getAllLayers(norm)
        threats = matchAllLayers(layers)
      } catch {
        // Engine error for this permutation — treat as no detection
      }

      const severity = highestSeverity(threats)
      const ms = Math.round(performance.now() - start)

      out.push({
        id: perm.id,
        label: perm.label,
        description: perm.description,
        color: perm.color,
        permuted,
        threats,
        severity,
        detected: threats.length > 0,
        evaded: originalHadThreats && threats.length === 0,
        processingMs: ms,
      })

      // Stream results one by one (feels alive)
      setResults([...out])

      // Yield to event loop between permutations
      await new Promise((r) => setTimeout(r, 0))
    }

    setRunning(false)
    setDone(true)
  }, [payload, originalHadThreats])

  const stop = () => { abortRef.current = true; setRunning(false) }

  const evadedCount = results.filter((r) => r.evaded).length
  const detectedCount = results.filter((r) => r.detected).length

  return (
    <div className="glass fade-in-up" style={{ padding: 20 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
        <div style={{
          width: 28, height: 28, borderRadius: 8,
          background: 'rgba(249,115,22,0.12)', border: '1px solid rgba(249,115,22,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Zap size={13} color="#f97316" />
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
            Adversarial Mode
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
            Tests {PERMUTATIONS.length} obfuscation permutations — reveals which variants evade detection
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {done && (
            <span style={{ display: 'flex', gap: 6 }}>
              {evadedCount > 0 && (
                <span style={{ fontSize: '0.7rem', color: '#ef4444', fontFamily: 'var(--font-mono)',
                  background: 'rgba(239,68,68,0.1)', padding: '2px 8px', borderRadius: 4 }}>
                  🚨 {evadedCount} evaded
                </span>
              )}
              <span style={{ fontSize: '0.7rem', color: '#10b981', fontFamily: 'var(--font-mono)',
                background: 'rgba(16,185,129,0.1)', padding: '2px 8px', borderRadius: 4 }}>
                ✓ {detectedCount} detected
              </span>
            </span>
          )}
          {results.length > 0 && (
            <button onClick={() => setCollapsed((c) => !c)} className="btn-ghost" style={{ padding: '4px 8px' }}>
              {collapsed ? <ChevronRight size={13} /> : <ChevronDown size={13} />}
            </button>
          )}
        </div>
      </div>

      {/* Run / Stop button */}
      <div style={{ display: 'flex', gap: 8, marginBottom: results.length > 0 ? 14 : 0 }}>
        {running ? (
          <button
            onClick={stop}
            className="btn-ghost"
            style={{ color: '#ef4444', borderColor: 'rgba(239,68,68,0.3)', fontSize: '0.78rem' }}
          >
            <X size={13} /> Stop
          </button>
        ) : (
          <button
            onClick={runAdversarial}
            className="btn-primary"
            disabled={!payload.trim()}
            style={{ fontSize: '0.78rem', padding: '8px 16px' }}
          >
            <Zap size={14} />
            {done ? 'Re-run Adversarial Scan' : 'Run Adversarial Scan'}
          </button>
        )}

        {running && (
          <motion.span
            animate={{ opacity: [0.5, 1, 0.5] }}
            transition={{ duration: 1.2, repeat: Infinity }}
            style={{ fontSize: '0.75rem', color: '#f97316', fontFamily: 'var(--font-mono)', alignSelf: 'center' }}
          >
            Running permutations… ({results.length}/{PERMUTATIONS.length})
          </motion.span>
        )}
      </div>

      {/* Results table */}
      <AnimatePresence>
        {results.length > 0 && !collapsed && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22 }}
            style={{ overflowX: 'auto', overflow: 'hidden' }}
          >
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 600 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-strong)' }}>
                  {['Technique', 'Permuted Snippet', 'Detected?', 'Threats', 'Severity'].map((h) => (
                    <th key={h} style={{
                      padding: '6px 10px', textAlign: 'left', fontSize: '0.62rem',
                      fontWeight: 700, color: 'var(--text-muted)',
                      textTransform: 'uppercase', letterSpacing: '0.06em',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {results.map((result, i) => (
                    <PermRow
                      key={result.id}
                      result={result}
                      originalHadThreats={originalHadThreats}
                      index={i}
                    />
                  ))}
                </AnimatePresence>
              </tbody>
            </table>

            {/* Summary bar */}
            {done && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                style={{
                  marginTop: 12, padding: '8px 12px',
                  background: evadedCount > 0 ? 'rgba(239,68,68,0.06)' : 'rgba(16,185,129,0.06)',
                  border: `1px solid ${evadedCount > 0 ? 'rgba(239,68,68,0.25)' : 'rgba(16,185,129,0.25)'}`,
                  borderRadius: 8, fontSize: '0.75rem',
                  color: evadedCount > 0 ? '#ef4444' : '#10b981',
                }}
              >
                {evadedCount > 0
                  ? `🚨 ${evadedCount} of ${PERMUTATIONS.length} obfuscation techniques evaded detection — review rule coverage for these encoding patterns.`
                  : `✓ All ${PERMUTATIONS.length} obfuscation permutations were detected. Rule coverage is strong.`
                }
              </motion.div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
