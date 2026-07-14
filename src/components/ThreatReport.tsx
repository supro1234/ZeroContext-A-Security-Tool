import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, Layers, Eye, ChevronDown, ChevronRight, Database } from 'lucide-react'
import type { IncidentReport, ThreatMatch, HiddenRun, DataContradiction } from '../types/threat'
import { SeverityBadge } from './SeverityBadge'

interface ThreatReportProps {
  report: IncidentReport
}

const CATEGORY_COLORS: Record<string, string> = {
  XSS:                '#f43f5e',
  SQL_INJECTION:      '#f97316',
  PROMPT_INJECTION:   '#a78bfa',
  OBFUSCATION:        '#fb923c',
  HOMOGLYPH:          '#facc15',
  COMMAND_INJECTION:  '#ef4444',
  PATH_TRAVERSAL:     '#f97316',
  PROTOTYPE_POLLUTION:'#c084fc',
  REDOS:              '#f87171',
  ENCODING_ABUSE:     '#60a5fa',
  HIDDEN_TEXT:        '#ef4444',
  DATA_CONTRADICTION: '#eab308',
  UNKNOWN:            '#94a3b8',
}

const HIDDEN_REASON_LABELS: Record<string, string> = {
  vanish:      'w:vanish (explicitly hidden)',
  webHidden:   'w:webHidden (hidden in web view)',
  whiteColor:  'White/near-white text colour',
  nearZeroSize:'Near-zero font size (≤1pt)',
  doubleHide:  'Double-hide (highlight == font colour)',
}

// ─── Threat Table Row ─────────────────────────────────────────────────────────

const ThreatTableRow: React.FC<{ threat: ThreatMatch; index: number }> = ({ threat, index }) => {
  const [expanded, setExpanded] = useState(false)
  const catColor = CATEGORY_COLORS[threat.category] ?? '#94a3b8'
  const confidencePct = Math.round(threat.confidence * 100)

  const confidenceColor =
    threat.confidence >= 0.8 ? 'var(--critical)' :
    threat.confidence >= 0.5 ? 'var(--high)' :
    threat.confidence >= 0.3 ? 'var(--medium)' : 'var(--text-muted)'

  return (
    <>
      <motion.tr
        initial={{ opacity: 0, x: -8 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: index * 0.04, duration: 0.25 }}
        onClick={() => setExpanded((e) => !e)}
        style={{
          cursor: 'pointer',
          borderLeft: `3px solid ${catColor}`,
          background: expanded ? 'rgba(99,102,241,0.05)' : 'transparent',
          transition: 'background 0.15s',
        }}
        onMouseEnter={(e) => {
          if (!expanded) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.03)'
        }}
        onMouseLeave={(e) => {
          if (!expanded) (e.currentTarget as HTMLElement).style.background = 'transparent'
        }}
      >
        {/* Location */}
        <td style={{ padding: '8px 10px', fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
          {threat.location ?? (threat.layer > 0 ? `Layer ${threat.layer}` : 'Raw')}
          {' '}
          {(expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />)}
        </td>

        {/* Category */}
        <td style={{ padding: '8px 6px' }}>
          <span style={{
            display: 'inline-block',
            padding: '2px 7px',
            borderRadius: 4,
            fontSize: '0.65rem',
            fontWeight: 600,
            color: catColor,
            background: `${catColor}18`,
            border: `1px solid ${catColor}30`,
            whiteSpace: 'nowrap',
          }}>
            {threat.category.replace(/_/g, ' ')}
          </span>
        </td>

        {/* Confidence */}
        <td style={{ padding: '8px 6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{
              width: 36, height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, overflow: 'hidden',
            }}>
              <div style={{
                width: `${confidencePct}%`, height: '100%',
                background: confidenceColor, borderRadius: 2,
                transition: 'width 0.4s ease',
              }} />
            </div>
            <span style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: confidenceColor }}>
              {confidencePct}%
            </span>
          </div>
        </td>

        {/* Excerpt */}
        <td style={{ padding: '8px 6px', maxWidth: 200 }}>
          <code style={{
            fontSize: '0.7rem',
            color: '#fca5a5',
            fontFamily: 'var(--font-mono)',
            display: 'block',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}>
            {/* SECURITY: matchedText is escaped in ruleMatcher via escapeAndTruncate() */}
            {threat.matchedText}
          </code>
        </td>

        {/* Reason / Rule Name */}
        <td style={{ padding: '8px 6px' }}>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
            {threat.reason ?? threat.ruleName}
          </span>
          {' '}
          <SeverityBadge severity={threat.severity} size="sm" />
        </td>
      </motion.tr>

      {/* Expanded detail row */}
      {expanded && (
        <tr>
          <td colSpan={5} style={{ padding: 0 }}>
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              style={{
                padding: '10px 16px 14px 16px',
                background: 'rgba(0,0,0,0.25)',
                borderBottom: `1px solid ${catColor}30`,
              }}
            >
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                    Matched Text
                  </div>
                  <code style={{
                    display: 'block', padding: '6px 10px',
                    background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
                    borderRadius: 6, fontSize: '0.75rem', color: '#fca5a5',
                    fontFamily: 'var(--font-mono)', wordBreak: 'break-all',
                  }}>
                    {threat.matchedText}
                  </code>
                </div>
                {threat.context && (
                  <div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                      Context
                    </div>
                    {/* SECURITY: context is escaped in ruleMatcher via escapeAndTruncate() */}
                    <code style={{
                      display: 'block', padding: '6px 10px',
                      background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border)',
                      borderRadius: 6, fontSize: '0.72rem', color: 'var(--text-secondary)',
                      fontFamily: 'var(--font-mono)', wordBreak: 'break-all',
                    }}>
                      {threat.context}
                    </code>
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', gap: 14, marginTop: 8, fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                <span>Rule: <code style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)' }}>{threat.ruleId}</code></span>
                <span>Offset: <code style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)' }}>{threat.offset}</code></span>
                {threat.layer > 0 && (
                  <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                    <Layers size={10} /> Layer {threat.layer}
                  </span>
                )}
              </div>
            </motion.div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Hidden Text Table ────────────────────────────────────────────────────────

const HiddenTextSection: React.FC<{ runs: HiddenRun[] }> = ({ runs }) => {
  if (runs.length === 0) return null
  return (
    <div style={{
      marginTop: 16,
      padding: '12px 14px',
      background: 'rgba(239,68,68,0.06)',
      border: '1px solid rgba(239,68,68,0.25)',
      borderRadius: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
        <Eye size={14} color="#ef4444" />
        <span style={{ fontWeight: 600, fontSize: '0.8rem', color: '#ef4444' }}>
          Hidden Text Findings ({runs.length}) — AUTO HIGH
        </span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.72rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(239,68,68,0.2)' }}>
              {['Offset', 'Reason', 'Text Preview', 'Details'].map((h) => (
                <th key={h} style={{ padding: '4px 8px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', fontSize: '0.65rem' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {runs.map((run, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(239,68,68,0.08)' }}>
                <td style={{ padding: '5px 8px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {run.offset}
                </td>
                <td style={{ padding: '5px 8px', color: '#fca5a5' }}>
                  {HIDDEN_REASON_LABELS[run.reason] ?? run.reason}
                </td>
                <td style={{ padding: '5px 8px', maxWidth: 180 }}>
                  <code style={{ fontFamily: 'var(--font-mono)', color: '#fca5a5', wordBreak: 'break-all' }}>
                    {run.text.slice(0, 80)}{run.text.length > 80 ? '…' : ''}
                  </code>
                </td>
                <td style={{ padding: '5px 8px', color: 'var(--text-muted)' }}>
                  {run.colorHex && <span>color=#{run.colorHex} </span>}
                  {run.sizePt !== undefined && <span>size={run.sizePt}pt</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Data Contradiction Section ───────────────────────────────────────────────

const DataContradictionSection: React.FC<{ contradictions: DataContradiction[] }> = ({ contradictions }) => {
  if (contradictions.length === 0) return null
  return (
    <div style={{
      marginTop: 12,
      padding: '12px 14px',
      background: 'rgba(234,179,8,0.06)',
      border: '1px solid rgba(234,179,8,0.25)',
      borderRadius: 10,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
        <Database size={14} color="#eab308" />
        <span style={{ fontWeight: 600, fontSize: '0.8rem', color: '#eab308' }}>
          Data Contradictions ({contradictions.length}) — HIGH WEIGHT SIGNAL
        </span>
      </div>
      {contradictions.map((c, i) => (
        <div key={i} style={{
          marginBottom: 8, padding: '8px 10px',
          background: 'rgba(234,179,8,0.04)', border: '1px solid rgba(234,179,8,0.15)', borderRadius: 6,
        }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>
            <span style={{ color: '#eab308', fontWeight: 600 }}>Table says:</span>{' '}
            <code style={{ fontFamily: 'var(--font-mono)', color: '#eab308' }}>{c.tableValue}</code>
            {' '}→{' '}
            <span style={{ color: '#f97316', fontWeight: 600 }}>Text claims:</span>{' '}
            <code style={{ fontFamily: 'var(--font-mono)', color: '#f97316' }}>{c.claimedValue}</code>
            <span style={{ marginLeft: 8, color: 'var(--text-muted)', fontSize: '0.65rem' }}>
              confidence: {Math.round(c.confidence * 100)}%
            </span>
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>
            "{c.claim.slice(0, 200)}"
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Main ThreatReport ────────────────────────────────────────────────────────

export const ThreatReport: React.FC<ThreatReportProps> = ({ report }) => {
  const threatsByCategory = report.threats.reduce((acc, t) => {
    if (!acc[t.category]) acc[t.category] = []
    acc[t.category].push(t)
    return acc
  }, {} as Record<string, ThreatMatch[]>)

  const hasDocumentFindings =
    (report.hiddenRuns?.length ?? 0) > 0 ||
    (report.dataContradictions?.length ?? 0) > 0

  return (
    <div className="glass fade-in-up" style={{ padding: 24 }}>
      {/* Summary header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <AlertTriangle size={18} color="var(--accent)" />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.95rem' }}>
            Analysis Report
          </span>
          {report.sourceFileName && (
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
              padding: '2px 6px', background: 'var(--glass-bg)', border: '1px solid var(--border)', borderRadius: 4 }}>
              {report.sourceFileName}
            </span>
          )}
        </div>
        <SeverityBadge severity={report.severity} size="md" pulse={report.severity === 'CRITICAL' || report.severity === 'HIGH'} />
      </div>

      {/* Stats row */}
      <div className="mobile-stats-2col" style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 10,
        marginBottom: 20,
      }}>
        {[
          { label: 'Threats',      value: report.threats.length,                                color: report.threats.length > 0 ? 'var(--critical)' : 'var(--safe)' },
          { label: 'Categories',   value: Object.keys(threatsByCategory).length,                color: 'var(--accent)' },
          { label: 'Encode Layers', value: report.normalizationTrace.filter(l => l.changed).length, color: 'var(--medium)' },
          { label: 'Hidden Runs',  value: report.hiddenRuns?.length ?? 0,                      color: (report.hiddenRuns?.length ?? 0) > 0 ? 'var(--critical)' : 'var(--text-muted)' },
        ].map((stat) => (
          <div key={stat.label} className="glass-sm" style={{ padding: '12px 14px', textAlign: 'center' }}>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color: stat.color, fontFamily: 'var(--font-mono)', lineHeight: 1 }}>
              {stat.value}
            </div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {stat.label}
            </div>
          </div>
        ))}
      </div>

      {/* Meta */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap', fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
        <span>ID: <span style={{ color: 'var(--text-accent)' }}>{report.id.slice(0, 8)}…</span></span>
        <span>Engine: <span style={{ color: report.engineMode === 'hybrid' ? 'var(--safe)' : 'var(--accent)' }}>{report.engineMode.toUpperCase()}</span></span>
        <span>Rules: <span style={{ color: 'var(--text-accent)' }}>v{report.rulesVersion}</span></span>
        <span>Time: <span style={{ color: 'var(--text-accent)' }}>{report.processingTimeMs}ms</span></span>
        <span>Input: <span style={{ color: 'var(--text-accent)' }}>{report.inputLength} chars</span></span>
      </div>

      {/* No threats */}
      {report.threats.length === 0 && !hasDocumentFindings && (
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          style={{ textAlign: 'center', padding: '32px 16px', color: 'var(--safe)' }}
        >
          <div style={{ fontSize: '3rem', marginBottom: 8 }}>✓</div>
          <div style={{ fontWeight: 600, fontSize: '1rem', marginBottom: 4 }}>No Threats Detected</div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            {report.normalizationTrace.length > 1
              ? `Analyzed ${report.normalizationTrace.length} encoding layers`
              : 'Input appears clean across all rule categories'}
          </div>
        </motion.div>
      )}

      {/* ── Threat Table ─────────────────────────────────────────────── */}
      {report.threats.length > 0 && (
        <div style={{ overflowX: 'auto', marginBottom: 16 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-strong)' }}>
                {['Location', 'Category', 'Confidence', 'Excerpt', 'Reason / Rule'].map((h) => (
                  <th key={h} style={{
                    padding: '6px 10px',
                    textAlign: 'left',
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    whiteSpace: 'nowrap',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              <AnimatePresence>
                {report.threats.map((threat, i) => (
                  <ThreatTableRow key={`${threat.ruleId}-${i}`} threat={threat} index={i} />
                ))}
              </AnimatePresence>
            </tbody>
          </table>
        </div>
      )}

      {/* ── Document-specific findings ────────────────────────────── */}
      {report.hiddenRuns && report.hiddenRuns.length > 0 && (
        <HiddenTextSection runs={report.hiddenRuns} />
      )}
      {report.dataContradictions && report.dataContradictions.length > 0 && (
        <DataContradictionSection contradictions={report.dataContradictions} />
      )}

      {/* AI Analysis */}
      {report.aiAnalysis && (
        <div style={{
          marginTop: 16, padding: 14,
          background: 'rgba(99,102,241,0.06)', border: '1px solid rgba(99,102,241,0.2)', borderRadius: 10,
        }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            🤖 AI Deep Analysis ({report.aiAnalysis.modelUsed})
          </div>
          <div className="mobile-ai-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div className="glass-sm" style={{ padding: '8px 12px' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Prompt Injection</div>
              <div style={{
                fontSize: '1.2rem', fontWeight: 700, fontFamily: 'var(--font-mono)',
                color: report.aiAnalysis.promptInjectionScore > 0.7 ? 'var(--critical)' :
                       report.aiAnalysis.promptInjectionScore > 0.4 ? 'var(--high)' : 'var(--safe)',
              }}>
                {(report.aiAnalysis.promptInjectionScore * 100).toFixed(0)}%
              </div>
            </div>
            <div className="glass-sm" style={{ padding: '8px 12px' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Obfuscation</div>
              <div style={{
                fontSize: '1.2rem', fontWeight: 700, fontFamily: 'var(--font-mono)',
                color: report.aiAnalysis.obfuscationScore > 0.7 ? 'var(--critical)' :
                       report.aiAnalysis.obfuscationScore > 0.4 ? 'var(--high)' : 'var(--safe)',
              }}>
                {(report.aiAnalysis.obfuscationScore * 100).toFixed(0)}%
              </div>
            </div>
          </div>
          {/* SECURITY: threatSummary is sanitized on backend before returning */}
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
            {report.aiAnalysis.threatSummary}
          </p>
        </div>
      )}
    </div>
  )
}
