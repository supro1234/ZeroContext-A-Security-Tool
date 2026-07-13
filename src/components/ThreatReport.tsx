import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, ChevronRight, AlertTriangle, Layers } from 'lucide-react'
import type { IncidentReport, ThreatMatch } from '../types/threat'
import { SeverityBadge } from './SeverityBadge'

interface ThreatReportProps {
  report: IncidentReport
}

const CATEGORY_COLORS: Record<string, string> = {
  XSS:               '#f43f5e',
  SQL_INJECTION:     '#f97316',
  PROMPT_INJECTION:  '#a78bfa',
  OBFUSCATION:       '#fb923c',
  HOMOGLYPH:         '#facc15',
  COMMAND_INJECTION: '#ef4444',
  PATH_TRAVERSAL:    '#f97316',
  PROTOTYPE_POLLUTION:'#c084fc',
  REDOS:             '#f87171',
  ENCODING_ABUSE:    '#60a5fa',
  UNKNOWN:           '#94a3b8',
}

const ThreatCard: React.FC<{ threat: ThreatMatch; index: number }> = ({ threat, index }) => {
  const [expanded, setExpanded] = useState(false)
  const catColor = CATEGORY_COLORS[threat.category] ?? '#94a3b8'

  return (
    <motion.div
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04, duration: 0.3 }}
      style={{
        background: 'rgba(0,0,0,0.2)',
        border: `1px solid ${catColor}30`,
        borderLeft: `3px solid ${catColor}`,
        borderRadius: 10,
        marginBottom: 8,
        overflow: 'hidden',
      }}
    >
      {/* Header row */}
      <button
        onClick={() => setExpanded((e) => !e)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          width: '100%',
          padding: '10px 14px',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        {expanded ? <ChevronDown size={14} color="var(--text-muted)" /> : <ChevronRight size={14} color="var(--text-muted)" />}

        <SeverityBadge severity={threat.severity} size="sm" />

        {/* SECURITY: rule name is from our own validated rules, not user input */}
        <span style={{ flex: 1, fontSize: '0.82rem', color: 'var(--text-primary)', fontWeight: 500 }}>
          {threat.ruleName}
        </span>

        <span className="tag" style={{ color: catColor, borderColor: catColor, background: `${catColor}18` }}>
          {threat.category.replace('_', ' ')}
        </span>

        {threat.layer > 0 && (
          <span style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            <Layers size={11} /> L{threat.layer}
          </span>
        )}
      </button>

      {/* Expanded detail */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ padding: '0 14px 12px 14px', overflow: 'hidden' }}
          >
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Matched Text
              </div>
              {/* SECURITY: matchedText is already escaped in ruleMatcher.ts via escapeAndTruncate() */}
              <code style={{
                display: 'block',
                padding: '6px 10px',
                background: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.2)',
                borderRadius: 6,
                fontSize: '0.78rem',
                color: '#fca5a5',
                fontFamily: 'var(--font-mono)',
                wordBreak: 'break-all',
                whiteSpace: 'pre-wrap',
              }}>
                {threat.matchedText}
              </code>
            </div>

            {threat.context && (
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Context
                </div>
                {/* SECURITY: context is already escaped in ruleMatcher.ts via escapeAndTruncate() */}
                <code style={{
                  display: 'block',
                  padding: '6px 10px',
                  background: 'rgba(0,0,0,0.2)',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  fontSize: '0.75rem',
                  color: 'var(--text-secondary)',
                  fontFamily: 'var(--font-mono)',
                  wordBreak: 'break-all',
                  whiteSpace: 'pre-wrap',
                }}>
                  {threat.context}
                </code>
              </div>
            )}

            <div style={{ display: 'flex', gap: 16, marginTop: 10, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              <span>Rule: <code style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)' }}>{threat.ruleId}</code></span>
              <span>Offset: <code style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)' }}>{threat.offset}</code></span>
              <span>Confidence: <code style={{ color: 'var(--text-accent)', fontFamily: 'var(--font-mono)' }}>{(threat.confidence * 100).toFixed(0)}%</code></span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

export const ThreatReport: React.FC<ThreatReportProps> = ({ report }) => {
  const threatsByCategory = report.threats.reduce((acc, t) => {
    if (!acc[t.category]) acc[t.category] = []
    acc[t.category].push(t)
    return acc
  }, {} as Record<string, ThreatMatch[]>)

  return (
    <div className="glass fade-in-up" style={{ padding: 24 }}>
      {/* Summary header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <AlertTriangle size={18} color="var(--accent)" />
          <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.95rem' }}>
            Analysis Report
          </span>
        </div>
        <SeverityBadge severity={report.severity} size="md" pulse={report.severity === 'CRITICAL' || report.severity === 'HIGH'} />
      </div>

      {/* Stats row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 10,
        marginBottom: 20,
      }}>
        {[
          { label: 'Threats',      value: report.threats.length,              color: report.threats.length > 0 ? 'var(--critical)' : 'var(--safe)' },
          { label: 'Categories',   value: Object.keys(threatsByCategory).length, color: 'var(--accent)' },
          { label: 'Encode Layers', value: report.normalizationTrace.filter(l => l.changed).length, color: 'var(--medium)' },
          { label: 'Homoglyphs',   value: report.homoglyphs.length,           color: 'var(--high)' },
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
      {report.threats.length === 0 && (
        <motion.div
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          style={{
            textAlign: 'center',
            padding: '32px 16px',
            color: 'var(--safe)',
          }}
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

      {/* Threat cards */}
      {report.threats.length > 0 && (
        <div>
          {report.threats.map((threat, i) => (
            <ThreatCard key={`${threat.ruleId}-${i}`} threat={threat} index={i} />
          ))}
        </div>
      )}

      {/* AI Analysis */}
      {report.aiAnalysis && (
        <div style={{
          marginTop: 16,
          padding: 14,
          background: 'rgba(99,102,241,0.06)',
          border: '1px solid rgba(99,102,241,0.2)',
          borderRadius: 10,
        }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            🤖 AI Deep Analysis ({report.aiAnalysis.modelUsed})
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
            <div className="glass-sm" style={{ padding: '8px 12px' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Prompt Injection</div>
              <div style={{
                fontSize: '1.2rem',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                color: report.aiAnalysis.promptInjectionScore > 0.7 ? 'var(--critical)' : report.aiAnalysis.promptInjectionScore > 0.4 ? 'var(--high)' : 'var(--safe)',
              }}>
                {(report.aiAnalysis.promptInjectionScore * 100).toFixed(0)}%
              </div>
            </div>
            <div className="glass-sm" style={{ padding: '8px 12px' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Obfuscation</div>
              <div style={{
                fontSize: '1.2rem',
                fontWeight: 700,
                fontFamily: 'var(--font-mono)',
                color: report.aiAnalysis.obfuscationScore > 0.7 ? 'var(--critical)' : report.aiAnalysis.obfuscationScore > 0.4 ? 'var(--high)' : 'var(--safe)',
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
