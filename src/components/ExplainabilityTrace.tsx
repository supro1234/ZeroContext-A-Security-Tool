/**
 * ExplainabilityTrace.tsx
 *
 * Per-finding "Explainability Trace" — shows the exact step-by-step chain:
 *   Raw Input → [Layer N: technique decoded] → [Matched rule XYZ] → VERDICT
 *
 * Reads NormalizationLayer[] already present on every IncidentReport.
 * Clicking a threat expands its full chain with colour-coded technique badges.
 */

import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, ChevronRight, Layers, ArrowRight, AlertTriangle, Cpu } from 'lucide-react'
import type { IncidentReport, ThreatMatch, NormalizationLayer } from '../types/threat'

interface ExplainabilityTraceProps {
  report: IncidentReport
}

// ─── Technique badge colours ──────────────────────────────────────────────────

const TECHNIQUE_STYLE: Record<string, { bg: string; color: string; label: string }> = {
  raw:       { bg: 'rgba(99,102,241,0.12)',  color: '#818cf8', label: 'Raw Input'      },
  url:       { bg: 'rgba(249,115,22,0.12)',  color: '#fb923c', label: 'URL Decode'     },
  hex:       { bg: 'rgba(234,179,8,0.12)',   color: '#fbbf24', label: 'Hex Decode'     },
  base64:    { bg: 'rgba(16,185,129,0.12)',  color: '#34d399', label: 'Base64 Decode'  },
  nfkc:      { bg: 'rgba(14,165,233,0.12)',  color: '#38bdf8', label: 'Unicode NFKC'   },
  homoglyph: { bg: 'rgba(167,139,250,0.12)', color: '#c084fc', label: 'Homoglyph Norm' },
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#64748b', SAFE: '#10b981',
}

// ─── Single-threat trace chain ────────────────────────────────────────────────

interface ThreatChainProps {
  threat: ThreatMatch
  layers: NormalizationLayer[]
  index: number
}

const ThreatChain: React.FC<ThreatChainProps> = ({ threat, layers, index }) => {
  const [open, setOpen] = useState(false)
  const sColor = SEVERITY_COLOR[threat.severity] ?? '#94a3b8'

  // Build the chain: show layers up to and including the one where the match was found
  const relevantLayers = layers.filter((l) => l.depth <= threat.layer || threat.layer === 0)
  const displayLayers = relevantLayers.length > 0 ? relevantLayers : layers.slice(0, 1)

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.2 }}
      style={{
        border: `1px solid rgba(99,102,241,0.15)`,
        borderLeft: `3px solid ${sColor}`,
        borderRadius: 10,
        overflow: 'hidden',
        marginBottom: 8,
      }}
    >
      {/* Header row */}
      <button
        onClick={() => setOpen((o) => !o)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '9px 12px',
          background: 'var(--glass-bg)',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        {open ? <ChevronDown size={13} color="var(--accent)" /> : <ChevronRight size={13} color="var(--text-muted)" />}

        <span style={{
          fontSize: '0.7rem', fontWeight: 700, color: sColor,
          textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap',
        }}>
          {threat.severity}
        </span>

        <span style={{ fontSize: '0.75rem', color: 'var(--text-primary)', fontWeight: 600, flex: 1, minWidth: 0 }}>
          {threat.ruleName}
        </span>

        <span style={{
          fontSize: '0.65rem', color: 'var(--accent)',
          fontFamily: 'var(--font-mono)', padding: '2px 6px',
          background: 'rgba(99,102,241,0.1)', borderRadius: 4, whiteSpace: 'nowrap',
        }}>
          {threat.category.replace(/_/g, ' ')}
        </span>
      </button>

      {/* Expanded chain */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22 }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{ padding: '12px 14px', background: 'rgba(0,0,0,0.2)' }}>

              {/* Chain visualization */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>

                {/* Each normalization layer */}
                {displayLayers.map((layer, li) => {
                  const ts = TECHNIQUE_STYLE[layer.technique] ?? TECHNIQUE_STYLE.raw
                  return (
                    <div key={li}>
                      {/* Layer node */}
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                        {/* Line + dot */}
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 16, flexShrink: 0 }}>
                          <div style={{
                            width: 10, height: 10, borderRadius: '50%',
                            background: ts.color, marginTop: 3, flexShrink: 0,
                          }} />
                          {(li < displayLayers.length - 1 || true) && (
                            <div style={{ width: 2, flex: 1, minHeight: 20, background: 'rgba(255,255,255,0.06)', marginTop: 2 }} />
                          )}
                        </div>

                        {/* Layer content */}
                        <div style={{ flex: 1, paddingBottom: 10, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4, flexWrap: 'wrap' }}>
                            <span style={{
                              display: 'inline-block',
                              padding: '2px 7px',
                              borderRadius: 4,
                              fontSize: '0.62rem',
                              fontWeight: 700,
                              color: ts.color,
                              background: ts.bg,
                              border: `1px solid ${ts.color}30`,
                            }}>
                              {layer.depth === 0 ? 'LAYER 0' : `LAYER ${layer.depth}`} — {ts.label}
                            </span>
                            {layer.changed && (
                              <span style={{ fontSize: '0.6rem', color: '#10b981' }}>✓ decoded</span>
                            )}
                            {!layer.changed && (
                              <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>no change</span>
                            )}
                          </div>

                          {layer.changed && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                              <code style={{
                                fontSize: '0.67rem', padding: '3px 6px',
                                background: 'rgba(255,255,255,0.04)',
                                border: '1px solid rgba(255,255,255,0.06)',
                                borderRadius: 4,
                                color: 'var(--text-muted)',
                                fontFamily: 'var(--font-mono)',
                                maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                              }}>
                                {layer.inputSnippet}
                              </code>
                              <ArrowRight size={10} color="var(--text-muted)" />
                              <code style={{
                                fontSize: '0.67rem', padding: '3px 6px',
                                background: 'rgba(99,102,241,0.08)',
                                border: '1px solid rgba(99,102,241,0.2)',
                                borderRadius: 4,
                                color: '#a5b4fc',
                                fontFamily: 'var(--font-mono)',
                                maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                              }}>
                                {layer.outputSnippet}
                              </code>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Arrow between layers */}
                      {li < displayLayers.length - 1 && (
                        <div style={{ display: 'flex', paddingLeft: 7, marginBottom: 0 }}>
                          <ArrowRight size={10} color="rgba(255,255,255,0.15)" style={{ transform: 'rotate(90deg)' }} />
                        </div>
                      )}
                    </div>
                  )
                })}

                {/* Rule match node */}
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 16, flexShrink: 0 }}>
                    <div style={{
                      width: 10, height: 10, borderRadius: 2,
                      background: sColor, marginTop: 3, flexShrink: 0,
                    }} />
                    <div style={{ width: 2, flex: 1, minHeight: 20, background: 'rgba(255,255,255,0.06)', marginTop: 2 }} />
                  </div>
                  <div style={{ flex: 1, paddingBottom: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <span style={{
                        display: 'inline-block', padding: '2px 7px', borderRadius: 4,
                        fontSize: '0.62rem', fontWeight: 700, color: sColor,
                        background: `${sColor}15`, border: `1px solid ${sColor}40`,
                      }}>
                        RULE MATCHED — {threat.ruleId}
                      </span>
                      <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                        confidence: {Math.round(threat.confidence * 100)}%
                      </span>
                    </div>
                    <code style={{
                      display: 'block', fontSize: '0.67rem', padding: '4px 8px',
                      background: `${sColor}10`, border: `1px solid ${sColor}30`,
                      borderRadius: 4, color: '#fca5a5',
                      fontFamily: 'var(--font-mono)', wordBreak: 'break-all',
                    }}>
                      {threat.matchedText}
                    </code>
                  </div>
                </div>

                {/* Verdict node */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{
                    width: 16, height: 16, borderRadius: '50%',
                    background: sColor, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexShrink: 0,
                  }}>
                    <AlertTriangle size={8} color="#fff" />
                  </div>
                  <div style={{
                    flex: 1, padding: '6px 10px',
                    background: `${sColor}10`, border: `1px solid ${sColor}30`,
                    borderRadius: 6,
                  }}>
                    <span style={{ fontSize: '0.72rem', fontWeight: 700, color: sColor }}>
                      VERDICT: {threat.severity}
                    </span>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginLeft: 8 }}>
                      {threat.reason ?? threat.ruleName}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export const ExplainabilityTrace: React.FC<ExplainabilityTraceProps> = ({ report }) => {
  const [collapsed, setCollapsed] = useState(false)

  if (report.threats.length === 0) return null

  return (
    <div className="glass fade-in-up" style={{ padding: 20 }}>
      {/* Header */}
      <button
        onClick={() => setCollapsed((c) => !c)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8,
          width: '100%', background: 'none', border: 'none', cursor: 'pointer',
          padding: 0, marginBottom: collapsed ? 0 : 16,
        }}
      >
        <div style={{
          width: 28, height: 28, borderRadius: 8,
          background: 'rgba(99,102,241,0.12)', border: '1px solid rgba(99,102,241,0.25)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Layers size={13} color="var(--accent)" />
        </div>
        <div style={{ flex: 1, textAlign: 'left' }}>
          <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
            Explainability Trace
          </div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
            {report.threats.length} finding{report.threats.length !== 1 ? 's' : ''} — click each to expand decode chain
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{
            fontSize: '0.65rem', color: 'var(--accent)', fontFamily: 'var(--font-mono)',
            background: 'rgba(99,102,241,0.1)', padding: '2px 7px', borderRadius: 4,
          }}>
            <Cpu size={9} style={{ marginRight: 3, verticalAlign: 'middle' }} />
            {report.normalizationTrace.filter((l) => l.changed).length} decode layers
          </span>
          {collapsed
            ? <ChevronRight size={14} color="var(--text-muted)" />
            : <ChevronDown size={14} color="var(--text-muted)" />
          }
        </div>
      </button>

      <AnimatePresence>
        {!collapsed && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22 }}
            style={{ overflow: 'hidden' }}
          >
            {/* Legend */}
            <div style={{
              display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12,
              padding: '8px 10px', background: 'rgba(0,0,0,0.15)',
              border: '1px solid var(--border)', borderRadius: 8,
            }}>
              {Object.entries(TECHNIQUE_STYLE).map(([key, ts]) => (
                <span key={key} style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                  fontSize: '0.62rem', color: ts.color,
                }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: ts.color, display: 'inline-block' }} />
                  {ts.label}
                </span>
              ))}
            </div>

            {/* Threat chains */}
            {report.threats.map((threat, i) => (
              <ThreatChain
                key={`${threat.ruleId}-${i}`}
                threat={threat}
                layers={report.normalizationTrace}
                index={i}
              />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
