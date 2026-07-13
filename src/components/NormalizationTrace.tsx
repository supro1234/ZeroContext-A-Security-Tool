import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Layers, ChevronRight } from 'lucide-react'
import type { NormalizationLayer, HomoglyphMatch } from '../types/threat'

interface NormalizationTraceProps {
  layers: NormalizationLayer[]
  homoglyphs: HomoglyphMatch[]
}

const TECHNIQUE_LABELS: Record<string, string> = {
  base64:    'Base64 Decode',
  url:       'URL Decode',
  hex:       'Hex Decode',
  nfkc:      'Unicode NFKC',
  homoglyph: 'Homoglyph',
  raw:       'Raw Input',
}

const TECHNIQUE_COLORS: Record<string, string> = {
  base64:    '#a78bfa',
  url:       '#60a5fa',
  hex:       '#34d399',
  nfkc:      '#f472b6',
  homoglyph: '#facc15',
  raw:       '#94a3b8',
}

export const NormalizationTrace: React.FC<NormalizationTraceProps> = ({ layers, homoglyphs }) => {
  const changedLayers = layers.filter((l) => l.changed)

  return (
    <div className="glass fade-in-up fade-in-up-delay-1" style={{ padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
        <Layers size={16} color="var(--accent)" />
        <span style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>
          Normalization Trace
        </span>
        <span className="glass-sm" style={{
          marginLeft: 'auto',
          padding: '2px 8px',
          fontSize: '0.7rem',
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-muted)',
        }}>
          {layers.length} layer{layers.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Layer pipeline */}
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 6, marginBottom: changedLayers.length > 0 ? 14 : 0 }}>
        {layers.map((layer, i) => {
          const color = TECHNIQUE_COLORS[layer.technique] ?? '#94a3b8'
          return (
            <React.Fragment key={i}>
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.05 }}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  padding: '6px 10px',
                  background: `${color}15`,
                  border: `1px solid ${color}40`,
                  borderRadius: 8,
                  minWidth: 80,
                }}
              >
                <span style={{ fontSize: '0.65rem', color, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {TECHNIQUE_LABELS[layer.technique] ?? layer.technique}
                </span>
                <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginTop: 2, fontFamily: 'var(--font-mono)' }}>
                  L{layer.depth}
                </span>
                <span style={{ fontSize: '0.65rem', marginTop: 2 }}>
                  {layer.changed ? '✓ changed' : '– same'}
                </span>
              </motion.div>
              {i < layers.length - 1 && (
                <ChevronRight size={12} color="var(--text-muted)" />
              )}
            </React.Fragment>
          )
        })}
      </div>

      {/* Changed layers detail */}
      <AnimatePresence>
        {changedLayers.map((layer, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06 }}
            style={{
              marginBottom: 8,
              padding: '8px 12px',
              background: 'rgba(0,0,0,0.2)',
              border: '1px solid var(--border)',
              borderRadius: 8,
            }}
          >
            <div style={{ fontSize: '0.68rem', color: TECHNIQUE_COLORS[layer.technique] ?? '#94a3b8', fontWeight: 600, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Layer {layer.depth} — {TECHNIQUE_LABELS[layer.technique]}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div>
                <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase' }}>Input</div>
                {/* SECURITY: snippets are escaped in normalizer via .slice() on sanitized strings */}
                <code style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', display: 'block' }}>
                  {layer.inputSnippet || '(empty)'}
                </code>
              </div>
              <div>
                <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase' }}>Output</div>
                <code style={{ fontSize: '0.7rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', display: 'block' }}>
                  {layer.outputSnippet || '(empty)'}
                </code>
              </div>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>

      {/* Homoglyphs */}
      {homoglyphs.length > 0 && (
        <div style={{ marginTop: 10, padding: '10px 12px', background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)', borderRadius: 8 }}>
          <div style={{ fontSize: '0.7rem', color: '#eab308', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            ⚠ {homoglyphs.length} Homoglyph{homoglyphs.length !== 1 ? 's' : ''} Detected
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {homoglyphs.slice(0, 20).map((h, i) => (
              <span key={i} style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                padding: '3px 8px',
                background: 'rgba(234,179,8,0.1)',
                border: '1px solid rgba(234,179,8,0.3)',
                borderRadius: 4,
                fontSize: '0.72rem',
                fontFamily: 'var(--font-mono)',
                color: '#eab308',
              }}>
                {/* SECURITY: original and replacement are single chars from our controlled map */}
                {h.original} → {h.replacement}
                <span style={{ color: 'var(--text-muted)', fontSize: '0.65rem' }}>
                  ({h.script})
                </span>
              </span>
            ))}
            {homoglyphs.length > 20 && (
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', alignSelf: 'center' }}>
                +{homoglyphs.length - 20} more
              </span>
            )}
          </div>
        </div>
      )}

      {changedLayers.length === 0 && homoglyphs.length === 0 && (
        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', textAlign: 'center', padding: '8px 0' }}>
          No encoding layers detected — input appears as plain text
        </div>
      )}
    </div>
  )
}
