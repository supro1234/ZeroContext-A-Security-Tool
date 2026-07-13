import React from 'react'
import { motion } from 'framer-motion'
import type { AnalysisProgress } from '../types/threat'

interface LiveFeedProps {
  progress: AnalysisProgress | null
  isAnalyzing: boolean
}

const STAGE_ICONS: Record<string, string> = {
  'Loading rules': '📋',
  'Normalizing': '🔄',
  'Detecting homoglyphs': '🔍',
  'Matching threat rules': '⚡',
  'Computing severity': '📊',
  'Generating report': '📄',
  'Analysis complete': '✅',
  'Starting': '🚀',
}

function getIcon(stage: string): string {
  for (const [key, icon] of Object.entries(STAGE_ICONS)) {
    if (stage.toLowerCase().includes(key.toLowerCase())) return icon
  }
  return '⟳'
}

export const LiveFeed: React.FC<LiveFeedProps> = ({ progress, isAnalyzing }) => {
  if (!isAnalyzing && !progress) return null

  const percent = progress?.percent ?? 0
  const stage = progress?.stage ?? 'Starting…'

  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      className="glass-sm"
      style={{ padding: '14px 18px', margin: '0' }}
    >
      {/* Scan line */}
      <div className="scan-line-active" />

      {/* Stage */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <motion.span
          animate={{ rotate: isAnalyzing ? 360 : 0 }}
          transition={{ duration: 1, repeat: isAnalyzing ? Infinity : 0, ease: 'linear' }}
          style={{ fontSize: '1rem', display: 'inline-block' }}
        >
          {getIcon(stage)}
        </motion.span>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.8rem',
          color: 'var(--text-secondary)',
        }}>
          {/* SECURITY: stage text is our own internal string, not user input */}
          {stage}
        </span>
        <span style={{
          marginLeft: 'auto',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.75rem',
          color: 'var(--accent)',
        }}>
          {percent}%
        </span>
      </div>

      {/* Progress bar */}
      <div style={{
        height: 4,
        background: 'rgba(99,102,241,0.1)',
        borderRadius: 2,
        overflow: 'hidden',
      }}>
        <motion.div
          className="progress-bar"
          initial={{ width: 0 }}
          animate={{ width: `${percent}%` }}
          transition={{ duration: 0.4, ease: 'easeOut' }}
          style={{ height: '100%', borderRadius: 2 }}
        />
      </div>
    </motion.div>
  )
}
