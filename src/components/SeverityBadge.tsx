import React from 'react'
import { motion } from 'framer-motion'
import type { Severity } from '../types/threat'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md' | 'lg'
  pulse?: boolean
}

const SEVERITY_CONFIG: Record<Severity, {
  label: string
  color: string
  bg: string
  glow: string
  icon: string
}> = {
  CRITICAL: { label: 'CRITICAL', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', glow: 'rgba(239,68,68,0.5)', icon: '⚠' },
  HIGH:     { label: 'HIGH',     color: '#f97316', bg: 'rgba(249,115,22,0.12)', glow: 'rgba(249,115,22,0.4)', icon: '▲' },
  MEDIUM:   { label: 'MEDIUM',   color: '#eab308', bg: 'rgba(234,179,8,0.12)',  glow: 'rgba(234,179,8,0.4)',  icon: '◆' },
  LOW:      { label: 'LOW',      color: '#22c55e', bg: 'rgba(34,197,94,0.12)',  glow: 'rgba(34,197,94,0.3)',  icon: '●' },
  INFO:     { label: 'INFO',     color: '#38bdf8', bg: 'rgba(56,189,248,0.12)', glow: 'rgba(56,189,248,0.3)', icon: 'ℹ' },
  SAFE:     { label: 'SAFE',     color: '#10b981', bg: 'rgba(16,185,129,0.12)', glow: 'rgba(16,185,129,0.3)', icon: '✓' },
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  pulse = false,
}) => {
  const cfg = SEVERITY_CONFIG[severity]

  const sizeStyles = {
    sm: { fontSize: '0.65rem', padding: '2px 8px', gap: 4 },
    md: { fontSize: '0.75rem', padding: '4px 12px', gap: 6 },
    lg: { fontSize: '0.9rem',  padding: '6px 18px', gap: 8 },
  }

  return (
    <motion.span
      initial={{ scale: 0.8, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 300, damping: 20 }}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: sizeStyles[size].gap,
        padding: sizeStyles[size].padding,
        fontSize: sizeStyles[size].fontSize,
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        letterSpacing: '0.08em',
        color: cfg.color,
        background: cfg.bg,
        border: `1px solid ${cfg.color}`,
        borderRadius: 6,
        boxShadow: pulse ? `0 0 12px ${cfg.glow}` : 'none',
        transition: 'box-shadow 0.3s',
        whiteSpace: 'nowrap',
      }}
    >
      {pulse && (
        <motion.span
          animate={{ opacity: [1, 0.3, 1] }}
          transition={{ duration: 1.2, repeat: Infinity }}
          style={{ display: 'inline-block' }}
        >
          {cfg.icon}
        </motion.span>
      )}
      {!pulse && <span>{cfg.icon}</span>}
      {cfg.label}
    </motion.span>
  )
}
