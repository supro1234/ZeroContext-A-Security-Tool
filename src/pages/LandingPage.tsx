import React, { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import { Shield, Zap, Lock, Eye, GitBranch, ChevronRight, Terminal, Globe } from 'lucide-react'

// ── Fake terminal lines ──────────────────────────────────────────────────────
const TERMINAL_LINES = [
  { delay: 0,    text: '$ zerocontext scan --payload "<?php eval($_GET[\'cmd\']); ?>"', type: 'cmd' },
  { delay: 900,  text: '[engine] Normalizing payload…', type: 'info' },
  { delay: 1600, text: '[engine] Layer 0: raw input (238 chars)', type: 'info' },
  { delay: 2200, text: '[engine] Layer 1: URL decode → no change', type: 'info' },
  { delay: 2800, text: '[engine] Layer 2: Hex decode → 1 substitution', type: 'info' },
  { delay: 3400, text: '[rule]   PHP-001 WEBSHELL_GENERIC  ██ CRITICAL (conf: 97%)', type: 'critical' },
  { delay: 4100, text: '[rule]   OBFS-001 Base64 blob decoded → eval() chain', type: 'high' },
  { delay: 4800, text: '[ai]     Prompt Injection Score: 0.04  |  Obfuscation: 0.89', type: 'info' },
  { delay: 5500, text: '════ SEVERITY: CRITICAL ════  1 file  2 threats  5ms', type: 'result' },
]

const lineColor: Record<string, string> = {
  cmd: '#818cf8',
  info: '#64748b',
  critical: '#ef4444',
  high: '#f97316',
  result: '#10b981',
}

// ── Feature cards ────────────────────────────────────────────────────────────
const FEATURES = [
  {
    icon: Lock,
    title: 'Zero Server Exposure',
    description: 'All regex matching runs inside a Web Worker. Your payloads never leave the browser.',
    color: '#6366f1',
  },
  {
    icon: Zap,
    title: '5-Layer Normalization',
    description: 'URL → Hex → Base64 → HTML-entity → Unicode NFKC decoding before any rule fires.',
    color: '#f97316',
  },
  {
    icon: Eye,
    title: 'Context-Aware Scoring',
    description: 'Prose detection, gap analysis, and multi-signal confidence prevent false positives.',
    color: '#10b981',
  },
  {
    icon: GitBranch,
    title: 'Forensic Export',
    description: 'Download structured DOCX/JSON incident reports with full normalization trace.',
    color: '#818cf8',
  },
]

// ── Particle grid (CSS-only, no canvas) ─────────────────────────────────────
function ParticleGrid() {
  return (
    <div
      aria-hidden
      style={{
        position: 'absolute',
        inset: 0,
        overflow: 'hidden',
        zIndex: 0,
        pointerEvents: 'none',
      }}
    >
      {/* Gradient radial glow */}
      <div style={{
        position: 'absolute',
        top: '30%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        width: 900,
        height: 900,
        background: 'radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%)',
        borderRadius: '50%',
      }} />
      {/* Dot grid via CSS background */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: 'radial-gradient(circle, rgba(99,102,241,0.18) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
        maskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, black 30%, transparent 100%)',
        WebkitMaskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, black 30%, transparent 100%)',
      }} />
      {/* Accent lines */}
      <div style={{
        position: 'absolute',
        inset: 0,
        backgroundImage: `
          linear-gradient(to right, rgba(99,102,241,0.06) 1px, transparent 1px),
          linear-gradient(to bottom, rgba(99,102,241,0.06) 1px, transparent 1px)
        `,
        backgroundSize: '80px 80px',
      }} />
    </div>
  )
}

// ── Terminal Demo ────────────────────────────────────────────────────────────
function TerminalDemo() {
  const [lines, setLines] = useState<typeof TERMINAL_LINES>([])
  const [cursor, setCursor] = useState(true)
  const ref = useRef<HTMLDivElement>(null)
  const reducedMotion = useReducedMotion()

  useEffect(() => {
    if (reducedMotion) {
      setLines(TERMINAL_LINES)
      return
    }
    const timers: ReturnType<typeof setTimeout>[] = []
    TERMINAL_LINES.forEach((line) => {
      timers.push(setTimeout(() => {
        setLines((prev) => [...prev, line])
      }, line.delay))
    })
    // Loop
    const reset = setTimeout(() => {
      setLines([])
    }, 8000)
    timers.push(reset)
    return () => timers.forEach(clearTimeout)
  }, [lines.length === 0, reducedMotion])

  useEffect(() => {
    const blink = setInterval(() => setCursor((c) => !c), 530)
    return () => clearInterval(blink)
  }, [])

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])

  return (
    <div style={{
      background: '#0d1117',
      border: '1px solid rgba(99,102,241,0.25)',
      borderRadius: 12,
      overflow: 'hidden',
      boxShadow: '0 0 60px rgba(99,102,241,0.12), 0 20px 60px rgba(0,0,0,0.5)',
      maxWidth: 620,
      width: '100%',
    }}>
      {/* Terminal header */}
      <div style={{
        padding: '10px 16px',
        borderBottom: '1px solid rgba(99,102,241,0.15)',
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        background: '#080b12',
      }}>
        {['#ef4444', '#f97316', '#22c55e'].map((c) => (
          <div key={c} style={{ width: 10, height: 10, borderRadius: '50%', background: c }} />
        ))}
        <div style={{
          flex: 1,
          textAlign: 'center',
          fontSize: '0.72rem',
          color: '#475569',
          fontFamily: 'var(--font-mono)',
        }}>
          zerocontext — threat-engine
        </div>
        <Terminal size={12} color="#475569" />
      </div>
      {/* Terminal body */}
      <div ref={ref} style={{
        padding: '16px',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.72rem',
        lineHeight: 1.7,
        height: 280,
        overflowY: 'auto',
        scrollbarWidth: 'none',
      }}>
        {lines.map((line, i) => (
          <motion.div
            key={`${i}-${line.text}`}
            initial={{ opacity: 0, x: -4 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.15 }}
            style={{ color: lineColor[line.type] ?? '#94a3b8', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
          >
            {line.text}
          </motion.div>
        ))}
        <span style={{ color: '#818cf8' }}>
          ${cursor ? '▋' : ' '}
        </span>
      </div>
    </div>
  )
}

// ── Main Landing Page ────────────────────────────────────────────────────────
export const LandingPage: React.FC = () => {
  const navigate = useNavigate()

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-base)',
      color: 'var(--text-primary)',
      fontFamily: 'var(--font-sans)',
      display: 'flex',
      flexDirection: 'column',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* ── Navbar ──────────────────────────────────────────────────────── */}
      <nav style={{
        position: 'sticky',
        top: 0,
        zIndex: 40,
        borderBottom: '1px solid var(--border)',
        background: 'rgba(8,11,18,0.8)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
      }}>
        <div style={{
          maxWidth: 1200,
          margin: '0 auto',
          padding: '0 24px',
          height: 56,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <motion.div animate={{ rotate: [0, 360] }} transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}>
              <Shield size={20} color="var(--accent)" />
            </motion.div>
            <span style={{ fontWeight: 700, fontSize: '1rem', letterSpacing: '-0.02em' }}>
              Zero<span style={{ color: 'var(--accent)' }}>Context</span>
            </span>
            <span style={{
              fontSize: '0.6rem',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
              background: 'rgba(99,102,241,0.1)',
              border: '1px solid rgba(99,102,241,0.25)',
              borderRadius: 4,
              padding: '2px 6px',
            }}>v1.0 BETA</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 5 }}
            >
              <Globe size={13} /> GitHub
            </a>
            <button
              onClick={() => navigate('/analyze')}
              style={{
                padding: '7px 16px',
                background: 'var(--accent)',
                color: '#fff',
                border: 'none',
                borderRadius: 8,
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
                fontFamily: 'var(--font-sans)',
              }}
            >
              Launch App
            </button>
          </div>
        </div>
      </nav>

      {/* ── Hero ────────────────────────────────────────────────────────── */}
      <section style={{
        position: 'relative',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: '96px 24px 80px',
        flex: '0 0 auto',
        minHeight: '80vh',
      }}>
        <ParticleGrid />

        <div style={{ position: 'relative', zIndex: 1, maxWidth: 820 }}>
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, y: -12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 7,
              padding: '5px 14px',
              background: 'rgba(99,102,241,0.12)',
              border: '1px solid rgba(99,102,241,0.3)',
              borderRadius: 99,
              fontSize: '0.72rem',
              color: 'var(--text-accent)',
              fontFamily: 'var(--font-mono)',
              marginBottom: 28,
            }}
          >
            <span style={{
              display: 'inline-block',
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: '#10b981',
              boxShadow: '0 0 6px #10b981',
            }} />
            Client-side · No data leaves your browser · Open Source
          </motion.div>

          {/* Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.1 }}
            style={{
              fontSize: 'clamp(2.4rem, 6vw, 4.2rem)',
              fontWeight: 800,
              lineHeight: 1.08,
              letterSpacing: '-0.04em',
              margin: '0 0 20px',
              color: '#f1f5f9',
            }}
          >
            Zero Trust.{' '}
            <span style={{
              background: 'linear-gradient(135deg, #6366f1 0%, #818cf8 50%, #a78bfa 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
            }}>
              Zero Context.
            </span>
            <br />Zero Compromise.
          </motion.h1>

          {/* Sub-headline */}
          <motion.p
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.2 }}
            style={{
              fontSize: 'clamp(1rem, 2.5vw, 1.2rem)',
              color: 'var(--text-secondary)',
              lineHeight: 1.65,
              maxWidth: 600,
              margin: '0 auto 40px',
            }}
          >
            Real-time, client-side payload analysis for XSS, SQL injection, prompt injection,
            and obfuscated malware — powered by a 5-layer normalization engine running entirely
            in your browser.
          </motion.p>

          {/* CTA buttons */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}
          >
            <motion.button
              onClick={() => navigate('/analyze')}
              whileHover={{ scale: 1.03, boxShadow: '0 0 30px rgba(99,102,241,0.5)' }}
              whileTap={{ scale: 0.97 }}
              style={{
                padding: '13px 28px',
                background: 'linear-gradient(135deg, #6366f1, #818cf8)',
                color: '#fff',
                border: 'none',
                borderRadius: 10,
                fontSize: '1rem',
                fontWeight: 700,
                cursor: 'pointer',
                fontFamily: 'var(--font-sans)',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                letterSpacing: '-0.01em',
              }}
            >
              Launch Threat Engine <ChevronRight size={16} />
            </motion.button>
            <motion.a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              style={{
                padding: '13px 28px',
                background: 'transparent',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-strong)',
                borderRadius: 10,
                fontSize: '1rem',
                fontWeight: 600,
                cursor: 'pointer',
                fontFamily: 'var(--font-sans)',
                textDecoration: 'none',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <GitBranch size={15} /> View Source
            </motion.a>
          </motion.div>

          {/* Stats row */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.55, duration: 0.5 }}
            style={{
              display: 'flex',
              gap: 32,
              justifyContent: 'center',
              marginTop: 52,
              flexWrap: 'wrap',
            }}
          >
            {[
              { value: '70+', label: 'Detection Rules' },
              { value: '5', label: 'Decode Layers' },
              { value: '<5ms', label: 'Analysis Time' },
              { value: '0', label: 'Server Requests' },
            ].map(({ value, label }) => (
              <div key={label} style={{ textAlign: 'center' }}>
                <div style={{
                  fontSize: '1.6rem',
                  fontWeight: 800,
                  color: 'var(--text-accent)',
                  letterSpacing: '-0.04em',
                  fontFamily: 'var(--font-mono)',
                }}>{value}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Terminal Demo ────────────────────────────────────────────────── */}
      <section style={{
        padding: '40px 24px 80px',
        display: 'flex',
        justifyContent: 'center',
        position: 'relative',
        zIndex: 1,
      }}>
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
        >
          <TerminalDemo />
        </motion.div>
      </section>

      {/* ── Features ────────────────────────────────────────────────────── */}
      <section style={{
        padding: '64px 24px 80px',
        maxWidth: 1100,
        margin: '0 auto',
        width: '100%',
        position: 'relative',
        zIndex: 1,
      }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          style={{ textAlign: 'center', marginBottom: 48 }}
        >
          <h2 style={{
            fontSize: 'clamp(1.5rem, 4vw, 2.2rem)',
            fontWeight: 800,
            letterSpacing: '-0.03em',
            margin: '0 0 12px',
          }}>
            Built for security professionals
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', margin: 0 }}>
            Every feature designed around the principle of zero implicit trust.
          </p>
        </motion.div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: 20,
        }}>
          {FEATURES.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08, duration: 0.45 }}
              whileHover={{ y: -4, boxShadow: `0 12px 40px rgba(0,0,0,0.3)` }}
              style={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                borderRadius: 14,
                padding: '28px 24px',
                cursor: 'default',
                transition: 'border-color 0.2s',
              }}
            >
              <div style={{
                width: 42,
                height: 42,
                borderRadius: 10,
                background: `${f.color}18`,
                border: `1px solid ${f.color}30`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: 16,
              }}>
                <f.icon size={20} color={f.color} />
              </div>
              <h3 style={{
                fontSize: '0.95rem',
                fontWeight: 700,
                margin: '0 0 8px',
                color: 'var(--text-primary)',
              }}>{f.title}</h3>
              <p style={{
                fontSize: '0.82rem',
                color: 'var(--text-secondary)',
                lineHeight: 1.6,
                margin: 0,
              }}>{f.description}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ── CTA Banner ──────────────────────────────────────────────────── */}
      <section style={{
        padding: '64px 24px',
        textAlign: 'center',
        position: 'relative',
        zIndex: 1,
      }}>
        <div style={{
          maxWidth: 600,
          margin: '0 auto',
          padding: '48px 40px',
          background: 'linear-gradient(135deg, rgba(99,102,241,0.12) 0%, rgba(139,92,246,0.08) 100%)',
          border: '1px solid rgba(99,102,241,0.25)',
          borderRadius: 20,
        }}>
          <motion.div
            initial={{ opacity: 0, scale: 0.96 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
          >
            <div style={{
              width: 56,
              height: 56,
              borderRadius: '50%',
              background: 'rgba(99,102,241,0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 20px',
            }}>
              <Shield size={26} color="var(--accent)" />
            </div>
            <h2 style={{
              fontSize: 'clamp(1.3rem, 4vw, 1.8rem)',
              fontWeight: 800,
              letterSpacing: '-0.03em',
              margin: '0 0 12px',
            }}>Ready to analyze a payload?</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 28, fontSize: '0.9rem' }}>
              Paste text, upload a file, or drop a suspicious payload. Results in under 5ms.
            </p>
            <motion.button
              onClick={() => navigate('/analyze')}
              whileHover={{ scale: 1.04, boxShadow: '0 0 40px rgba(99,102,241,0.45)' }}
              whileTap={{ scale: 0.97 }}
              style={{
                padding: '13px 32px',
                background: 'linear-gradient(135deg, #6366f1, #818cf8)',
                color: '#fff',
                border: 'none',
                borderRadius: 10,
                fontSize: '0.95rem',
                fontWeight: 700,
                cursor: 'pointer',
                fontFamily: 'var(--font-sans)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              Launch Threat Engine <ChevronRight size={15} />
            </motion.button>
          </motion.div>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <footer style={{
        borderTop: '1px solid var(--border)',
        padding: '24px',
        textAlign: 'center',
        color: 'var(--text-muted)',
        fontSize: '0.75rem',
        fontFamily: 'var(--font-mono)',
        zIndex: 1,
      }}>
        ZeroContext v1.0 · Client-side threat detection · No telemetry · No storage ·{' '}
        <a href="https://github.com" target="_blank" rel="noopener noreferrer"
          style={{ color: 'var(--text-accent)', textDecoration: 'none' }}>
          Open Source
        </a>
      </footer>
    </div>
  )
}
