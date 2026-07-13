import React, { useState, useCallback, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Moon, Sun, Wifi, Loader, Shield, Terminal, GitBranch, Cpu, Flag, RotateCcw, ChevronLeft } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useTheme } from '../hooks/useTheme'
import { useWorker } from '../hooks/useWorker'
import { useBackendStatus, callAIAnalysis } from '../hooks/useBackendStatus'
import { useMediaQuery } from '../hooks/useMediaQuery'
import { AnalysisInput } from '../components/AnalysisInput'
import { ThreatReport } from '../components/ThreatReport'
import { NormalizationTrace } from '../components/NormalizationTrace'
import { LiveFeed } from '../components/LiveFeed'
import { ForensicExport } from '../components/ForensicExport'
import type { IncidentReport } from '../types/threat'

// ── Staged post-analysis messages shown before revealing results ────────────
const REVEAL_STAGES = [
  { label: 'Correlating threat signatures…',  percent: 72 },
  { label: 'Cross-referencing rule database…', percent: 84 },
  { label: 'Building incident report…',        percent: 93 },
  { label: 'Finalising analysis…',             percent: 99 },
]
const STAGE_DURATION_MS = 480  // ms per stage → ~1.9 s total

export const AnalyzePage: React.FC = () => {
  const navigate  = useNavigate()
  const { theme, toggle: toggleTheme } = useTheme()
  const { status: backendStatus } = useBackendStatus()
  const isMobile  = useMediaQuery('(max-width: 640px)')    // ← React-based, never purged

  const [isCTFMode,      setIsCTFMode]      = useState(false)
  const [reports,        setReports]        = useState<IncidentReport[]>([])
  const [currentReport,  setCurrentReport]  = useState<IncidentReport | null>(null)
  const [error,          setError]          = useState<string | null>(null)

  // ── Realistic loading state ─────────────────────────────────────────────
  const [isRevealing,    setIsRevealing]    = useState(false)
  const [revealStage,    setRevealStage]    = useState('')
  const [revealPercent,  setRevealPercent]  = useState(0)
  const revealTimers = useRef<ReturnType<typeof setTimeout>[]>([])

  const clearRevealTimers = () => {
    revealTimers.current.forEach(clearTimeout)
    revealTimers.current = []
  }

  const handleResult = useCallback(async (report: IncidentReport) => {
    let finalReport = report

    // If backend is online, enrich with AI analysis
    if (backendStatus === 'online' && report.normalizationTrace.length > 0) {
      const finalText = report.normalizationTrace[report.normalizationTrace.length - 1].outputSnippet
      const aiResult  = await callAIAnalysis(finalText, report.inputHash)
      if (aiResult) {
        finalReport = {
          ...report,
          aiAnalysis:  aiResult,
          engineMode:  'hybrid',
          severity:    aiResult.promptInjectionScore > 0.85 && report.severity === 'SAFE'
            ? 'HIGH'
            : report.severity,
        }
      }
    }

    // ── Staged reveal animation ──────────────────────────────────────────
    clearRevealTimers()
    setIsRevealing(true)

    REVEAL_STAGES.forEach((stage, i) => {
      const t = setTimeout(() => {
        setRevealStage(stage.label)
        setRevealPercent(stage.percent)
      }, i * STAGE_DURATION_MS)
      revealTimers.current.push(t)
    })

    const doneTimer = setTimeout(() => {
      setIsRevealing(false)
      setRevealStage('')
      setRevealPercent(0)
      setCurrentReport(finalReport)
      setReports((prev) => [...prev, finalReport])
      setError(null)
    }, REVEAL_STAGES.length * STAGE_DURATION_MS + 200)
    revealTimers.current.push(doneTimer)

  }, [backendStatus])

  const handleError = useCallback((err: string) => {
    clearRevealTimers()
    setIsRevealing(false)
    setError(err)
    setCurrentReport(null)
  }, [])

  const { analyze, cancel, progress, isReady, isAnalyzing } = useWorker(handleResult, handleError)

  const newSession = useCallback(() => {
    clearRevealTimers()
    setIsRevealing(false)
    setReports([])
    setCurrentReport(null)
    setError(null)
  }, [])

  // Cleanup on unmount
  useEffect(() => () => clearRevealTimers(), [])

  // Combined "busy" state: worker running OR staged reveal
  const isBusy = isAnalyzing || isRevealing

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* ── Navbar ──────────────────────────────────────────────── */}
      <header style={{
        position: 'sticky',
        top: 0,
        zIndex: 40,
        borderBottom: '1px solid var(--border)',
        background: 'var(--glass-bg)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
      }}>
        <div style={{
          maxWidth: 1400,
          margin: '0 auto',
          padding: '0 16px',
          height: 56,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          overflow: 'hidden',
        }}>
          {/* ── Left: logo ─────────────────────────────────────── */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 0, overflow: 'hidden' }}>
            <button
              onClick={() => navigate('/')}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                padding: '6px', color: 'var(--text-muted)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0, minWidth: 32, minHeight: 44,
              }}
              title="Back to home"
            >
              <ChevronLeft size={16} />
            </button>

            <motion.div
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
              style={{ flexShrink: 0 }}
            >
              <Shield size={20} color="var(--accent)" />
            </motion.div>

            <span style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text-primary)', letterSpacing: '-0.02em', whiteSpace: 'nowrap' }}>
              Zero<span style={{ color: 'var(--accent)' }}>Context</span>
            </span>

            {/* BETA badge — hidden on phones via JS (not CSS classes) */}
            {!isMobile && (
              <span style={{
                fontSize: '0.65rem', color: 'var(--text-muted)',
                fontFamily: 'var(--font-mono)', background: 'var(--glass-bg)',
                border: '1px solid var(--border)', borderRadius: 4,
                padding: '2px 6px', flexShrink: 0, whiteSpace: 'nowrap',
              }}>
                v1.0 BETA
              </span>
            )}

            {/* New Session button */}
            {currentReport !== null && (
              <motion.button
                initial={{ opacity: 0, scale: 0.85 }}
                animate={{ opacity: 1, scale: 1 }}
                onClick={newSession}
                style={{
                  display: 'flex', alignItems: 'center', gap: isMobile ? 0 : 5,
                  padding: isMobile ? '6px' : '5px 10px',
                  fontSize: '0.72rem', fontFamily: 'var(--font-mono)',
                  background: 'rgba(99,102,241,0.1)',
                  border: '1px solid rgba(99,102,241,0.3)',
                  borderRadius: 6, color: 'var(--text-accent)',
                  cursor: 'pointer', whiteSpace: 'nowrap',
                  flexShrink: 0, minHeight: 32,
                }}
                title="Clear session and start fresh"
              >
                <RotateCcw size={11} />
                {!isMobile && ' New Session'}
              </motion.button>
            )}
          </div>

          {/* ── Right: status + controls ────────────────────────── */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            {/* Worker / reveal status — icon always visible, text hidden on mobile */}
            <motion.div
              style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.72rem' }}
              animate={{ opacity: isReady ? 1 : 0.5 }}
            >
              {isBusy ? (
                <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}>
                  <Loader size={14} color="var(--accent)" />
                </motion.div>
              ) : (
                <Cpu size={14} color={isReady ? 'var(--safe)' : 'var(--text-muted)'} />
              )}
              {!isMobile && (
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                  {isAnalyzing ? 'Analyzing…' : isRevealing ? 'Processing…' : isReady ? 'Engine Ready' : 'Loading…'}
                </span>
              )}
            </motion.div>

            {/* AI Online — icon only on mobile */}
            {backendStatus === 'online' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.72rem' }}>
                <Wifi size={14} color="var(--safe)" />
                {!isMobile && (
                  <span style={{ color: 'var(--safe)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>AI Online</span>
                )}
              </div>
            )}

            {/* CTF toggle — icon only on mobile */}
            <button
              onClick={() => setIsCTFMode((c) => !c)}
              className="btn-ghost"
              style={{
                padding: '5px 8px', fontSize: '0.72rem', minHeight: 36,
                color: isCTFMode ? '#f97316' : 'var(--text-muted)',
                borderColor: isCTFMode ? '#f97316' : 'var(--border)',
                display: 'flex', alignItems: 'center', gap: 4,
              }}
              title="Toggle Red Team / CTF Mode"
            >
              <Flag size={12} />
              {!isMobile && 'CTF'}
            </button>

            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              className="btn-ghost"
              style={{ padding: '6px 8px', minHeight: 36 }}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            >
              {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
            </button>
          </div>
        </div>
      </header>

      {/* ── Main Content ─────────────────────────────────────────── */}
      <main style={{ flex: 1, maxWidth: 1400, margin: '0 auto', padding: isMobile ? '20px 14px' : '32px 24px', width: '100%' }}>

        {/* Hero */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          style={{ textAlign: 'center', marginBottom: isMobile ? 24 : 40 }}
        >
          <h1 style={{
            fontSize: 'clamp(1.8rem, 4vw, 3rem)',
            fontWeight: 800, letterSpacing: '-0.03em',
            background: 'linear-gradient(135deg, var(--text-primary) 0%, var(--accent) 60%, #c084fc 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            backgroundClip: 'text', marginBottom: 12,
          }}>
            Threat Detection Engine
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', maxWidth: 560, margin: '0 auto' }}>
            Client-side malicious code analysis with AI-powered deep inspection.
            {' '}<span style={{ color: 'var(--accent)' }}>Zero server-side processing</span> of untrusted input.
          </p>

          {/* Feature badges */}
          <div style={{
            display: 'flex', justifyContent: isMobile ? 'flex-start' : 'center',
            gap: 8, marginTop: 16, flexWrap: isMobile ? 'nowrap' : 'wrap',
            overflowX: isMobile ? 'auto' : 'visible',
            paddingBottom: isMobile ? 4 : 0,
          }}>
            {[
              { icon: <Terminal size={11} />, label: 'Web Worker Isolated' },
              { icon: <Shield size={11} />,   label: 'Sandboxed Analysis' },
              { icon: <GitBranch size={11} />, label: '5-Layer Normalization' },
              { icon: <Cpu size={11} />,       label: 'Client-Side Engine' },
            ].map((b) => (
              <span key={b.label} style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '4px 10px', background: 'var(--glass-bg)',
                border: '1px solid var(--border)', borderRadius: 20,
                fontSize: '0.7rem', color: 'var(--text-muted)',
                whiteSpace: 'nowrap', flexShrink: 0,
              }}>
                {b.icon} {b.label}
              </span>
            ))}
          </div>
        </motion.div>

        {/* Two-column layout — stacks to 1 col on mobile */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr',
          gap: 20,
          alignItems: 'start',
        }}>
          {/* Left column — Input + Progress */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <AnalysisInput
              onAnalyze={analyze}
              onCancel={cancel}
              isAnalyzing={isBusy}
              isWorkerReady={isReady}
              isCTFMode={isCTFMode}
            />

            {/* Worker live feed */}
            <AnimatePresence>
              {isAnalyzing && progress && (
                <LiveFeed progress={progress} isAnalyzing={isAnalyzing} />
              )}
            </AnimatePresence>

            {/* ── Staged post-analysis reveal overlay ─────────── */}
            <AnimatePresence>
              {isRevealing && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="glass-sm"
                  style={{ padding: '14px 18px' }}
                >
                  {/* Scan line */}
                  <div className="scan-line-active" />

                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                    <motion.span
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                      style={{ fontSize: '1rem', display: 'inline-block' }}
                    >
                      🔬
                    </motion.span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {revealStage || 'Processing…'}
                    </span>
                    <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--accent)' }}>
                      {revealPercent}%
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div style={{ height: 4, background: 'rgba(99,102,241,0.1)', borderRadius: 2, overflow: 'hidden' }}>
                    <motion.div
                      className="progress-bar"
                      animate={{ width: `${revealPercent}%` }}
                      transition={{ duration: 0.45, ease: 'easeOut' }}
                      style={{ height: '100%', borderRadius: 2 }}
                    />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Error state */}
            <AnimatePresence>
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  className="glass-sm"
                  style={{
                    padding: '12px 16px', border: '1px solid var(--critical)',
                    background: 'rgba(239,68,68,0.08)', borderRadius: 10,
                    color: 'var(--critical)', fontSize: '0.82rem', fontFamily: 'var(--font-mono)',
                  }}
                >
                  ⚠ {/* SECURITY: error is our own internal string from worker */}
                  {error}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Normalization trace */}
            <AnimatePresence>
              {currentReport && currentReport.normalizationTrace.length > 0 && (
                <NormalizationTrace
                  layers={currentReport.normalizationTrace}
                  homoglyphs={currentReport.homoglyphs}
                />
              )}
            </AnimatePresence>

            {/* Forensic export */}
            <ForensicExport reports={reports} />
          </div>

          {/* Right column — Report */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <AnimatePresence mode="wait">
              {currentReport ? (
                <motion.div
                  key={currentReport.id}
                  initial={{ opacity: 0, x: isMobile ? 0 : 20, y: isMobile ? 16 : 0 }}
                  animate={{ opacity: 1, x: 0, y: 0 }}
                  exit={{ opacity: 0, x: isMobile ? 0 : -20 }}
                  transition={{ duration: 0.3 }}
                >
                  <ThreatReport report={currentReport} />
                </motion.div>
              ) : isRevealing ? (
                /* ── "Report incoming" placeholder during reveal ── */
                <motion.div
                  key="revealing"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="glass"
                  style={{
                    padding: 48, textAlign: 'center', minHeight: 320,
                    display: 'flex', flexDirection: 'column',
                    alignItems: 'center', justifyContent: 'center', gap: 14,
                  }}
                >
                  <motion.div
                    animate={{ scale: [1, 1.12, 1], opacity: [0.6, 1, 0.6] }}
                    transition={{ duration: 1.2, repeat: Infinity }}
                  >
                    <Shield size={48} color="var(--accent)" />
                  </motion.div>
                  <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontWeight: 500 }}>
                    Generating threat report…
                  </div>
                  {/* Mini progress dots */}
                  <div style={{ display: 'flex', gap: 6 }}>
                    {[0, 1, 2].map((i) => (
                      <motion.div
                        key={i}
                        animate={{ opacity: [0.2, 1, 0.2], y: [0, -4, 0] }}
                        transition={{ duration: 0.8, repeat: Infinity, delay: i * 0.2 }}
                        style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)' }}
                      />
                    ))}
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                    {revealStage || 'Processing…'}
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="glass"
                  style={{
                    padding: 48, textAlign: 'center', minHeight: 320,
                    display: 'flex', flexDirection: 'column',
                    alignItems: 'center', justifyContent: 'center', gap: 12,
                  }}
                >
                  <motion.div
                    animate={{ scale: [1, 1.05, 1], opacity: [0.4, 0.7, 0.4] }}
                    transition={{ duration: 3, repeat: Infinity }}
                  >
                    <Shield size={48} color="var(--border-strong)" />
                  </motion.div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                    Awaiting payload submission
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                    Results will appear here
                  </div>
                  <div className="terminal-cursor" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }} />
                </motion.div>
              )}
            </AnimatePresence>

            {/* Session history */}
            {reports.length > 1 && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="glass-sm"
                style={{ padding: 16 }}
              >
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Session History ({reports.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {[...reports].reverse().slice(0, 5).map((r, i) => (
                    <button
                      key={r.id}
                      onClick={() => setCurrentReport(r)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        padding: isMobile ? '10px' : '6px 10px',
                        background: currentReport?.id === r.id ? 'var(--glass-bg)' : 'transparent',
                        border: '1px solid ' + (currentReport?.id === r.id ? 'var(--border-strong)' : 'transparent'),
                        borderRadius: 6, cursor: 'pointer',
                        textAlign: 'left', width: '100%', transition: 'all 0.15s',
                      }}
                    >
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        #{reports.length - i}
                      </span>
                      <span style={{
                        width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                        background: r.severity === 'CRITICAL' ? 'var(--critical)' :
                          r.severity === 'HIGH' ? 'var(--high)' :
                          r.severity === 'MEDIUM' ? 'var(--medium)' :
                          r.severity === 'SAFE' ? 'var(--safe)' : 'var(--info)',
                      }} />
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', flex: 1, fontFamily: 'var(--font-mono)' }}>
                        {r.threats.length} threats · {r.severity}
                      </span>
                      <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        {r.processingTimeMs}ms
                      </span>
                    </button>
                  ))}
                </div>
              </motion.div>
            )}
          </div>
        </div>
      </main>

      {/* ── Footer ──────────────────────────────────────────────── */}
      <footer style={{
        borderTop: '1px solid var(--border)',
        padding: '14px 16px',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexWrap: 'wrap', gap: isMobile ? 8 : 16,
        fontSize: '0.7rem', color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
      }}>
        <span>ZeroContext v1.0</span>
        {!isMobile && <><span>·</span><span>All analysis runs in-browser</span><span>·</span><span>No untrusted data sent to servers</span><span>·</span></>}
        <span style={{ color: backendStatus === 'online' ? 'var(--safe)' : 'var(--text-muted)' }}>
          {backendStatus === 'online' ? '● AI Enhanced' : '○ Offline Mode'}
        </span>
      </footer>
    </div>
  )
}
