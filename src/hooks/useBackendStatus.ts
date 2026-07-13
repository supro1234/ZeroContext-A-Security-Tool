/**
 * useBackendStatus.ts
 * Probes the Python AI backend and manages online/offline mode.
 *
 * Uses relative /api/* paths so it works in both:
 *  - Local dev (Vite proxy: /api/* → http://localhost:8000/*)
 *  - Vercel production (/api/* → serverless Python function)
 */

import { useState, useEffect, useCallback } from 'react'
import type { AIAnalysisResult } from '../types/threat'

export type BackendStatus = 'checking' | 'online' | 'offline'

// Relative path — works in dev (Vite proxy) and production (Vercel function)
const API_BASE = '/api'
const HEALTH_INTERVAL_MS = 30_000

export function useBackendStatus() {
  const [status, setStatus] = useState<BackendStatus>('checking')
  const [manualOverride, setManualOverride] = useState<'online' | 'offline' | null>(null)

  const probe = useCallback(async () => {
    if (manualOverride) return
    try {
      const resp = await fetch(`${API_BASE}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      })
      setStatus(resp.ok ? 'online' : 'offline')
    } catch {
      setStatus('offline')
    }
  }, [manualOverride])

  useEffect(() => {
    probe()
    const interval = setInterval(probe, HEALTH_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [probe])

  const effectiveStatus: BackendStatus = manualOverride ?? status

  const forceOnline = () => setManualOverride('online')
  const forceOffline = () => setManualOverride('offline')
  const resetOverride = () => setManualOverride(null)

  return { status: effectiveStatus, forceOnline, forceOffline, resetOverride }
}

/**
 * Calls the Python AI backend for deep analysis.
 * Returns null if backend is unreachable.
 */
export async function callAIAnalysis(
  normalizedText: string,
  inputHash: string,
): Promise<AIAnalysisResult | null> {
  try {
    const resp = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: normalizedText, hash: inputHash }),
      signal: AbortSignal.timeout(15000),
    })

    if (!resp.ok) return null

    const data = await resp.json()
    return data as AIAnalysisResult
  } catch {
    return null
  }
}
