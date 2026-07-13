/**
 * useWorker.ts
 * React hook for managing the analysis Web Worker lifecycle.
 * Handles worker creation, message routing, and cancellation.
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import type { WorkerMessage, WorkerRequest } from '../types/worker'
import type { IncidentReport, AnalysisProgress } from '../types/threat'

export interface UseWorkerReturn {
  analyze: (payload: string) => string  // returns sessionId
  cancel: () => void
  progress: AnalysisProgress | null
  isReady: boolean
  isAnalyzing: boolean
}

export function useWorker(
  onResult: (report: IncidentReport) => void,
  onError: (error: string) => void
): UseWorkerReturn {
  const workerRef = useRef<Worker | null>(null)
  const [isReady, setIsReady] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [progress, setProgress] = useState<AnalysisProgress | null>(null)

  useEffect(() => {
    // Instantiate worker
    const worker = new Worker(
      new URL('../workers/analysisWorker.ts', import.meta.url),
      { type: 'module' }
    )

    worker.addEventListener('message', (event: MessageEvent<WorkerMessage>) => {
      const msg = event.data
      switch (msg.type) {
        case 'READY':
          setIsReady(true)
          break
        case 'PROGRESS':
          setProgress(msg.data)
          setIsAnalyzing(msg.data.status !== 'complete' && msg.data.status !== 'error')
          break
        case 'RESULT':
          setIsAnalyzing(false)
          setProgress(null)
          onResult(msg.data)
          break
        case 'ERROR':
          setIsAnalyzing(false)
          setProgress(null)
          onError(msg.error)
          break
      }
    })

    worker.addEventListener('error', (e) => {
      setIsAnalyzing(false)
      onError(`Worker error: ${e.message}`)
    })

    workerRef.current = worker

    return () => {
      worker.terminate()
      workerRef.current = null
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const analyze = useCallback((payload: string): string => {
    const sessionId = crypto.randomUUID()
    if (!workerRef.current) return sessionId
    setIsAnalyzing(true)
    setProgress({ status: 'normalizing', stage: 'Starting analysis…', percent: 0 })
    const msg: WorkerRequest = { type: 'ANALYZE', payload, sessionId }
    workerRef.current.postMessage(msg)
    return sessionId
  }, [])

  const cancel = useCallback(() => {
    if (!workerRef.current) return
    const msg: WorkerRequest = { type: 'CANCEL' }
    workerRef.current.postMessage(msg)
    setIsAnalyzing(false)
    setProgress(null)
  }, [])

  return { analyze, cancel, progress, isReady, isAnalyzing }
}
