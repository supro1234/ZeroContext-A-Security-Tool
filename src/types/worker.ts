// Worker message protocol types

import type { AnalysisProgress, IncidentReport } from './threat'

export interface WorkerAnalyzeRequest {
  type: 'ANALYZE'
  payload: string
  sessionId: string
  rulesVersion?: string
}

export interface WorkerCancelRequest {
  type: 'CANCEL'
}

export type WorkerRequest = WorkerAnalyzeRequest | WorkerCancelRequest

export interface WorkerProgressMessage {
  type: 'PROGRESS'
  data: AnalysisProgress
}

export interface WorkerResultMessage {
  type: 'RESULT'
  data: IncidentReport
}

export interface WorkerErrorMessage {
  type: 'ERROR'
  error: string
  code: 'RULES_INVALID' | 'REDOS_DETECTED' | 'DEPTH_EXCEEDED' | 'UNKNOWN'
}

export interface WorkerReadyMessage {
  type: 'READY'
}

export type WorkerMessage =
  | WorkerProgressMessage
  | WorkerResultMessage
  | WorkerErrorMessage
  | WorkerReadyMessage
