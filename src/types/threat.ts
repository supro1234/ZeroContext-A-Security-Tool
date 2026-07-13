// ──────────────────────────────────────────────────────────────
// ZeroContext — Core Type Definitions
// ──────────────────────────────────────────────────────────────

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'SAFE'

export type ThreatCategory =
  | 'XSS'
  | 'SQL_INJECTION'
  | 'PROMPT_INJECTION'
  | 'OBFUSCATION'
  | 'HOMOGLYPH'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'PROTOTYPE_POLLUTION'
  | 'REDOS'
  | 'ENCODING_ABUSE'
  | 'UNKNOWN'

export interface ThreatMatch {
  ruleId: string
  ruleName: string
  category: ThreatCategory
  severity: Severity
  matchedText: string      // always escaped before display
  context: string          // surrounding context, escaped
  offset: number
  layer: number            // which decode layer this was found at
  confidence: number       // 0–1
}

export interface NormalizationLayer {
  depth: number
  technique: 'base64' | 'url' | 'hex' | 'nfkc' | 'homoglyph' | 'raw'
  inputSnippet: string     // first 120 chars, escaped
  outputSnippet: string    // first 120 chars, escaped
  changed: boolean
}

export interface HomoglyphMatch {
  original: string
  replacement: string
  codepoint: string
  position: number
  script: string           // e.g. 'Cyrillic', 'Greek'
}

export interface IncidentReport {
  id: string
  sessionId: string
  timestamp: string
  inputLength: number
  inputHash: string        // sha256 of raw input for dedup
  severity: Severity       // highest severity found
  threats: ThreatMatch[]
  normalizationTrace: NormalizationLayer[]
  homoglyphs: HomoglyphMatch[]
  aiAnalysis?: AIAnalysisResult | null
  processingTimeMs: number
  rulesVersion: string
  engineMode: 'offline' | 'hybrid'
}

export interface AIAnalysisResult {
  promptInjectionScore: number    // 0–1
  obfuscationScore: number        // 0–1
  malwareSignatureMatches: string[]
  threatSummary: string           // plain text, sanitized
  modelUsed: string
  latencyMs: number
}

export interface Rule {
  id: string
  name: string
  description: string
  category: ThreatCategory
  severity: Severity
  pattern: string          // regex string
  flags?: string           // regex flags
  testCases: {
    matches: string[]
    noMatches: string[]
  }
  metadata: {
    cve?: string
    owasp?: string
    tags: string[]
  }
}

export interface RulesFile {
  version: string
  generatedAt: string
  totalRules: number
  rules: Rule[]
}

export type AnalysisStatus =
  | 'idle'
  | 'normalizing'
  | 'matching'
  | 'ai-analyzing'
  | 'complete'
  | 'error'

export interface AnalysisProgress {
  status: AnalysisStatus
  stage: string
  percent: number
}
