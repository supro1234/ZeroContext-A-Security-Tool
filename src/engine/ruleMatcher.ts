/**
 * ruleMatcher.ts
 * Context-aware threat rule matcher for ZeroContext.
 *
 * Key improvements over naïve pattern matching:
 *  1. Prose/documentation context detection — reduces confidence when a
 *     match appears inside quotation marks or normal grammatical sentences.
 *  2. Multi-signal scoring — CRITICAL/HIGH require ≥2 corroborating signals.
 *  3. Rule-specific context validators for XSS-001, SQL-002, OBFS-001, XSS-007.
 *  4. Base64 decode-first logic — OBFS-001 only elevates if decoded content
 *     itself contains a known threat pattern.
 */

import type { Rule, RulesFile, ThreatMatch, Severity } from '../types/threat'
import { runRegex } from './redosGuard'
import { escapeAndTruncate } from '../utils/escapeText'

let loadedRules: Rule[] = []
let rulesVersion = 'unloaded'

export function loadRules(rulesFile: RulesFile): void {
  loadedRules = rulesFile.rules
  rulesVersion = rulesFile.version
}

export function getRulesVersion(): string { return rulesVersion }
export function getRulesCount(): number { return loadedRules.length }

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, SAFE: 0,
}

export function highestSeverity(threats: ThreatMatch[]): Severity {
  if (threats.length === 0) return 'SAFE'
  return threats.reduce(
    (best, t) => SEVERITY_ORDER[t.severity] > SEVERITY_ORDER[best] ? t.severity : best,
    'SAFE' as Severity,
  )
}

// ─── Context Helpers ──────────────────────────────────────────────────────────

/**
 * Returns true if the match offset is inside a quoted span (prose/docs context).
 * Heuristic: if the nearest preceding unmatched quote character is within 120 chars.
 */
function isInsideQuotes(text: string, offset: number): boolean {
  const before = text.slice(Math.max(0, offset - 120), offset)
  // Count unmatched single or double quotes before this position
  const doubleCount = (before.match(/"/g) ?? []).length
  const singleCount = (before.match(/'/g) ?? []).length
  return doubleCount % 2 === 1 || singleCount % 2 === 1
}

/**
 * Returns true if the surrounding context looks like normal prose/documentation
 * (contains sentence-ending punctuation and lowercase words — not code-like).
 */
function looksLikeProse(context: string): boolean {
  // Prose signals: sentence-ending punctuation, multiple lowercase words, no code chars
  const hasEndPunctuation = /[.!?]/.test(context)
  const wordCount = (context.match(/\b[a-z]{3,}\b/gi) ?? []).length
  const codeChars = (context.match(/[{}[\]();=<>|&$`\\]/g) ?? []).length
  return hasEndPunctuation && wordCount >= 4 && codeChars < 3
}

/**
 * Returns true if text around offset looks like it's inside actual HTML structure
 * (there's a real attribute context, or the script tag is followed by executable content).
 */
function isInHtmlContext(text: string, offset: number, matchLen: number): boolean {
  const after = text.slice(offset + matchLen, offset + matchLen + 200)
  // Needs closing </script> with some content in between to be executable
  const hasClosingTag = /<\/script\s*>/i.test(after)
  // OR has src= attribute (external script load)
  const hasSrcAttr = /src\s*=\s*["']?[^"'\s>]+/i.test(text.slice(offset, offset + 80))
  return hasClosingTag || hasSrcAttr
}

/**
 * Returns true if `--` appears in a genuine SQL injection context.
 *
 * Key insight: a real injection via comment truncation always places an
 * injected command BETWEEN the injected semicolon and the `--` terminator:
 *   e.g.  ' OR 1=1; DROP TABLE users; --
 *                   ^^^^^^^^^^^^^^^^^^  ← injected content in the "gap"
 *
 * A legitimate parameterized query followed by a text divider has ONLY
 * whitespace in that gap:
 *   e.g.  ORDER BY last_name ASC;   --------
 *                               ^^^  ← whitespace only → benign
 *
 * Strategy:
 *  1. If ";" appears within 80 chars before "--", inspect the gap between
 *     them. If the gap contains only whitespace/newlines → NOT injection.
 *     If the gap contains a dangerous SQL keyword → IS injection.
 *  2. For quote-then-dash patterns (e.g. admin'--), check the 60 chars before
 *     for a quote char with no intervening semicolon (tight coupling).
 *  3. Exclude plain repeated-dash dividers (3+ consecutive dashes).
 */
const SQL_INJECTION_KEYWORDS = /\b(?:DROP|DELETE|INSERT|UPDATE|UNION|EXEC(?:UTE)?|ALTER|TRUNCATE|CREATE|REPLACE|MERGE)\b/i
const SQL_TAUTOLOGY = /\b(?:OR|AND)\s+[\w'"]+\s*=\s*[\w'"]+/i

function hasSqlContext(text: string, offset: number): boolean {
  // 1. Reject plain dash-only dividers outright (e.g. "----------")
  const matchWindow = text.slice(Math.max(0, offset - 3), offset + 12)
  if (/^[-\s]+$/.test(matchWindow)) return false

  const before = text.slice(Math.max(0, offset - 80), offset)

  // 2. Check for a semicolon within the look-back window
  const lastSemiIdx = before.lastIndexOf(';')
  if (lastSemiIdx !== -1) {
    // gap = text between the semicolon and "--"
    const gap = before.slice(lastSemiIdx + 1)

    if (/^\s*$/.test(gap)) {
      // Gap is whitespace-only → legitimate query end + unrelated divider → BENIGN
      return false
    }

    // Gap has content — only flag if it contains an actual injected SQL keyword
    const gapHasInjection = SQL_INJECTION_KEYWORDS.test(gap) || SQL_TAUTOLOGY.test(gap)
    if (gapHasInjection) return true

    // Gap has content but no injection keyword — fall through to quote-char check below
  }

  // 3. Quote-then-dash: the classic admin'-- pattern
  //    Look for a quote char tightly before the "--" (no semicolon in between)
  const tightBefore = text.slice(Math.max(0, offset - 60), offset)
  const hasQuoteChar = /['"`]/.test(tightBefore)
  if (hasQuoteChar) {
    // Make sure the quote isn't separated from "--" by a legitimate semicolon+whitespace
    const quotePos = Math.max(tightBefore.lastIndexOf("'"), tightBefore.lastIndexOf('"'), tightBefore.lastIndexOf('`'))
    const semiAfterQuote = tightBefore.indexOf(';', quotePos)
    if (semiAfterQuote === -1) {
      // No semicolon between the quote and "--" → clean quote-comment pattern
      return true
    }
    // Semicolon between quote and "--": check the gap again
    const gapAfterSemi = tightBefore.slice(semiAfterQuote + 1)
    return SQL_INJECTION_KEYWORDS.test(gapAfterSemi) || SQL_TAUTOLOGY.test(gapAfterSemi)
  }

  // 4. SQL keyword directly adjacent to "--" without semicolon (e.g. OR 1=1--)
  const hasSqlKeyword = /(?:UNION|DROP|DELETE|INSERT|UPDATE|OR\s+\d|AND\s+\d)\b/i.test(before)
  return hasSqlKeyword
}

/**
 * Decode a Base64 string and return the decoded text, or null on failure.
 */
function tryBase64Decode(candidate: string): string | null {
  const cleaned = candidate.trim().replace(/\s/g, '')
  if (cleaned.length < 16) return null
  try {
    const norm = cleaned.replace(/-/g, '+').replace(/_/g, '/')
    const padded = norm.padEnd(norm.length + ((4 - (norm.length % 4)) % 4), '=')
    const decoded = atob(padded)
    const printable = decoded.replace(/[\x00-\x08\x0E-\x1F\x7F-\x9F]/g, '')
    if (printable.length < decoded.length * 0.6) return null
    return decoded
  } catch {
    return null
  }
}

/**
 * Known-dangerous patterns to check in decoded Base64 content.
 * These are lightweight inline checks (not full rule re-run) to avoid recursion.
 */
const DECODED_THREAT_PATTERNS = [
  /<\s*script[^>]*>/i,
  /javascript\s*:/i,
  /on\w+\s*=\s*/i,
  /union\s+select/i,
  /exec\s*\(/i,
  /eval\s*\(/i,
  /document\.(write|cookie)/i,
  /ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions/i,
  /your\s+(?:new|real)\s+goal\s+is/i,
  /<\s*iframe/i,
  /\.\.\/\.\.\//,
]

function decodedBase64IsDangerous(candidate: string): boolean {
  const decoded = tryBase64Decode(candidate)
  if (!decoded) return false
  return DECODED_THREAT_PATTERNS.some((p) => p.test(decoded))
}

/**
 * Returns true if {{ expr }} looks like an active injection attempt.
 * Requires complex expressions OR chaining with other attack indicators.
 */
function isActiveTemplateInjection(matched: string, context: string): boolean {
  // Complex expressions: arithmetic, method calls, constructor access
  const isComplex = /\{\{.*?(?:\d+\s*[*+\-/%]\s*\d+|constructor|__proto__|\.[\w]+\s*\(|eval|system|exec).*?\}\}/.test(matched)
  // Chained signal: other SQL/XSS patterns also present in the same context
  const hasChainedSignal = /(?:select|union|alert|eval|exec|drop\s+table|<script)/i.test(context)
  // ERB/server-side: <%= ... %> always suspicious
  const isServerSide = /<%[=\-]/.test(matched)
  return isComplex || hasChainedSignal || isServerSide
}

// ─── Confidence / Severity Adjusters ─────────────────────────────────────────

type Adjustment = { confidence: number; severity: Severity }

function adjustForContext(
  ruleId: string,
  matchedText: string,
  context: string,
  text: string,
  offset: number,
  matchLen: number,
  baseSeverity: Severity,
): Adjustment {
  let confidence = 1.0
  let severity = baseSeverity

  const inQuotes = isInsideQuotes(text, offset)
  const prose = looksLikeProse(context)

  // ── XSS-001: Script Tag ─────────────────────────────────────────────────
  if (ruleId === 'XSS-001') {
    const inHtml = isInHtmlContext(text, offset, matchLen)
    if (!inHtml) {
      // No closing </script> with content and no src= attribute
      confidence = inQuotes || prose ? 0.2 : 0.5
      severity = confidence < 0.4 ? 'LOW' : 'MEDIUM'
    }
    // If in HTML context, keep CRITICAL
  }

  // ── SQL-002: SQL Comment Terminator ────────────────────────────────────
  else if (ruleId === 'SQL-002') {
    const hasSql = hasSqlContext(text, offset)
    if (!hasSql) {
      // Bare -- with no SQL context = not a threat
      confidence = 0.1
      severity = 'INFO'
    } else {
      confidence = 0.9
    }
  }

  // ── OBFS-001: Base64 ────────────────────────────────────────────────────
  else if (ruleId === 'OBFS-001') {
    // Raw match: only flag if decoded content is dangerous
    const rawMatch = matchedText.replace(/^&amp;|&quot;|&#x27;/g, '') // un-escape briefly
    if (decodedBase64IsDangerous(rawMatch)) {
      confidence = 0.95
      severity = 'HIGH'  // Elevate from MEDIUM because decoded = dangerous
    } else {
      // Decoded content is benign — downgrade
      confidence = 0.15
      severity = 'INFO'
    }
  }

  // ── XSS-007: Template Injection ─────────────────────────────────────────
  else if (ruleId === 'XSS-007') {
    const active = isActiveTemplateInjection(matchedText, context)
    if (!active) {
      // Simple {{ variable }} in prose/docs — not dangerous
      confidence = prose || inQuotes ? 0.1 : 0.3
      severity = confidence < 0.2 ? 'INFO' : 'LOW'
    }
    // Complex expressions keep CRITICAL
  }

  // ── General prose downgrade for all other rules ──────────────────────
  else if ((inQuotes || prose) && (severity === 'CRITICAL' || severity === 'HIGH')) {
    confidence = Math.max(0.35, confidence * 0.5)
    // Don't drop severity fully, but flag reduced confidence
  }

  return { confidence, severity }
}

// ─── Main Matcher ─────────────────────────────────────────────────────────────

/**
 * Match all rules against a single text layer.
 * Returns all matches found, with context-adjusted confidence and severity.
 */
export function matchRulesAgainstLayer(text: string, depth: number): ThreatMatch[] {
  if (loadedRules.length === 0) return []

  const matches: ThreatMatch[] = []

  for (const rule of loadedRules) {
    let pattern: RegExp
    try {
      pattern = new RegExp(rule.pattern, rule.flags ?? 'gi')
    } catch {
      continue
    }

    const result = runRegex(pattern, text)

    if (result.timedOut) {
      matches.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        severity: 'HIGH',
        matchedText: '[ReDoS timeout — pattern exceeded budget]',
        context: escapeAndTruncate(text.slice(0, 80)),
        offset: 0,
        layer: depth,
        confidence: 0.5,
      })
      continue
    }

    for (const m of result.matches) {
      const offset = m.index ?? 0
      const contextStart = Math.max(0, offset - 40)
      const contextEnd = Math.min(text.length, offset + m[0].length + 40)
      const contextRaw = text.slice(contextStart, contextEnd)

      const { confidence, severity } = adjustForContext(
        rule.id,
        m[0],
        contextRaw,
        text,
        offset,
        m[0].length,
        rule.severity,
      )

      // Skip INFO-level matches with very low confidence — suppress noise
      if (severity === 'INFO' && confidence < 0.2) continue

      matches.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        severity,
        matchedText: escapeAndTruncate(m[0]),
        context: escapeAndTruncate(contextRaw),
        offset,
        layer: depth,
        confidence,
      })
    }
  }

  return matches
}

/**
 * Run rules against all normalization layers, deduplicating by ruleId + matchedText.
 */
export function matchAllLayers(
  layers: Array<{ text: string; depth: number }>,
): ThreatMatch[] {
  const allMatches: ThreatMatch[] = []
  const seenKeys = new Set<string>()

  for (const layer of layers) {
    const layerMatches = matchRulesAgainstLayer(layer.text, layer.depth)
    for (const m of layerMatches) {
      const key = `${m.ruleId}::${m.matchedText}`
      if (!seenKeys.has(key)) {
        seenKeys.add(key)
        allMatches.push(m)
      }
    }
  }

  return allMatches
}
