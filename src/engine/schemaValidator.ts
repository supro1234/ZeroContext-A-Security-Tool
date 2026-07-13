/**
 * schemaValidator.ts
 * Validates rules.json against its schema before trusting the data.
 */

import type { RulesFile } from '../types/threat'

const VALID_CATEGORIES = new Set([
  'XSS', 'SQL_INJECTION', 'PROMPT_INJECTION', 'OBFUSCATION',
  'HOMOGLYPH', 'COMMAND_INJECTION', 'PATH_TRAVERSAL',
  'PROTOTYPE_POLLUTION', 'REDOS', 'ENCODING_ABUSE', 'UNKNOWN'
])

const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'SAFE'])

export interface ValidationResult {
  valid: boolean
  errors: string[]
}

function validateRule(rule: unknown, index: number): string[] {
  const errors: string[] = []
  const prefix = `rules[${index}]`

  if (!rule || typeof rule !== 'object') {
    return [`${prefix}: must be an object`]
  }

  const r = rule as Record<string, unknown>

  if (typeof r.id !== 'string' || r.id.length === 0)
    errors.push(`${prefix}.id: must be non-empty string`)

  if (typeof r.name !== 'string' || r.name.length === 0)
    errors.push(`${prefix}.name: must be non-empty string`)

  if (typeof r.description !== 'string')
    errors.push(`${prefix}.description: must be string`)

  if (!VALID_CATEGORIES.has(r.category as string))
    errors.push(`${prefix}.category: invalid value "${r.category}"`)

  if (!VALID_SEVERITIES.has(r.severity as string))
    errors.push(`${prefix}.severity: invalid value "${r.severity}"`)

  if (typeof r.pattern !== 'string' || r.pattern.length === 0) {
    errors.push(`${prefix}.pattern: must be non-empty string`)
  } else {
    // Validate the regex is syntactically valid
    try {
      new RegExp(r.pattern as string, (r.flags as string) ?? 'gi')
    } catch (e) {
      errors.push(`${prefix}.pattern: invalid regex — ${e}`)
    }
  }

  if (!Array.isArray((r.testCases as Record<string, unknown>)?.matches))
    errors.push(`${prefix}.testCases.matches: must be array`)

  if (!Array.isArray((r.testCases as Record<string, unknown>)?.noMatches))
    errors.push(`${prefix}.testCases.noMatches: must be array`)

  if (!r.metadata || typeof r.metadata !== 'object')
    errors.push(`${prefix}.metadata: must be object`)

  return errors
}

export function validateRulesFile(data: unknown): ValidationResult {
  const errors: string[] = []

  if (!data || typeof data !== 'object') {
    return { valid: false, errors: ['Root must be an object'] }
  }

  const d = data as Record<string, unknown>

  if (typeof d.version !== 'string' || d.version.length === 0)
    errors.push('version: must be non-empty string')

  if (typeof d.generatedAt !== 'string')
    errors.push('generatedAt: must be string')

  if (typeof d.totalRules !== 'number' || d.totalRules < 0)
    errors.push('totalRules: must be non-negative number')

  if (!Array.isArray(d.rules)) {
    errors.push('rules: must be an array')
    return { valid: false, errors }
  }

  if (d.rules.length !== d.totalRules) {
    errors.push(`totalRules (${d.totalRules}) does not match rules array length (${d.rules.length})`)
  }

  for (let i = 0; i < (d.rules as unknown[]).length; i++) {
    errors.push(...validateRule((d.rules as unknown[])[i], i))
  }

  return { valid: errors.length === 0, errors }
}

export function parseValidatedRulesFile(data: unknown): RulesFile {
  const result = validateRulesFile(data)
  if (!result.valid) {
    throw new Error(`rules.json failed validation:\n${result.errors.join('\n')}`)
  }
  return data as RulesFile
}
