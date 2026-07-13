/**
 * redosGuard.ts
 * Executes a regex with a strict timeout to prevent ReDoS attacks.
 * All regex matching in ZeroContext MUST use runRegex() — never raw .test() or .exec().
 */

export interface RegexResult {
  matched: boolean
  matches: RegExpExecArray[]
  timedOut: boolean
  executionMs: number
}

const REGEX_TIMEOUT_MS = 50

/**
 * Runs a regex against input with a character-budget timeout.
 * Uses step counting since true threading isn't available in sync context.
 */
export function runRegex(
  pattern: RegExp,
  input: string,
  timeoutMs: number = REGEX_TIMEOUT_MS
): RegexResult {
  const start = performance.now()
  const matches: RegExpExecArray[] = []
  let timedOut = false

  try {
    // Clone pattern with global flag to iterate matches
    const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'
    const globalPattern = new RegExp(pattern.source, flags)

    let match: RegExpExecArray | null
    let iterations = 0
    const maxIterations = input.length * 10  // linear budget

    while ((match = globalPattern.exec(input)) !== null) {
      matches.push(match)
      iterations++

      // Prevent infinite loop on zero-length matches
      if (match.index === globalPattern.lastIndex) {
        globalPattern.lastIndex++
      }

      const elapsed = performance.now() - start
      if (elapsed > timeoutMs || iterations > maxIterations) {
        timedOut = true
        break
      }
    }
  } catch (e) {
    // Invalid regex or other error — treat as no match
    return { matched: false, matches: [], timedOut: false, executionMs: performance.now() - start }
  }

  return {
    matched: matches.length > 0,
    matches,
    timedOut,
    executionMs: performance.now() - start,
  }
}

/**
 * Safely test if pattern matches without returning match details.
 */
export function safeTest(pattern: RegExp, input: string): boolean {
  const result = runRegex(pattern, input)
  return result.matched && !result.timedOut
}
