/**
 * homoglyphDetector.ts
 * Detects confusable/homoglyph characters — e.g. Cyrillic 'а' (U+0430) mimicking Latin 'a'.
 * Based on Unicode Confusables data.
 */

import type { HomoglyphMatch } from '../types/threat'

// Common confusable mappings: Unicode lookalike → Latin equivalent
// Source: Unicode Confusables (https://unicode.org/reports/tr39/)
const CONFUSABLE_MAP: Record<string, { replacement: string; script: string }> = {
  // Cyrillic mimicking Latin
  '\u0430': { replacement: 'a', script: 'Cyrillic' },  // а → a
  '\u0435': { replacement: 'e', script: 'Cyrillic' },  // е → e
  '\u043e': { replacement: 'o', script: 'Cyrillic' },  // о → o
  '\u0440': { replacement: 'p', script: 'Cyrillic' },  // р → p
  '\u0441': { replacement: 'c', script: 'Cyrillic' },  // с → c
  '\u0445': { replacement: 'x', script: 'Cyrillic' },  // х → x
  '\u0443': { replacement: 'y', script: 'Cyrillic' },  // у → y
  '\u0456': { replacement: 'i', script: 'Cyrillic' },  // і → i
  '\u0410': { replacement: 'A', script: 'Cyrillic' },  // А → A
  '\u0412': { replacement: 'B', script: 'Cyrillic' },  // В → B
  '\u0415': { replacement: 'E', script: 'Cyrillic' },  // Е → E
  '\u041a': { replacement: 'K', script: 'Cyrillic' },  // К → K
  '\u041c': { replacement: 'M', script: 'Cyrillic' },  // М → M
  '\u041d': { replacement: 'H', script: 'Cyrillic' },  // Н → H
  '\u041e': { replacement: 'O', script: 'Cyrillic' },  // О → O
  '\u0420': { replacement: 'P', script: 'Cyrillic' },  // Р → P
  '\u0421': { replacement: 'C', script: 'Cyrillic' },  // С → C
  '\u0422': { replacement: 'T', script: 'Cyrillic' },  // Т → T
  '\u0425': { replacement: 'X', script: 'Cyrillic' },  // Х → X

  // Greek mimicking Latin
  '\u03bf': { replacement: 'o', script: 'Greek' },    // ο → o
  '\u03b1': { replacement: 'a', script: 'Greek' },    // α → a
  '\u03b5': { replacement: 'e', script: 'Greek' },    // ε → e
  '\u03bd': { replacement: 'v', script: 'Greek' },    // ν → v
  '\u03c5': { replacement: 'u', script: 'Greek' },    // υ → u
  '\u039f': { replacement: 'O', script: 'Greek' },    // Ο → O
  '\u0391': { replacement: 'A', script: 'Greek' },    // Α → A
  '\u0392': { replacement: 'B', script: 'Greek' },    // Β → B
  '\u0395': { replacement: 'E', script: 'Greek' },    // Ε → E
  '\u0396': { replacement: 'Z', script: 'Greek' },    // Ζ → Z
  '\u0397': { replacement: 'H', script: 'Greek' },    // Η → H
  '\u0399': { replacement: 'I', script: 'Greek' },    // Ι → I
  '\u039a': { replacement: 'K', script: 'Greek' },    // Κ → K
  '\u039c': { replacement: 'M', script: 'Greek' },    // Μ → M
  '\u039d': { replacement: 'N', script: 'Greek' },    // Ν → N
  '\u03a1': { replacement: 'P', script: 'Greek' },    // Ρ → P
  '\u03a4': { replacement: 'T', script: 'Greek' },    // Τ → T
  '\u03a5': { replacement: 'Y', script: 'Greek' },    // Υ → Y
  '\u03a7': { replacement: 'X', script: 'Greek' },    // Χ → X

  // Mathematical/letterlike forms
  '\u2135': { replacement: 'N', script: 'Letterlike' },  // ℵ → N
  '\u2131': { replacement: 'F', script: 'Letterlike' },  // ℱ → F
  '\uff41': { replacement: 'a', script: 'Fullwidth' },   // ａ → a
  '\uff45': { replacement: 'e', script: 'Fullwidth' },   // ｅ → e
  '\uff4f': { replacement: 'o', script: 'Fullwidth' },   // ｏ → o
}

export interface HomoglyphDetectionResult {
  hasHomoglyphs: boolean
  matches: HomoglyphMatch[]
  normalized: string  // Input with homoglyphs replaced by Latin equivalents
}

export function detectHomoglyphs(input: string): HomoglyphDetectionResult {
  const matches: HomoglyphMatch[] = []
  let normalized = ''

  for (let i = 0; i < input.length; i++) {
    const char = input[i]
    const codepoint = `U+${char.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`
    const confusable = CONFUSABLE_MAP[char]

    if (confusable) {
      matches.push({
        original: char,
        replacement: confusable.replacement,
        codepoint,
        position: i,
        script: confusable.script,
      })
      normalized += confusable.replacement
    } else {
      normalized += char
    }
  }

  return {
    hasHomoglyphs: matches.length > 0,
    matches,
    normalized,
  }
}
