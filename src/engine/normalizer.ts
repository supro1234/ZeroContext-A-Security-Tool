/**
 * normalizer.ts
 * Recursive payload normalization engine.
 * Decodes Base64, URL encoding, and hex up to MAX_DEPTH layers.
 * Applies Unicode NFKC normalization at each layer.
 */

import type { NormalizationLayer } from '../types/threat'

const MAX_DEPTH = 5

// ─── Decoders ──────────────────────────────────────────────────────────────

function tryBase64Decode(input: string): string | null {
  // Base64 pattern check (avoid false positives on random text)
  const b64Pattern = /^[A-Za-z0-9+/\-_]+=*$/
  const cleaned = input.trim().replace(/\s/g, '')
  if (!b64Pattern.test(cleaned) || cleaned.length < 8) return null

  try {
    // Support both standard and URL-safe base64
    const normalized = cleaned.replace(/-/g, '+').replace(/_/g, '/')
    const padded = normalized.padEnd(
      normalized.length + ((4 - (normalized.length % 4)) % 4),
      '='
    )
    const decoded = atob(padded)
    // Ensure it decoded to something printable/meaningful
    if (decoded === input) return null
    // Check decoded contains non-binary chars (rough heuristic)
    const printable = decoded.replace(/[\x00-\x08\x0E-\x1F\x7F-\x9F]/g, '')
    if (printable.length < decoded.length * 0.7) return null
    return decoded
  } catch {
    return null
  }
}

function tryUrlDecode(input: string): string | null {
  if (!/%[0-9A-Fa-f]{2}/.test(input)) return null
  try {
    const decoded = decodeURIComponent(input)
    if (decoded === input) return null
    return decoded
  } catch {
    try {
      const decoded = unescape(input)   // fallback for malformed %xx
      if (decoded === input) return null
      return decoded
    } catch {
      return null
    }
  }
}

function tryHexDecode(input: string): string | null {
  // Match \x41\x42 style or 0x41 style or plain hex string
  const hexEscape = /(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4})/g
  if (!hexEscape.test(input)) {
    // Try plain hex string (even-length, all hex chars)
    const plain = input.trim().replace(/\s/g, '')
    if (plain.length >= 4 && plain.length % 2 === 0 && /^[0-9A-Fa-f]+$/.test(plain)) {
      try {
        const decoded = plain.match(/.{2}/g)!
          .map((h) => String.fromCharCode(parseInt(h, 16)))
          .join('')
        if (decoded === input) return null
        const printable = decoded.replace(/[\x00-\x08\x0E-\x1F\x7F]/g, '')
        if (printable.length < decoded.length * 0.5) return null
        return decoded
      } catch {
        return null
      }
    }
    return null
  }

  const decoded = input
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u([0-9A-Fa-f]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
  return decoded === input ? null : decoded
}

function applyNFKC(input: string): string {
  try {
    return input.normalize('NFKC')
  } catch {
    return input
  }
}

// ─── Main Normalizer ────────────────────────────────────────────────────────

export interface NormalizationResult {
  final: string
  layers: NormalizationLayer[]
  maxDepthReached: boolean
}

export function normalizePayload(raw: string): NormalizationResult {
  const layers: NormalizationLayer[] = []
  let current = raw
  let maxDepthReached = false

  // Layer 0: always apply NFKC to the raw input
  const nfkc = applyNFKC(current)
  layers.push({
    depth: 0,
    technique: 'nfkc',
    inputSnippet: current.slice(0, 120),
    outputSnippet: nfkc.slice(0, 120),
    changed: nfkc !== current,
  })
  current = nfkc

  for (let depth = 1; depth <= MAX_DEPTH; depth++) {
    let decoded: string | null = null
    let technique: NormalizationLayer['technique'] = 'raw'

    // Try decoders in order of specificity
    decoded = tryUrlDecode(current)
    if (decoded !== null) { technique = 'url' }

    if (decoded === null) {
      decoded = tryHexDecode(current)
      if (decoded !== null) { technique = 'hex' }
    }

    if (decoded === null) {
      decoded = tryBase64Decode(current)
      if (decoded !== null) { technique = 'base64' }
    }

    if (decoded === null) break  // No further decoding possible

    const nfkcDecoded = applyNFKC(decoded)

    layers.push({
      depth,
      technique,
      inputSnippet: current.slice(0, 120),
      outputSnippet: nfkcDecoded.slice(0, 120),
      changed: true,
    })

    current = nfkcDecoded

    if (depth === MAX_DEPTH) {
      maxDepthReached = true
    }
  }

  return { final: current, layers, maxDepthReached }
}

/**
 * Returns all intermediate strings (including raw) for multi-layer rule matching.
 */
export function getAllLayers(result: NormalizationResult): Array<{ text: string; depth: number }> {
  const seen = new Set<string>()
  const out: Array<{ text: string; depth: number }> = []

  for (const layer of result.layers) {
    if (!seen.has(layer.outputSnippet)) {
      seen.add(layer.outputSnippet)
      out.push({ text: layer.outputSnippet, depth: layer.depth })
    }
  }

  // Always include the final normalized string
  if (!seen.has(result.final)) {
    out.push({ text: result.final, depth: result.layers.length })
  }

  return out
}
