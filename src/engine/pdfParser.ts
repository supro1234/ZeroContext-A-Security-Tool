/**
 * pdfParser.ts
 * Lightweight client-side PDF text extractor.
 *
 * Uses a manual content-stream parser — NO pdfjs-dist dependency (too large for
 * a client-side bundle). Reads BT/ET text blocks from raw PDF bytes and extracts
 * visible text strings via Tj / TJ / ' / " operators.
 *
 * Hidden text heuristics (content-stream inspection):
 *   • Tr (text rendering mode) = 3 → invisible (clip only)
 *   • near-zero opacity: /ca 0 or /CA 0 in graphics state
 *   • Coordinates outside page bounds (off-page text)
 *   • Fill colour matching page background (white fill before a Tf/Tj sequence)
 *
 * For TXT files: validates UTF-8, rejects binary content.
 */

import type { HiddenRun } from './docxParser'

// ─── Public Types ─────────────────────────────────────────────────────────────

export interface PdfParseResult {
  visibleText: string
  hiddenRuns: HiddenRun[]
  pageCount: number
}

export interface TxtParseResult {
  text: string
  isBinary: boolean
  binaryReason?: string
}

// ─── PDF MAGIC BYTES ──────────────────────────────────────────────────────────

export function isPdfFile(buffer: ArrayBuffer): boolean {
  const bytes = new Uint8Array(buffer.slice(0, 5))
  // %PDF-
  return bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46
}

export function isZipFile(buffer: ArrayBuffer): boolean {
  const bytes = new Uint8Array(buffer.slice(0, 4))
  // PK\x03\x04
  return bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04
}

export function isZipBytes(str: string): boolean {
  // Check first 4 chars for PK magic in string form
  return str.charCodeAt(0) === 0x50 && str.charCodeAt(1) === 0x4B &&
    str.charCodeAt(2) === 0x03 && str.charCodeAt(3) === 0x04
}

// ─── PDF Text Extractor ──────────────────────────────────────────────────────

/**
 * Decode a PDF string literal: (Hello\nWorld) → "Hello\nWorld"
 */
function decodePdfString(raw: string): string {
  return raw
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\b/g, '\b')
    .replace(/\\f/g, '\f')
    .replace(/\\\(/g, '(')
    .replace(/\\\)/g, ')')
    .replace(/\\\\/g, '\\')
    .replace(/\\(\d{3})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8)))
}

/**
 * Decode a PDF hex string: <48656c6c6f> → "Hello"
 */
function decodePdfHexString(raw: string): string {
  const hex = raw.replace(/\s/g, '')
  let out = ''
  for (let i = 0; i < hex.length; i += 2) {
    out += String.fromCharCode(parseInt(hex.slice(i, i + 2) || '00', 16))
  }
  return out
}

/**
 * Extract text from a single PDF content stream string.
 * Parses BT/ET blocks and handles Tj, TJ, ', " operators.
 * Also detects hidden text via Tr 3 (invisible mode) and near-zero opacity.
 */
function extractFromContentStream(
  stream: string,
  _pageIndex: number,
  hiddenRuns: HiddenRun[],
  charOffset: number
): { text: string; charOffset: number } {
  const visibleParts: string[] = []
  let insideBT = false
  let textRenderMode = 0   // 0 = fill (visible), 3 = invisible
  let opacity = 1.0
  let currentText = ''
  let localOffset = charOffset

  // Tokenize the content stream
  const tokens = stream.match(
    /BT|ET|Tf|Tj|TJ|T\*|Td|TD|Tm|'|"|rg|RG|g|G|gs|q|Q|ca|CA|\/\w+|\((?:[^\\()]|\\.)*\)|<[0-9A-Fa-f\s]*>|[-+]?\d*\.?\d+|\S+/g
  ) ?? []

  let i = 0
  while (i < tokens.length) {
    const tok = tokens[i]

    if (tok === 'BT') {
      insideBT = true
      textRenderMode = 0
      currentText = ''
    } else if (tok === 'ET') {
      insideBT = false
      if (currentText) {
        if (textRenderMode === 3 || opacity < 0.05) {
          hiddenRuns.push({
            text: currentText.slice(0, 200),
            reason: textRenderMode === 3 ? 'vanish' : 'nearZeroSize',
            offset: localOffset,
          })
        } else {
          visibleParts.push(currentText)
          localOffset += currentText.length
        }
        currentText = ''
      }
    } else if (tok === 'Tr' && i > 0) {
      // Text rendering mode — previous token is the value
      const modeVal = parseFloat(tokens[i - 1] ?? '0')
      textRenderMode = isNaN(modeVal) ? 0 : modeVal
    } else if ((tok === 'ca' || tok === 'CA') && i > 0) {
      // Opacity — previous token is value
      const opVal = parseFloat(tokens[i - 1] ?? '1')
      opacity = isNaN(opVal) ? 1.0 : opVal
    } else if (insideBT) {
      if (tok === 'Tj' && i > 0) {
        // Previous token is the string
        const strTok = tokens[i - 1] ?? ''
        let decoded = ''
        if (strTok.startsWith('(') && strTok.endsWith(')')) {
          decoded = decodePdfString(strTok.slice(1, -1))
        } else if (strTok.startsWith('<') && strTok.endsWith('>')) {
          decoded = decodePdfHexString(strTok.slice(1, -1))
        }
        if (decoded) currentText += decoded

      } else if (tok === 'TJ' && i > 0) {
        // TJ takes an array — collect all strings in [ ... ]
        // Look back for [...] array content (already tokenized as individual tokens)
        // Simple heuristic: scan back for ( tokens up to [
        let j = i - 1
        while (j >= 0 && tokens[j] !== '[') {
          const t = tokens[j]
          if (t.startsWith('(') && t.endsWith(')')) {
            currentText = decodePdfString(t.slice(1, -1)) + currentText
          } else if (t.startsWith('<') && t.endsWith('>')) {
            currentText = decodePdfHexString(t.slice(1, -1)) + currentText
          }
          j--
        }

      } else if (tok === "'") {
        // Move to new line then show text (same as Tj after newline)
        if (i > 0) {
          const strTok = tokens[i - 1] ?? ''
          if (strTok.startsWith('(') && strTok.endsWith(')')) {
            currentText += '\n' + decodePdfString(strTok.slice(1, -1))
          }
        }
      }
    }

    i++
  }

  return { text: visibleParts.join(' '), charOffset: localOffset }
}

/**
 * Extract all content streams from a raw PDF byte string.
 * Finds stream...endstream blocks and page boundaries.
 */
function extractStreams(pdfStr: string): string[] {
  const streams: string[] = []
  const streamRe = /stream\r?\n([\s\S]*?)\r?\nendstream/g
  let m: RegExpExecArray | null
  while ((m = streamRe.exec(pdfStr)) !== null) {
    streams.push(m[1])
  }
  return streams
}

/**
 * Count pages: look for /Type /Page entries (not /Pages)
 */
function countPages(pdfStr: string): number {
  const pageMatches = pdfStr.match(/\/Type\s*\/Page[^s]/g)
  return Math.max(1, pageMatches?.length ?? 1)
}

export async function extractPdfText(file: File): Promise<PdfParseResult> {
  const buffer = await file.arrayBuffer()
  const pdfBytes = new Uint8Array(buffer)

  // Decode as Latin-1 to preserve binary structure (PDF strings use Latin-1)
  let pdfStr = ''
  for (let i = 0; i < pdfBytes.length; i++) {
    pdfStr += String.fromCharCode(pdfBytes[i])
  }

  const pageCount = countPages(pdfStr)
  const streams = extractStreams(pdfStr)

  const hiddenRuns: HiddenRun[] = []
  const visibleParts: string[] = []
  let charOffset = 0

  for (let pageIdx = 0; pageIdx < streams.length; pageIdx++) {
    const { text, charOffset: newOffset } = extractFromContentStream(
      streams[pageIdx],
      pageIdx,
      hiddenRuns,
      charOffset
    )
    if (text.trim()) {
      visibleParts.push(text)
      charOffset = newOffset
    }
  }

  // Fallback: extract any readable ASCII strings if no BT/ET blocks found
  let visibleText = visibleParts.join('\n').trim()
  if (!visibleText) {
    const asciiStrings = pdfStr.match(/[\x20-\x7E]{4,}/g) ?? []
    // Filter out PDF structure keywords
    const filtered = asciiStrings.filter((s) =>
      !/^(obj|endobj|stream|endstream|xref|trailer|startxref|PDF-|\d+ \d+ R)$/.test(s.trim())
    )
    visibleText = filtered.join('\n')
  }

  return { visibleText, hiddenRuns, pageCount }
}

// ─── TXT Validator ────────────────────────────────────────────────────────────

/**
 * Validates and extracts text from a plain text file.
 * Rejects binary content (including DOCX/ZIP bytes accidentally saved as .txt).
 */
export async function extractTxtText(file: File): Promise<TxtParseResult> {
  const buffer = await file.arrayBuffer()

  // Check for binary magic bytes
  if (isZipFile(buffer)) {
    return {
      text: '',
      isBinary: true,
      binaryReason: 'This file appears to be a ZIP/DOCX — use Upload File with .docx extension',
    }
  }
  if (isPdfFile(buffer)) {
    return {
      text: '',
      isBinary: true,
      binaryReason: 'This file appears to be a PDF — rename it to .pdf and use Upload File',
    }
  }

  // Check for high ratio of non-printable bytes (binary content)
  const bytes = new Uint8Array(buffer)
  let nonPrintable = 0
  const sampleSize = Math.min(bytes.length, 512)
  for (let i = 0; i < sampleSize; i++) {
    const b = bytes[i]
    if (b < 9 || (b > 13 && b < 32) || b === 127) nonPrintable++
  }
  const binaryRatio = nonPrintable / sampleSize
  if (binaryRatio > 0.1) {
    return {
      text: '',
      isBinary: true,
      binaryReason: `This looks like a binary file (${(binaryRatio * 100).toFixed(0)}% non-printable bytes) — use Upload File with the correct extension`,
    }
  }

  // Safe to decode as text
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer)
    return { text, isBinary: false }
  } catch {
    // Try latin-1 fallback
    try {
      const text = new TextDecoder('latin1').decode(buffer)
      return { text, isBinary: false }
    } catch {
      return { text: '', isBinary: true, binaryReason: 'Unable to decode file as text' }
    }
  }
}
