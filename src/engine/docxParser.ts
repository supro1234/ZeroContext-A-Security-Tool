/**
 * docxParser.ts
 * Proper DOCX extraction using JSZip + DOMParser.
 *
 * NEVER reads raw ZIP bytes as text — always unzips and parses word/document.xml.
 *
 * Detects hidden/invisible text runs by inspecting w:rPr properties:
 *   • w:vanish           — text explicitly hidden
 *   • w:webHidden        — hidden in web view
 *   • w:color FFFFFF     — white (near-background) text
 *   • w:sz near 0        — near-invisible font size
 *   • w:highlight match  — highlight colour == font colour (double-hide)
 *
 * Also parses w:tbl tables for structured data, enabling data-contradiction checks.
 */

import JSZip from 'jszip'

// ─── Public Types ────────────────────────────────────────────────────────────

export type HiddenReason =
  | 'vanish'
  | 'webHidden'
  | 'whiteColor'
  | 'nearZeroSize'
  | 'doubleHide'

export interface HiddenRun {
  text: string
  reason: HiddenReason
  offset: number       // approximate char offset in full doc text
  colorHex?: string    // e.g. "FFFFFF"
  sizePt?: number      // half-points / 2
}

export interface ParsedCell {
  text: string
}

export interface ParsedRow {
  cells: ParsedCell[]
}

export interface ParsedTable {
  rows: ParsedRow[]
}

export interface DataContradiction {
  claim: string          // The contradicting sentence
  tableValue: string     // The value from the parsed table
  claimedValue: string   // What the text claims
  confidence: number     // 0–1
}

export interface DocxParseResult {
  visibleText: string
  hiddenRuns: HiddenRun[]
  tables: ParsedTable[]
  contradictions: DataContradiction[]
  pageCount: number
}

// ─── Colour Helpers ──────────────────────────────────────────────────────────

/** Returns true if a hex colour is near-white (background) */
function isNearWhite(hex: string): boolean {
  const h = hex.replace('#', '').padStart(6, '0')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  // Luminance > 230/255 → near-white
  return r > 230 && g > 230 && b > 230
}

/** Returns true if a hex colour is near-black (dark background) */
function isNearBlack(hex: string): boolean {
  const h = hex.replace('#', '').padStart(6, '0')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return r < 30 && g < 30 && b < 30
}

// ─── XML Helpers ─────────────────────────────────────────────────────────────

function getAttr(el: Element, ns: string, name: string): string {
  // Try w: namespace attr first, then plain
  return el.getAttribute(`${ns}:${name}`) ?? el.getAttribute(name) ?? ''
}



// ─── Run Property Inspector ──────────────────────────────────────────────────

interface RunProps {
  vanish: boolean
  webHidden: boolean
  colorHex: string | null   // e.g. "FFFFFF", or null if unset
  sizePt: number | null     // half-points ÷ 2, null if unset
  highlightColor: string | null
}

function inspectRunProps(rPr: Element | null): RunProps {
  if (!rPr) return { vanish: false, webHidden: false, colorHex: null, sizePt: null, highlightColor: null }

  // w:vanish — element presence = hidden
  const hasVanish = Array.from(rPr.children).some(
    (c) => c.localName === 'vanish' || c.tagName.endsWith(':vanish')
  )

  // w:webHidden
  const hasWebHidden = Array.from(rPr.children).some(
    (c) => c.localName === 'webHidden' || c.tagName.endsWith(':webHidden')
  )

  // w:color
  let colorHex: string | null = null
  const colorEl = Array.from(rPr.children).find(
    (c) => c.localName === 'color' || c.tagName.endsWith(':color')
  )
  if (colorEl) {
    const val = getAttr(colorEl as Element, 'w', 'val')
    if (val && val !== 'auto') colorHex = val.toUpperCase()
  }

  // w:sz — font size in half-points
  let sizePt: number | null = null
  const szEl = Array.from(rPr.children).find(
    (c) => c.localName === 'sz' || c.tagName.endsWith(':sz')
  )
  if (szEl) {
    const val = getAttr(szEl as Element, 'w', 'val')
    if (val) sizePt = parseInt(val, 10) / 2
  }

  // w:highlight
  let highlightColor: string | null = null
  const hlEl = Array.from(rPr.children).find(
    (c) => c.localName === 'highlight' || c.tagName.endsWith(':highlight')
  )
  if (hlEl) {
    highlightColor = getAttr(hlEl as Element, 'w', 'val') || null
  }

  return { vanish: hasVanish, webHidden: hasWebHidden, colorHex, sizePt, highlightColor }
}

// ─── Table Parser ────────────────────────────────────────────────────────────

function parseTable(tbl: Element): ParsedTable {
  const rows: ParsedRow[] = []
  const trEls = Array.from(tbl.children).filter(
    (c) => c.localName === 'tr' || c.tagName.endsWith(':tr')
  )
  for (const tr of trEls) {
    const cells: ParsedCell[] = []
    const tcEls = Array.from(tr.children).filter(
      (c) => c.localName === 'tc' || c.tagName.endsWith(':tc')
    )
    for (const tc of tcEls) {
      cells.push({ text: tc.textContent ?? '' })
    }
    if (cells.length > 0) rows.push({ cells })
  }
  return { rows }
}

// ─── Data-Contradiction Detector ─────────────────────────────────────────────

/**
 * Finds sentences in free text that claim a numeric value which contradicts
 * what is actually present in the parsed tables.
 *
 * Heuristic: look for "X is/was/scores N" or "only X at N%" patterns,
 * then check if N appears in table cells AND whether the table shows
 * a different (higher) value alongside.
 */
function detectContradictions(
  freeText: string,
  tables: ParsedTable[]
): DataContradiction[] {
  const contradictions: DataContradiction[] = []
  if (tables.length === 0) return contradictions

  // Extract all (label, value) pairs from tables
  const tableValues: Array<{ label: string; value: string }> = []
  for (const tbl of tables) {
    for (const row of tbl.rows) {
      if (row.cells.length >= 2) {
        const label = row.cells[0].text.trim()
        const value = row.cells[1].text.trim()
        if (label && value) tableValues.push({ label, value })
      }
    }
  }
  if (tableValues.length === 0) return contradictions

  // Patterns: "X is the only/top/highest entry at N" or "only real score is N"
  const claimPatterns = [
    /(?:only|top|best|highest|real|true)\s+(?:score|result|value|entry)\s+(?:is|was|equals?)\s+(\d+(?:\.\d+)?%?)/gi,
    /(\w[\w\s]{1,30})\s+(?:scored?|rated?|ranks?|at)\s+(\d+(?:\.\d+)?%?)/gi,
    /(?:the\s+)?(\w[\w\s]{1,20})\s+(?:is|was)\s+(?:at\s+)?(\d+(?:\.\d+)?%?)/gi,
  ]

  for (const sentence of freeText.split(/[.!?]/)) {
    for (const pattern of claimPatterns) {
      pattern.lastIndex = 0
      const m = pattern.exec(sentence)
      if (!m) continue
      const claimedValue = m[m.length - 1]  // last capture group = the number
      const claimedNum = parseFloat(claimedValue.replace('%', ''))
      if (isNaN(claimedNum)) continue

      // Check if any table row has a numerically higher value for a similar label
      for (const tv of tableValues) {
        const tableNum = parseFloat(tv.value.replace('%', ''))
        if (isNaN(tableNum)) continue
        if (Math.abs(tableNum - claimedNum) > 2 && tableNum !== claimedNum) {
          // There's a mismatch — the free-text claim doesn't match the table
          contradictions.push({
            claim: sentence.trim().slice(0, 200),
            tableValue: `${tv.label}: ${tv.value}`,
            claimedValue,
            confidence: 0.8,
          })
          break
        }
      }
    }
  }

  return contradictions
}

// ─── Main DOCX Parser ────────────────────────────────────────────────────────

export async function extractDocxText(file: File): Promise<DocxParseResult> {
  const arrayBuffer = await file.arrayBuffer()
  const zip = await JSZip.loadAsync(arrayBuffer)

  // Get the main document XML
  const docXmlFile = zip.file('word/document.xml')
  if (!docXmlFile) {
    throw new Error('Invalid DOCX: word/document.xml not found inside ZIP')
  }

  const docXmlStr = await docXmlFile.async('string')
  const parser = new DOMParser()
  const doc = parser.parseFromString(docXmlStr, 'application/xml')

  const body = doc.querySelector('body')
  if (!body) throw new Error('Invalid DOCX: no <w:body> found')

  const hiddenRuns: HiddenRun[] = []
  const tables: ParsedTable[] = []
  const visibleParts: string[] = []
  let charOffset = 0

  // Walk top-level body children: paragraphs (w:p) and tables (w:tbl)
  for (const child of Array.from(body.children)) {
    const tag = child.localName

    if (tag === 'tbl') {
      // Parse table structure for contradiction detection
      tables.push(parseTable(child))

      // Also extract table text as visible text
      const tableText = child.textContent ?? ''
      visibleParts.push(tableText)
      charOffset += tableText.length + 1

    } else if (tag === 'p') {
      // Walk runs inside each paragraph
      const runs = Array.from(child.children).filter(
        (c) => c.localName === 'r' || c.tagName.endsWith(':r')
      )

      for (const run of runs) {
        // Find run properties
        const rPrEl = Array.from(run.children).find(
          (c) => c.localName === 'rPr' || c.tagName.endsWith(':rPr')
        ) as Element | undefined

        const props = inspectRunProps(rPrEl ?? null)

        // Get run text (w:t elements)
        const tEls = Array.from(run.children).filter(
          (c) => c.localName === 't' || c.tagName.endsWith(':t')
        )
        const runText = tEls.map((t) => t.textContent ?? '').join('')
        if (!runText) continue

        // Classify hidden reasons
        const reasons: HiddenReason[] = []

        if (props.vanish) reasons.push('vanish')
        if (props.webHidden) reasons.push('webHidden')
        if (props.colorHex && (isNearWhite(props.colorHex) || isNearBlack(props.colorHex))) {
          reasons.push('whiteColor')
        }
        if (props.sizePt !== null && props.sizePt <= 1) {
          reasons.push('nearZeroSize')
        }
        // Double-hide: highlight colour matches font colour
        if (
          props.highlightColor &&
          props.colorHex &&
          props.highlightColor.toLowerCase() === props.colorHex.toLowerCase()
        ) {
          reasons.push('doubleHide')
        }

        if (reasons.length > 0) {
          // Hidden run — flag it but don't add to visible text
          hiddenRuns.push({
            text: runText,
            reason: reasons[0],
            offset: charOffset,
            colorHex: props.colorHex ?? undefined,
            sizePt: props.sizePt ?? undefined,
          })
        } else {
          // Visible run
          visibleParts.push(runText)
          charOffset += runText.length
        }
      }

      // Paragraph break
      visibleParts.push('\n')
      charOffset += 1
    }
  }

  const visibleText = visibleParts.join('').trim()

  // Estimate page count from section properties (rough: 1 per w:sectPr, minimum 1)
  const sectPrs = doc.querySelectorAll('sectPr')
  const pageCount = Math.max(1, sectPrs.length)

  // Run contradiction detection
  const contradictions = detectContradictions(visibleText, tables)

  return { visibleText, hiddenRuns, tables, contradictions, pageCount }
}
