import React from 'react'
import { motion } from 'framer-motion'
import { Download, FileText, Shield, Globe } from 'lucide-react'
import type { IncidentReport } from '../types/threat'
import { sanitizeForExport } from '../utils/escapeText'
import { exportSandboxReplay } from '../utils/sandboxReplay'

interface ForensicExportProps {
  reports: IncidentReport[]
}


/**
 * Build a minimal .docx file using the Office Open XML (OOXML) format.
 * No external library needed — we generate the XML directly and zip it
 * with a lightweight approach using Blob + base64 (pre-built static parts).
 *
 * Structure: content.xml inside a ZIP with required OOXML boilerplate.
 * For a real production app you'd use docx.js or similar, but this gives
 * a valid .docx that opens in Word/LibreOffice with no dependencies.
 */
function buildDocxBlob(report: IncidentReport): Blob {
  const escXml = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

  const severityColor: Record<string, string> = {
    CRITICAL: 'C00000', HIGH: 'E84040', MEDIUM: 'FF8C00',
    LOW: '2E74B5', INFO: '4472C4', SAFE: '375623',
  }
  const sColor = severityColor[report.severity] ?? '000000'

  // ── XML primitives ─────────────────────────────────────────────────────────

  const para = (text: string, bold = false, color = '000000', size = 20) =>
    `<w:p><w:r><w:rPr>${bold ? '<w:b/>' : ''}<w:color w:val="${color}"/><w:sz w:val="${size}"/><w:szCs w:val="${size}"/></w:rPr><w:t xml:space="preserve">${escXml(text)}</w:t></w:r></w:p>`

  const heading = (text: string) => para(text, true, '1F3864', 28)
  const subheading = (text: string) => para(text, true, '2E74B5', 22)
  const normal = (text: string) => para(text, false, '333333', 20)
  const separator = () => `<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="1" w:color="CCCCCC"/></w:pBdr></w:pPr></w:p>`

  // ── Table builders ─────────────────────────────────────────────────────────

  /**
   * Build a table cell with background shade and text.
   * bgColor: optional 6-char hex fill (e.g. "1F3864"). Bold = header style.
   */
  const tableCell = (
    text: string,
    opts: { bold?: boolean; color?: string; bgColor?: string; size?: number; width?: number } = {}
  ) => {
    const { bold = false, color = '333333', bgColor, size = 18, width } = opts
    const shd = bgColor ? `<w:shd w:val="clear" w:color="auto" w:fill="${bgColor}"/>` : ''
    const w = width ? `<w:tcW w:w="${width}" w:type="dxa"/>` : ''
    return `<w:tc><w:tcPr>${w}${shd}</w:tcPr><w:p><w:r><w:rPr>${bold ? '<w:b/>' : ''}<w:color w:val="${color}"/><w:sz w:val="${size}"/><w:szCs w:val="${size}"/></w:rPr><w:t xml:space="preserve">${escXml(text)}</w:t></w:r></w:p></w:tc>`
  }

  /**
   * Build a complete table row.
   */
  const tableRow = (cells: string[], trBg?: string) => {
    const trPr = trBg ? `<w:trPr><w:trHeight w:val="300"/></w:trPr>` : `<w:trPr><w:trHeight w:val="280"/></w:trPr>`
    return `<w:tr>${trPr}${cells.join('')}</w:tr>`
  }

  /**
   * Build a table with a header row (dark blue) and data rows (alternating shading).
   * headers: column names, rows: array of column-value arrays
   */
  const buildTable = (headers: string[], rows: string[][], widths?: number[]) => {
    const headerCells = headers.map((h, i) =>
      tableCell(h, { bold: true, color: 'FFFFFF', bgColor: '1F3864', size: 18, width: widths?.[i] })
    )
    const headerRow = tableRow(headerCells)

    const dataRows = rows.map((row, ri) => {
      const bg = ri % 2 === 0 ? 'F2F2F2' : 'FFFFFF'
      const cells = row.map((cell, ci) =>
        tableCell(cell, { color: '333333', bgColor: bg, size: 17, width: widths?.[ci] })
      )
      return tableRow(cells)
    })

    const tblW = widths ? widths.reduce((s, w) => s + w, 0) : 9360
    return `<w:tbl>
      <w:tblPr>
        <w:tblW w:w="${tblW}" w:type="dxa"/>
        <w:tblBorders>
          <w:top w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>
          <w:left w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>
          <w:bottom w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>
          <w:right w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>
          <w:insideH w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>
          <w:insideV w:val="single" w:sz="4" w:space="0" w:color="CCCCCC"/>
        </w:tblBorders>
        <w:tblCellMar>
          <w:top w:w="80" w:type="dxa"/>
          <w:left w:w="100" w:type="dxa"/>
          <w:bottom w:w="80" w:type="dxa"/>
          <w:right w:w="100" w:type="dxa"/>
        </w:tblCellMar>
      </w:tblPr>
      ${headerRow}${dataRows.join('')}
    </w:tbl>`
  }

  // ── Document body ──────────────────────────────────────────────────────────

  let body = ''
  body += heading('ZeroContext Incident Report')
  body += separator()
  body += normal(`Report ID: ${sanitizeForExport(report.id)}`)
  body += normal(`Timestamp: ${sanitizeForExport(report.timestamp)}`)
  body += normal(`Source File: ${sanitizeForExport(report.sourceFileName ?? 'Text input')}`)
  body += normal(`Engine Mode: ${sanitizeForExport(report.engineMode)}`)
  body += normal(`Rules Version: ${sanitizeForExport(report.rulesVersion)}`)
  body += normal(`Processing Time: ${report.processingTimeMs}ms`)
  body += normal(`Input Length: ${report.inputLength} characters`)
  body += normal(`Input SHA-256: ${sanitizeForExport(report.inputHash)}`)
  body += para(`Overall Severity: ${report.severity}`, true, sColor, 22)
  body += separator()

  // ── MAIN THREAT TABLE: Location | Category | Confidence | Excerpt | Reason ─

  body += subheading(`Threats Detected (${report.threats.length})`)
  body += para('')  // spacer

  if (report.threats.length > 0) {
    const threatRows = report.threats.map((t) => [
      t.location ?? (t.layer > 0 ? `Layer ${t.layer}` : 'Raw input'),
      t.category.replace(/_/g, ' '),
      `${(t.confidence * 100).toFixed(0)}%`,
      sanitizeForExport(t.matchedText).slice(0, 80),
      sanitizeForExport(t.reason ?? t.ruleName),
    ])
    body += buildTable(
      ['Location', 'Category', 'Confidence', 'Excerpt', 'Reason / Rule'],
      threatRows,
      [1200, 1400, 1000, 2760, 3000]
    )
  } else {
    body += normal('No threats detected.')
  }

  // ── HIDDEN TEXT TABLE ─────────────────────────────────────────────────────

  if (report.hiddenRuns && report.hiddenRuns.length > 0) {
    body += separator()
    body += subheading(`Hidden Text Findings (${report.hiddenRuns.length}) — AUTO HIGH SEVERITY`)
    body += para('')
    const REASON_LABELS: Record<string, string> = {
      vanish: 'w:vanish (explicitly hidden)', webHidden: 'w:webHidden',
      whiteColor: 'White/near-white colour', nearZeroSize: 'Near-zero font size', doubleHide: 'Double-hide trick',
    }
    const hiddenRows = report.hiddenRuns.map((r) => [
      String(r.offset),
      REASON_LABELS[r.reason] ?? r.reason,
      sanitizeForExport(r.text).slice(0, 100),
      [r.colorHex ? `#${r.colorHex}` : '', r.sizePt !== undefined ? `${r.sizePt}pt` : ''].filter(Boolean).join(', '),
    ])
    body += buildTable(['Offset', 'Detection Method', 'Hidden Text Preview', 'Properties'], hiddenRows, [900, 2200, 3560, 1500])
  }

  // ── DATA CONTRADICTION TABLE ──────────────────────────────────────────────

  if (report.dataContradictions && report.dataContradictions.length > 0) {
    body += separator()
    body += subheading(`Data Contradictions (${report.dataContradictions.length}) — HIGH WEIGHT SIGNAL`)
    body += para('')
    const contradictionRows = report.dataContradictions.map((c) => [
      sanitizeForExport(c.tableValue), sanitizeForExport(c.claimedValue),
      `${(c.confidence * 100).toFixed(0)}%`, sanitizeForExport(c.claim).slice(0, 120),
    ])
    body += buildTable(['Table Shows', 'Text Claims', 'Confidence', 'Contradicting Sentence'], contradictionRows, [1800, 1800, 900, 4860])
  }

  // ── HOMOGLYPHS TABLE ──────────────────────────────────────────────────────

  if (report.homoglyphs.length > 0) {
    body += separator()
    body += subheading(`Homoglyphs (${report.homoglyphs.length})`)
    body += para('')
    const hRows = report.homoglyphs.map((h) => [
      sanitizeForExport(h.original), sanitizeForExport(h.codepoint),
      sanitizeForExport(h.replacement), h.script, String(h.position),
    ])
    body += buildTable(['Char', 'Codepoint', 'Looks Like', 'Script', 'Position'], hRows, [600, 1200, 900, 1400, 800])
  }

  // ── AI Analysis ────────────────────────────────────────────────────────────

  if (report.aiAnalysis) {
    body += separator()
    body += subheading('AI Analysis')
    body += normal(`Model: ${sanitizeForExport(report.aiAnalysis.modelUsed)}`)
    body += normal(`Prompt Injection Score: ${(report.aiAnalysis.promptInjectionScore * 100).toFixed(1)}%`)
    body += normal(`Obfuscation Score: ${(report.aiAnalysis.obfuscationScore * 100).toFixed(1)}%`)
    body += normal(`Summary: ${sanitizeForExport(report.aiAnalysis.threatSummary)}`)
  }

  body += separator()
  body += para('Generated by ZeroContext. All payload content has been sanitized (HTML-escaped).', false, '888888', 16)

  const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
  xmlns:cx="http://schemas.microsoft.com/office/drawing/2014/chartex"
  xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"
  xmlns:o="urn:schemas-microsoft-com:office:office"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
  xmlns:v="urn:schemas-microsoft-com:vml"
  xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing"
  xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
  xmlns:w10="urn:schemas-microsoft-com:office:word"
  xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
  xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"
  xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml"
  mc:Ignorable="w14 w15 wp14">
  <w:body>${body}<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080"/></w:sectPr></w:body>
</w:document>`

  const relsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

  const wordRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`

  const contentTypesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

  const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="20"/></w:rPr></w:rPrDefault></w:docDefaults>
</w:styles>`

  return buildZip([
    { name: '[Content_Types].xml', content: contentTypesXml },
    { name: '_rels/.rels', content: relsXml },
    { name: 'word/document.xml', content: documentXml },
    { name: 'word/_rels/document.xml.rels', content: wordRelsXml },
    { name: 'word/styles.xml', content: stylesXml },
  ])
}

/** Minimal ZIP builder — produces a valid ZIP file from text entries */
function buildZip(entries: Array<{ name: string; content: string }>): Blob {
  const enc = new TextEncoder()
  const localHeaders: Uint8Array<ArrayBuffer>[] = []
  const centralDirs: Uint8Array<ArrayBuffer>[] = []
  let offset = 0

  for (const entry of entries) {
    const nameBytes = enc.encode(entry.name) as Uint8Array<ArrayBuffer>
    const dataBytes = enc.encode(entry.content) as Uint8Array<ArrayBuffer>
    const crc = crc32(dataBytes)

    // Local file header
    const lhBuf = new ArrayBuffer(30 + nameBytes.length)
    const lh = new DataView(lhBuf)
    lh.setUint32(0, 0x04034b50, true)   // signature
    lh.setUint16(4, 20, true)            // version needed
    lh.setUint16(6, 0, true)             // flags
    lh.setUint16(8, 0, true)             // compression (stored)
    lh.setUint16(10, 0, true)            // mod time
    lh.setUint16(12, 0, true)            // mod date
    lh.setUint32(14, crc, true)          // crc-32
    lh.setUint32(18, dataBytes.length, true) // compressed size
    lh.setUint32(22, dataBytes.length, true) // uncompressed size
    lh.setUint16(26, nameBytes.length, true) // file name length
    lh.setUint16(28, 0, true)            // extra field length
    const lhArr = new Uint8Array(lhBuf) as Uint8Array<ArrayBuffer>
    nameBytes.forEach((b, i) => { lhArr[30 + i] = b })

    localHeaders.push(lhArr)
    localHeaders.push(dataBytes)

    // Central directory entry
    const cdBuf = new ArrayBuffer(46 + nameBytes.length)
    const cd = new DataView(cdBuf)
    cd.setUint32(0, 0x02014b50, true)    // signature
    cd.setUint16(4, 20, true)            // version made by
    cd.setUint16(6, 20, true)            // version needed
    cd.setUint16(8, 0, true)             // flags
    cd.setUint16(10, 0, true)            // compression
    cd.setUint16(12, 0, true)            // mod time
    cd.setUint16(14, 0, true)            // mod date
    cd.setUint32(16, crc, true)          // crc-32
    cd.setUint32(20, dataBytes.length, true) // compressed size
    cd.setUint32(24, dataBytes.length, true) // uncompressed size
    cd.setUint16(28, nameBytes.length, true) // file name length
    cd.setUint16(30, 0, true)            // extra field length
    cd.setUint16(32, 0, true)            // comment length
    cd.setUint16(34, 0, true)            // disk number start
    cd.setUint16(36, 0, true)            // internal attrs
    cd.setUint32(38, 0, true)            // external attrs
    cd.setUint32(42, offset, true)       // local header offset
    const cdArr = new Uint8Array(cdBuf) as Uint8Array<ArrayBuffer>
    nameBytes.forEach((b, i) => { cdArr[46 + i] = b })

    centralDirs.push(cdArr)
    offset += lhArr.length + dataBytes.length
  }

  const cdStart = offset
  const cdSize = centralDirs.reduce((s, a) => s + a.length, 0)

  // End of central directory record
  const eocdBuf = new ArrayBuffer(22)
  const eocd = new DataView(eocdBuf)
  eocd.setUint32(0, 0x06054b50, true)   // signature
  eocd.setUint16(4, 0, true)             // disk number
  eocd.setUint16(6, 0, true)             // disk with cd
  eocd.setUint16(8, entries.length, true)
  eocd.setUint16(10, entries.length, true)
  eocd.setUint32(12, cdSize, true)
  eocd.setUint32(16, cdStart, true)
  eocd.setUint16(20, 0, true)            // comment length

  const parts: BlobPart[] = [...localHeaders, ...centralDirs, new Uint8Array(eocdBuf) as Uint8Array<ArrayBuffer>]
  return new Blob(parts, { type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' })
}

/** CRC-32 implementation (needed for ZIP) */
function crc32(data: Uint8Array): number {
  let crc = 0xFFFFFFFF
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i]
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0)
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function downloadJSON(data: unknown, filename: string) {
  const content = JSON.stringify(data, null, 2)
  downloadBlob(new Blob([content], { type: 'application/json;charset=utf-8' }), filename)
}

export const ForensicExport: React.FC<ForensicExportProps> = ({ reports }) => {
  if (reports.length === 0) return null

  const latest = reports[reports.length - 1]
  const ts = new Date(latest.timestamp).toISOString().replace(/[:.]/g, '-').slice(0, 19)

  const exportDocx = () => {
    const blob = buildDocxBlob(latest)
    downloadBlob(blob, `zerocontext-report-${ts}.docx`)
  }

  const exportJson = () => {
    const sanitized = {
      ...latest,
      threats: latest.threats.map((t) => ({
        ...t,
        matchedText: sanitizeForExport(t.matchedText),
        context: sanitizeForExport(t.context),
        ruleName: sanitizeForExport(t.ruleName),
      })),
      normalizationTrace: latest.normalizationTrace.map((l) => ({
        ...l,
        inputSnippet: sanitizeForExport(l.inputSnippet),
        outputSnippet: sanitizeForExport(l.outputSnippet),
      })),
      homoglyphs: latest.homoglyphs.map((h) => ({
        ...h,
        original: sanitizeForExport(h.original),
        replacement: sanitizeForExport(h.replacement),
      })),
      aiAnalysis: latest.aiAnalysis ? {
        ...latest.aiAnalysis,
        threatSummary: sanitizeForExport(latest.aiAnalysis.threatSummary),
      } : null,
    }
    downloadJSON(sanitized, `zerocontext-report-${ts}.json`)
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-sm mobile-export-stack"
      style={{ padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1, minWidth: 120 }}>
        <Shield size={14} color="var(--accent)" />
        <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          {reports.length} report{reports.length !== 1 ? 's' : ''} in session
        </span>
      </div>
      <button className="btn-ghost" onClick={exportDocx} style={{ fontSize: '0.78rem' }}>
        <FileText size={13} /> Export .docx
      </button>
      <button className="btn-ghost" onClick={exportJson} style={{ fontSize: '0.78rem' }}>
        <Download size={13} /> Export .json
      </button>
      <button
        className="btn-ghost"
        onClick={() => exportSandboxReplay(latest)}
        style={{ fontSize: '0.78rem', color: '#10b981', borderColor: 'rgba(16,185,129,0.3)' }}
        title="Download a self-contained offline HTML report — works air-gapped"
      >
        <Globe size={13} /> Sandbox Replay
      </button>
    </motion.div>
  )
}
