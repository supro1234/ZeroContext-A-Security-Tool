/**
 * sandboxReplay.ts
 *
 * Generates a fully self-contained offline HTML "Sandbox Replay" export.
 *
 * The exported file:
 *   • Has ALL CSS and JS inlined — no external requests, no CDN, works air-gapped
 *   • Embeds the IncidentReport JSON directly in the HTML
 *   • Renders a complete static analysis report (normalization trace, threat table,
 *     hidden text, AI scores) using vanilla HTML/CSS — no React needed to view it
 *   • Includes the raw payload hash + timestamp in the title for forensic traceability
 *   • Is downloaded as `zerocontext-replay-<timestamp>.html`
 *
 * Security: the raw payload is NOT embedded — only the sanitized matchedText/context
 * snippets from the IncidentReport, which are already HTML-escaped before storage.
 */

import type { IncidentReport, ThreatMatch, NormalizationLayer } from '../types/threat'

// ─── Safety escaping ──────────────────────────────────────────────────────────

function escHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// ─── Severity styling ─────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308',
  LOW: '#3b82f6', INFO: '#64748b', SAFE: '#10b981',
}

function sevBadge(s: string): string {
  const c = SEV_COLOR[s] ?? '#94a3b8'
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;color:${c};background:${c}18;border:1px solid ${c}40">${escHtml(s)}</span>`
}

// ─── Threat table HTML ────────────────────────────────────────────────────────

function buildThreatTable(threats: ThreatMatch[]): string {
  if (threats.length === 0) {
    return `<div style="text-align:center;padding:32px;color:#10b981;font-size:1.1rem">✓ No threats detected</div>`
  }

  const rows = threats.map((t) => `
    <tr>
      <td>${escHtml(t.location ?? (t.layer > 0 ? `Layer ${t.layer}` : 'Raw'))}</td>
      <td><span style="color:${SEV_COLOR[t.severity]??'#94a3b8'};font-size:0.7rem">${escHtml(t.category.replace(/_/g,' '))}</span></td>
      <td>${Math.round(t.confidence * 100)}%</td>
      <td><code style="color:#fca5a5;font-size:0.72rem">${escHtml(t.matchedText.slice(0, 80))}</code></td>
      <td>${escHtml(t.reason ?? t.ruleName)} ${sevBadge(t.severity)}</td>
    </tr>`
  ).join('')

  return `
    <table>
      <thead>
        <tr>
          <th>Location</th><th>Category</th><th>Confidence</th><th>Excerpt</th><th>Reason / Rule</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`
}

// ─── Normalization trace HTML ─────────────────────────────────────────────────

function buildTraceHtml(layers: NormalizationLayer[]): string {
  if (layers.length === 0) return '<p style="color:#64748b">No normalization layers</p>'

  const TECH_COLOR: Record<string, string> = {
    raw: '#818cf8', url: '#fb923c', hex: '#fbbf24',
    base64: '#34d399', nfkc: '#38bdf8', homoglyph: '#c084fc',
  }

  return layers.map((l) => {
    const c = TECH_COLOR[l.technique] ?? '#94a3b8'
    return `
      <div class="layer">
        <span class="badge" style="color:${c};border-color:${c}40;background:${c}18">
          Layer ${l.depth} — ${l.technique.toUpperCase()}
        </span>
        ${l.changed ? `
          <div class="layer-diff">
            <code class="from">${escHtml(l.inputSnippet.slice(0, 120))}</code>
            <span class="arrow">→</span>
            <code class="to">${escHtml(l.outputSnippet.slice(0, 120))}</code>
          </div>` : `<span class="muted">no change</span>`}
      </div>`
  }).join('')
}

// ─── Hidden text section ──────────────────────────────────────────────────────

function buildHiddenHtml(report: IncidentReport): string {
  const runs = report.hiddenRuns ?? []
  if (runs.length === 0) return ''

  const rows = runs.map((r) => `
    <tr>
      <td>${r.offset}</td>
      <td style="color:#fca5a5">${escHtml(r.reason)}</td>
      <td><code style="color:#fca5a5">${escHtml(r.text.slice(0, 80))}</code></td>
      <td>${r.colorHex ? `#${escHtml(r.colorHex)}` : ''} ${r.sizePt !== undefined ? `${r.sizePt}pt` : ''}</td>
    </tr>`
  ).join('')

  return `
    <div class="section" style="border-color:#ef444440;background:rgba(239,68,68,0.04)">
      <h3 style="color:#ef4444">🚨 Hidden Text Findings (${runs.length}) — AUTO HIGH</h3>
      <table>
        <thead><tr><th>Offset</th><th>Reason</th><th>Text Preview</th><th>Properties</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`
}

// ─── AI section ───────────────────────────────────────────────────────────────

function buildAiHtml(report: IncidentReport): string {
  if (!report.aiAnalysis) return ''
  const ai = report.aiAnalysis
  const piColor = ai.promptInjectionScore > 0.7 ? '#ef4444' : ai.promptInjectionScore > 0.4 ? '#f97316' : '#10b981'
  const obColor = ai.obfuscationScore > 0.7 ? '#ef4444' : ai.obfuscationScore > 0.4 ? '#f97316' : '#10b981'
  return `
    <div class="section" style="border-color:rgba(99,102,241,0.3);background:rgba(99,102,241,0.04)">
      <h3 style="color:#818cf8">🤖 AI Analysis — ${escHtml(ai.modelUsed)}</h3>
      <div style="display:flex;gap:24px;margin-bottom:12px">
        <div><div class="label">Prompt Injection</div><div style="font-size:2rem;font-weight:700;color:${piColor};font-family:monospace">${(ai.promptInjectionScore*100).toFixed(0)}%</div></div>
        <div><div class="label">Obfuscation</div><div style="font-size:2rem;font-weight:700;color:${obColor};font-family:monospace">${(ai.obfuscationScore*100).toFixed(0)}%</div></div>
      </div>
      <p style="color:#94a3b8;font-size:0.85rem;line-height:1.6">${escHtml(ai.threatSummary)}</p>
    </div>`
}

// ─── Full HTML document ───────────────────────────────────────────────────────

function buildReplayHtml(report: IncidentReport): string {
  const ts = new Date(report.timestamp).toLocaleString()
  const sColor = SEV_COLOR[report.severity] ?? '#94a3b8'
  const threatTable = buildThreatTable(report.threats)
  const traceHtml = buildTraceHtml(report.normalizationTrace)
  const hiddenHtml = buildHiddenHtml(report)
  const aiHtml = buildAiHtml(report)

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>ZeroContext Replay — ${report.severity} — ${report.id.slice(0,8)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, 'Segoe UI', system-ui, sans-serif;
      background: #0b0e1a;
      color: #e2e8f0;
      padding: 32px 24px;
      min-height: 100vh;
      line-height: 1.6;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    .header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 32px; padding-bottom: 20px;
      border-bottom: 1px solid rgba(99,102,241,0.25);
    }
    .logo { font-size: 1.6rem; font-weight: 800; letter-spacing: -0.04em; color: #818cf8; }
    .logo span { color: #e2e8f0; }
    .badge {
      display: inline-block; padding: 3px 10px; border-radius: 5px;
      font-size: 0.72rem; font-weight: 700; border: 1px solid;
    }
    .severity-badge {
      font-size: 1rem; font-weight: 800; color: ${sColor};
      background: ${sColor}15; border: 1px solid ${sColor}40;
      padding: 6px 14px; border-radius: 6px;
    }
    .meta { display: flex; gap: 20px; flex-wrap: wrap; font-size: 0.78rem; color: #64748b; font-family: monospace; margin-bottom: 28px; }
    .meta span { display: flex; align-items: center; gap: 4px; }
    .meta span b { color: #94a3b8; }
    .section {
      background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08);
      border-radius: 12px; padding: 20px 22px; margin-bottom: 20px;
    }
    h2 { font-size: 1rem; font-weight: 700; margin-bottom: 16px; color: #c7d2fe; letter-spacing: -0.01em; }
    h3 { font-size: 0.88rem; font-weight: 700; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    th { padding: 8px 10px; text-align: left; font-size: 0.65rem; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.06em; border-bottom: 1px solid rgba(255,255,255,0.08); }
    td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.04); color: #94a3b8; vertical-align: top; }
    code { font-family: 'Cascadia Code','Fira Code',monospace; word-break: break-all; }
    .layer { display: flex; align-items: flex-start; gap: 12px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); flex-wrap: wrap; }
    .layer:last-child { border-bottom: none; }
    .layer-diff { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
    .from { font-size: 0.72rem; padding: 3px 8px; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.07); border-radius: 4px; color: #64748b; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
    .to { font-size: 0.72rem; padding: 3px 8px; background: rgba(99,102,241,0.08); border: 1px solid rgba(99,102,241,0.2); border-radius: 4px; color: #a5b4fc; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
    .arrow { color: #64748b; font-size: 0.9rem; }
    .muted { color: #475569; font-size: 0.72rem; }
    .label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.06em; color: #64748b; margin-bottom: 4px; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
    .stat { background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.07); border-radius: 10px; padding: 14px 16px; text-align: center; }
    .stat-val { font-size: 2rem; font-weight: 800; font-family: monospace; }
    .stat-lbl { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.06em; color: #64748b; margin-top: 4px; }
    .footer { margin-top: 32px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); color: #475569; font-size: 0.72rem; text-align: center; }
    @media (max-width: 640px) { .stats { grid-template-columns: 1fr 1fr; } .header { flex-direction: column; gap: 12px; } }
    @media print { body { background: white; color: black; } }
  </style>
</head>
<body>
  <div class="container">

    <!-- Header -->
    <div class="header">
      <div>
        <div class="logo">Zero<span>Context</span></div>
        <div style="font-size:0.78rem;color:#64748b;margin-top:4px">Offline Sandbox Replay — Client-Side Analysis</div>
      </div>
      <div class="severity-badge">${escHtml(report.severity)}</div>
    </div>

    <!-- Meta -->
    <div class="meta">
      <span><b>Report ID:</b> ${escHtml(report.id.slice(0,16))}…</span>
      <span><b>Analysed:</b> ${escHtml(ts)}</span>
      ${report.sourceFileName ? `<span><b>Source:</b> ${escHtml(report.sourceFileName)}</span>` : ''}
      <span><b>Engine:</b> ${escHtml(report.engineMode.toUpperCase())}</span>
      <span><b>Rules:</b> v${escHtml(report.rulesVersion)}</span>
      <span><b>Time:</b> ${report.processingTimeMs}ms</span>
      <span><b>Input:</b> ${report.inputLength} chars</span>
      <span><b>SHA-256:</b> ${escHtml(report.inputHash.slice(0, 16))}…</span>
    </div>

    <!-- Stats -->
    <div class="stats">
      <div class="stat">
        <div class="stat-val" style="color:${report.threats.length > 0 ? '#ef4444' : '#10b981'}">${report.threats.length}</div>
        <div class="stat-lbl">Threats</div>
      </div>
      <div class="stat">
        <div class="stat-val" style="color:#818cf8">${report.normalizationTrace.filter(l => l.changed).length}</div>
        <div class="stat-lbl">Encode Layers</div>
      </div>
      <div class="stat">
        <div class="stat-val" style="color:#eab308">${report.homoglyphs.length}</div>
        <div class="stat-lbl">Homoglyphs</div>
      </div>
      <div class="stat">
        <div class="stat-val" style="color:${(report.hiddenRuns?.length ?? 0) > 0 ? '#ef4444' : '#64748b'}">${report.hiddenRuns?.length ?? 0}</div>
        <div class="stat-lbl">Hidden Runs</div>
      </div>
    </div>

    <!-- Threat table -->
    <div class="section">
      <h2>⚠ Threat Findings (${report.threats.length})</h2>
      ${threatTable}
    </div>

    <!-- Hidden text -->
    ${hiddenHtml}

    <!-- Normalization trace -->
    <div class="section">
      <h2>🔍 Normalization Trace (${report.normalizationTrace.length} layers)</h2>
      ${traceHtml}
    </div>

    <!-- AI analysis -->
    ${aiHtml}

    <!-- Footer -->
    <div class="footer">
      Generated by ZeroContext · All content sanitized · No external requests were made<br/>
      This report contains no raw payload data — only sanitized analysis results.
    </div>

  </div>
</body>
</html>`
}

// ─── Export function ──────────────────────────────────────────────────────────

/**
 * Generate and trigger download of a self-contained HTML Sandbox Replay.
 * Call this from a button click handler in ForensicExport or AnalyzePage.
 */
export function exportSandboxReplay(report: IncidentReport): void {
  const html = buildReplayHtml(report)
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const ts = new Date(report.timestamp).toISOString().replace(/[:.]/g, '-').slice(0, 19)
  const a = document.createElement('a')
  a.href = url
  a.download = `zerocontext-replay-${ts}.html`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
