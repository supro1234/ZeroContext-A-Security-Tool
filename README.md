<div align="center">

<img src="public/favicon.svg" alt="ZeroContext" width="72" />

# ZeroContext

### The payload looks clean. It isn't.

**Client-side security payload analyzer for SOC analysts and incident responders.**  
Sub-6ms triage · Zero bytes uploaded · Works fully offline · Open Source

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/supro1234/ZeroContext)
[![TypeScript](https://img.shields.io/badge/TypeScript-6.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-8.x-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![License: Source-Available](https://img.shields.io/badge/License-Source--Available-orange.svg)](LICENSE)
[![F1 Score](https://img.shields.io/badge/F1%20Score-92.3%25-10b981)](benchmark/run.ts)

**🚀 Live Demo: [Launch ZeroContext](https://zero-context-a-security-tool-ds1ir9mug-supro1234s-projects.vercel.app/)**

</div>

---

## Why not VirusTotal?

Every major online scanner **uploads your payload to a third-party cloud** — a problem when you're triaging a live beaconing payload or working in a classified environment. ZeroContext runs entirely in your browser:

| Capability | ZeroContext | VirusTotal | Online Sandbox |
|---|---|---|---|
| Payload leaves your network | ✅ Never | ❌ Always | ❌ Always |
| Works air-gapped / offline | ✅ | ❌ | ❌ |
| DOCX hidden-text detection | ✅ w:vanish, white text | ❌ | ⚠ Partial |
| Analysis time | ✅ < 6 ms | ⚠ 2–60 s | ⚠ 60–300 s |
| Account / API key required | ✅ None | ❌ Required | ❌ Required |
| Adversarial evasion testing | ✅ 7 techniques | ❌ | ❌ |
| Explainability trace | ✅ Full decode chain | ❌ | ❌ |
| Forensic export | ✅ DOCX + JSON + Replay HTML | ⚠ CSV only | ⚠ PDF only |

---

## Case Study — Ticket-injection triage in 3 minutes

> A suspicious support ticket arrives. VT scan: 0/73. The analyst drops the `.docx` into ZeroContext.

1. **T+0** — Ticket arrives, looks clean visually. 0/73 VT engines flag it.  
2. **T+1 min** — DOCX dropped into ZeroContext. 5 ms later: `w:vanish` run detected at offset 318 (47 hidden chars).  
3. **T+1 min 20 s** — Hidden text decoded: URL-encoded XSS payload calling `evil.io`.  
4. **T+2 min** — Adversarial Mode finds 2 of 7 obfuscation permutations would evade current rules.  
5. **T+3 min** — `.docx` report + offline HTML sandbox replay attached to JIRA ticket. Escalated to IR.

---

## Features

| Feature | Detail |
|---|---|
| 🔒 **Zero Upload** | All analysis runs in a Web Worker. Untrusted payloads never leave the browser. |
| 🧅 **5-Layer Normalization** | URL → Hex → Base64 → HTML-entity → Unicode NFKC before any rule fires |
| 👁 **Hidden Text Detection** | `w:vanish`, white-on-white, near-zero font-size, and double-hide tricks in DOCX files |
| ⚡ **Adversarial Mode** | Generates 7 obfuscation permutations (double-URL, base64, homoglyph, zero-width, hex, unicode…) |
| 🔍 **Explainability Trace** | Full decode chain per finding: raw → layer N → rule matched → verdict |
| 📄 **Forensic Export** | `.docx` Word tables, `.json`, and self-contained offline HTML replay (air-gap safe) |
| 📊 **Benchmarked Accuracy** | 92.3% Precision / 92.3% Recall / 92.3% F1 on 20-case labeled dataset |
| 🌐 **Works Offline** | No network required after initial page load |

---

## Benchmarked Accuracy

Run the engine against the labeled test dataset:

```bash
npx tsx benchmark/run.ts
```

```
════════ BENCHMARK RESULTS ════════
Total Cases: 20  |  Avg: 0.7 ms / payload
-----------------------------------
True Positives:  12   True Negatives:  6
False Positives:  1   False Negatives: 1
-----------------------------------
Precision: 92.3%
Recall:    92.3%
F1 Score:  92.3%
═══════════════════════════════════
```

**Known edge cases:**
- `B-05` (URL with parameters) — generic URL rule fires on benign query strings; tunable via confidence threshold
- `M-13` (zero-width chars in script tag) — evasion technique not yet in ruleset; tracked in Adversarial Mode output

---

## Architecture

ZeroContext is intentionally split into two trust zones. **All dangerous inputs are processed in the browser's most-isolated context** — a Web Worker with no DOM access — before any data ever moves to the network.

```
╔══════════════════════════════════════════════════════════════╗
║                    USER'S BROWSER                            ║
║                                                              ║
║  ┌─────────────────────────────────────────────────────┐    ║
║  │              React + Vite (Main Thread)             │    ║
║  │                                                     │    ║
║  │  AnalyzePage.tsx ──────── spawns ──────────────┐   │    ║
║  │  LandingPage.tsx                               │   │    ║
║  │  AnalysisInput.tsx  ◀── DOCX / PDF / TXT ──┐  │   │    ║
║  │  ExplainabilityTrace.tsx                   │  │   │    ║
║  │  AdversarialMode.tsx                       │  │   │    ║
║  │  ForensicExport.tsx  ── .docx / .json / ── │  │   │    ║
║  │                         offline HTML       │  │   │    ║
║  └─────────────────────────────────────────── │ ─│───┘    ║
║                                               │  │         ║
║  ┌────────────────────────────────────────────▼──▼──────┐  ║
║  │           ⚙  Web Worker  (CPU-isolated sandbox)      │  ║
║  │                                                      │  ║
║  │  analysisWorker.ts                                   │  ║
║  │  ├── docxParser.ts    unzip + XML, w:vanish detect   │  ║
║  │  ├── pdfParser.ts     content-stream text + heuristic│  ║
║  │  ├── normalizer.ts    5-layer recursive decode        │  ║
║  │  │    Layer 0  NFKC normalization                     │  ║
║  │  │    Layer 1  URL decode  (%XX, %uXXXX)              │  ║
║  │  │    Layer 2  Hex decode  (\xNN, 0xNN chains)        │  ║
║  │  │    Layer 3  Base64 decode                          │  ║
║  │  │    Layer 4  HTML entity decode (&lt; etc.)         │  ║
║  │  ├── homoglyphDetector.ts  Unicode confusables map    │  ║
║  │  ├── ruleMatcher.ts   70+ regex rules, context score  │  ║
║  │  └── redosGuard.ts    100ms ReDoS timeout guard       │  ║
║  │                                                      │  ║
║  │  ✗  No DOM   ✗  No localStorage   ✗  No network      │  ║
║  └──────────────────────────────────────────────────────┘  ║
║                           │                                  ║
║         ① Only normalized, length-capped text               ║
║            crosses this boundary (never raw payload)        ║
║                           │                                  ║
╚═══════════════════════════│══════════════════════════════════╝
                            │  HTTPS + CSP headers
                            ▼
╔══════════════════════════════════════════════════════════════╗
║                    VERCEL EDGE                               ║
║                                                              ║
║  ┌──────────────────────┐   ┌──────────────────────────┐    ║
║  │  Static CDN          │   │  Python Serverless        │    ║
║  │  dist/  (SPA bundle) │   │  /api/analyze             │    ║
║  │  public/rules.json   │   │  ├── entropy scoring      │    ║
║  └──────────────────────┘   │  ├── YARA-like patterns   │    ║
║                             │  └── classifier.py        │    ║
║  Security headers on all    └──────────────────────────┘    ║
║  responses via vercel.json:                                  ║
║  CSP · HSTS · X-Frame-Options · COEP · COOP                 ║
╚══════════════════════════════════════════════════════════════╝
```

> **Security boundary:** The Web Worker receives the raw payload. Only a sanitized, 500-char-capped excerpt ever leaves the browser for optional AI enrichment. The raw payload is never serialised to disk, localStorage, or the network.

---

## Quick Start

### Prerequisites

- Node.js 20+
- Python 3.12+ *(optional — only needed for AI enrichment backend)*

### 1. Clone & install

```bash
git clone https://github.com/supro1234/ZeroContext.git
cd ZeroContext
npm install
```

### 2. Run (frontend only — fully functional offline)

```bash
npm run dev:frontend
```

Frontend → `http://localhost:5173`

### 3. Optional: AI enrichment backend

```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
npm run dev:backend
```

Backend → `http://localhost:8000` (proxied automatically from Vite)

### 4. Run benchmarks

```bash
npx tsx benchmark/run.ts
```

---

## Project Structure

```
ZeroContext/
│
├── 📊 benchmark/                          Accuracy evaluation suite
│   ├── sample-payloads.json               20 labeled test cases (7 benign · 13 malicious)
│   ├── run.ts                             Precision / Recall / F1 benchmark runner
│   └── tsconfig.json                      Node-specific TS config (isolated from Vite)
│
├── 🌐 public/
│   └── rules/
│       └── rules.json                     70+ detection rules (XSS · SQLi · Obfuscation …)
│
├── 🧩 src/
│   │
│   ├── components/                        UI Components
│   │   ├── AnalysisInput.tsx              File upload router — DOCX / PDF / TXT dispatch
│   │   ├── ThreatReport.tsx               Threat findings table (Location · Severity · Reason)
│   │   ├── ExplainabilityTrace.tsx        Per-finding decode chain visualizer
│   │   ├── AdversarialMode.tsx            7-technique evasion permutation tester
│   │   ├── NormalizationTrace.tsx         Layer-by-layer normalization inspector
│   │   ├── LiveFeed.tsx                   Real-time analysis event feed
│   │   └── ForensicExport.tsx             DOCX · JSON · Sandbox Replay exporter
│   │
│   ├── engine/                            ⚙  Core Analysis Engine (Web Worker safe)
│   │   ├── normalizer.ts                  5-layer recursive decoder (URL→Hex→B64→HTML→NFKC)
│   │   ├── ruleMatcher.ts                 Context-aware rule engine with gap analysis
│   │   ├── docxParser.ts                  DOCX unzip + XML parse, w:vanish detection
│   │   ├── pdfParser.ts                   PDF content-stream text + invisible-text heuristics
│   │   ├── homoglyphDetector.ts           Unicode confusable character map (Cyrillic, Greek…)
│   │   ├── redosGuard.ts                  100ms ReDoS timeout guard per regex
│   │   └── schemaValidator.ts             Rules JSON schema validator
│   │
│   ├── pages/                             Route-level pages
│   │   ├── LandingPage.tsx                SOC-analyst marketing page + Why-Not-VT table
│   │   └── AnalyzePage.tsx                Main triage interface (2-column layout)
│   │
│   ├── hooks/                             React custom hooks
│   │   ├── useWorker.ts                   Web Worker lifecycle manager
│   │   ├── useBackendStatus.ts            AI backend health poller
│   │   ├── useTheme.ts                    Dark / light mode
│   │   └── useMediaQuery.ts               Responsive breakpoint hook
│   │
│   ├── utils/
│   │   ├── sandboxReplay.ts               Air-gapped offline HTML report generator
│   │   └── escapeText.ts                  Safe export sanitization
│   │
│   ├── types/
│   │   ├── threat.ts                      IncidentReport · ThreatMatch · NormalizationLayer
│   │   └── worker.ts                      WorkerRequest · WorkerMessage types
│   │
│   └── workers/
│       └── analysisWorker.ts              Web Worker entry point — no DOM / no network
│
├── 🐍 backend/                            Optional AI enrichment (FastAPI)
│   ├── main.py                            FastAPI app entry point (local dev)
│   ├── models/
│   │   └── classifier.py                  Entropy scoring + YARA-like pattern matcher
│   ├── routers/
│   │   ├── analyze.py                     POST /analyze
│   │   └── health.py                      GET /health
│   └── schemas/request.py                 Pydantic request models
│
├── 🚀 api/
│   └── index.py                           Vercel Python serverless adapter
│
├── vercel.json                            Deployment config + CSP / HSTS security headers
├── vite.config.ts                         Vite bundler config + API proxy
├── tsconfig.json                          TypeScript config (Vite / bundler mode)
├── package.json
├── requirements.txt                       Python deps (FastAPI · uvicorn)
└── LICENSE                                MIT
```

---

## Detection Rules

Rules live in `public/rules/rules.json` and cover:

- **XSS** — Script injection, event handlers, SVG payloads, SSTI
- **SQL Injection** — UNION attacks, tautologies, comment terminators, time-based blind
- **Prompt Injection** — Jailbreaks, instruction overrides, role switching, DAN
- **Obfuscation** — Base64 (decoded-first), JSFuck, hex chains, eval chains
- **Path Traversal** — `../`, null byte, URL-encoded variants
- **Log4Shell** — `${jndi:ldap://...}` and variants

### Adding a Rule

```json
{
  "id": "CUSTOM-001",
  "name": "My Custom Rule",
  "description": "Detects...",
  "category": "XSS",
  "severity": "HIGH",
  "pattern": "your-regex-here",
  "flags": "gi",
  "metadata": { "owasp": "A03:2021", "tags": ["custom"] }
}
```

---

## Known Limitations

| Limitation | Status |
|---|---|
| Zero-width char evasion (`M-13`) | Not in ruleset — visible in Adversarial Mode output |
| Generic URL false-positive (`B-05`) | Tunable via confidence threshold; known edge case |
| PDF detection depth | Limited to content-stream text — encrypted/rasterized PDFs not analysed |
| AI backend | Optional — tool is fully functional without it |
| File size | DOCX/PDF parsing is synchronous in-browser; very large files (>10MB) may cause latency |

---

## Security

- All regex matching runs **inside a Web Worker** — isolated from the DOM
- **No raw payload ever touches the network** — only a normalized, length-capped snippet reaches the AI backend
- CSP headers set via `vercel.json`: `default-src 'self'`, no inline scripts, no external connects
- Report vulnerabilities via **GitHub Security Advisory** (not a public issue)

---

## Contributing

Team: **Lumix**

PRs welcome. Please open an issue first for major changes.

---

## License

ZeroContext is **source-available** — free to use and inspect, but redistribution or copying
of the codebase without the owner's written permission is prohibited.

See [LICENSE](LICENSE) for full terms.

> © 2025 Lumix Team · All rights reserved.
