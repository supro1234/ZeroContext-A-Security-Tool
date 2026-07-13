<div align="center">

<img src="public/favicon.svg" alt="ZeroContext" width="72" />

# ZeroContext

**Client-side threat detection engine. Zero server exposure. Sub-5ms analysis.**

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/YOUR_USERNAME/ZeroContext)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Vite](https://img.shields.io/badge/Vite-8.x-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## What is ZeroContext?

ZeroContext is a real-time, **client-side** payload analysis tool designed for security engineers, CTF players, and developers who need to inspect potentially malicious payloads without sending them to an untrusted server.

> **Zero trust by design** — all regex matching and normalization runs inside a Web Worker. Untrusted payloads never touch a third-party server.

---

## Features

| Feature | Detail |
|---|---|
|  **5-Layer Normalization** | URL → Hex → Base64 → HTML-entity → Unicode NFKC, recursively up to depth 5 |
|  **70+ Detection Rules** | XSS, SQLi, SSTI, Prompt Injection, Obfuscation, Path Traversal, Log4Shell |
|  **Context-Aware Scoring** | Gap analysis, prose detection, multi-signal confidence — eliminates false positives |
|  **AI Enrichment** | FastAPI backend adds entropy scoring, malware signatures, YARA-like pattern matching |
|  **File Upload** | Paste text or upload PDF, PNG, DOCX — client-side extraction, no server upload |
|  **Forensic Export** | Download structured `.docx` or `.json` incident reports |
|  **Full-Stack Vercel** | Frontend (Vite) + Backend (FastAPI serverless) on a single Vercel deployment |

---

## Architecture

```
Browser                        Vercel Edge
┌────────────────────────┐     ┌──────────────────────────────┐
│  React + Vite (SPA)    │     │  Static Assets (dist/)       │
│                        │────▶│  /api/* → Python Serverless  │
│  Web Worker            │     │  Security Headers (CSP/HSTS) │
│  ├─ normalizer.ts      │     └──────────────────────────────┘
│  ├─ ruleMatcher.ts     │
│  └─ homoglyphDetector  │     No raw payloads leave browser
│                        │     AI call sends normalized text only
│  ForensicExport.tsx    │
│  (OOXML ZIP builder)   │
└────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Node.js 20+
- Python 3.12+
- Git

### 1. Clone & install

```bash
git clone https://github.com/YOUR_USERNAME/ZeroContext.git
cd ZeroContext
npm install
```

### 2. Python backend

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run (full-stack)

```bash
npm run dev
```

This starts:
- **Frontend** → `http://localhost:5173`
- **Backend** → `http://localhost:8000`

The Vite dev proxy forwards `/api/*` → `http://localhost:8000/*` automatically.


## Security

### Client-Side Guarantees

- All regex matching and normalization run **inside a Web Worker** — isolated from the DOM
- **No raw payload is ever sent to the network** — only a normalized, length-capped snippet reaches the AI backend
- Worker has **no DOM or network access** by design

### Response Headers (Production)

Set by `vercel.json` on every response:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'self'` — no inline scripts, no external connects |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` |
| `X-Frame-Options` | `DENY` — clickjacking prevention |
| `X-Content-Type-Options` | `nosniff` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Permissions-Policy` | Camera, mic, geolocation, payment all disabled |

### Reporting a Vulnerability

Please open a **GitHub Security Advisory** (not a public issue) for any discovered vulnerabilities.

---

## Project Structure

```
ZeroContext/
├── api/
│   └── index.py              # Vercel Python serverless (FastAPI)
├── backend/
│   ├── main.py               # Local FastAPI entry point
│   ├── models/
│   │   └── classifier.py     # AI threat classifier
│   ├── routers/
│   │   ├── analyze.py        # POST /analyze
│   │   ├── health.py         # GET /health
│   │   └── rules.py          # GET /rules/version
│   └── schemas/
│       └── request.py        # Pydantic models
├── public/
│   └── rules/
│       └── rules.json        # 70+ detection rules (JSON)
├── src/
│   ├── components/           # React UI components
│   ├── engine/
│   │   ├── normalizer.ts     # 5-layer decoder
│   │   ├── ruleMatcher.ts    # Context-aware rule engine
│   │   └── redosGuard.ts     # ReDoS timeout guard
│   ├── pages/
│   │   ├── LandingPage.tsx   # Hero / marketing page
│   │   └── AnalyzePage.tsx   # Main analysis interface
│   ├── hooks/
│   │   ├── useWorker.ts      # Web Worker interface
│   │   └── useBackendStatus.ts
│   └── workers/
│       └── analysisWorker.ts # Web Worker entry point
├── vercel.json               # Deployment + security headers
├── requirements.txt          # Python deps for Vercel
├── vite.config.ts
└── package.json
```

---

## Detection Rules

Rules are defined in `public/rules/rules.json` and cover:

- **XSS** — Script injection, event handlers, SVG payloads, template injection (SSTI)
- **SQL Injection** — Comment terminators, UNION attacks, tautologies, time-based blind
- **Prompt Injection** — Jailbreaks, instruction overrides, role switching, DAN patterns
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

## Contributing

Team : Lumix

---

## License

MIT — see [LICENSE](LICENSE).

