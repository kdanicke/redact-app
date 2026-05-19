# REDACT — Code Review: MVP → Production

**Reviewed files:** `app.py` (351 lines), `index.html` (735 lines), `requirements.txt`, `README.md`

---

## 1. File Type Support

### Problem
`extract_text_from_file` (app.py line 211) uses a hardcoded extension allowlist and rejects anything not on it. The HTML `<input accept="...">` (line 294) compounds this — a user dragging in a `.log`, `.toml`, `.kt`, `.rs`, `.sql`, or any unlisted file gets rejected despite it being perfectly valid UTF-8 text.

### Fix Applied
Removed the extension allowlist entirely. The new logic:
1. Detect structural binary formats (`.pdf`, `.docx`, `.xlsx`, `.pptx`) by extension and parse them.
2. For everything else — **any extension, or no extension** — attempt UTF-8 → UTF-8-BOM → Latin-1 → CP-1252 decode in order.
3. If all four fail, return a clear error: "likely a true binary file (image, compiled code, etc.)."
4. Added `.pptx` parser (was missing).
5. HTML `accept` attribute set to `*` (no restriction).

---

## 2. Language Coverage

### Problem
Only Python and Java have dedicated pattern groups. The Code mode `<select>` (index.html line 220) and `LANG_PRESETS` (line 401) list only Terraform, GCP, Python, Java, and Generic. JavaScript/TypeScript, Go, Ruby, C#, PHP, Shell, Rust, and SQL each appear in millions of repos and have distinct secret-exposure patterns that the "Generic" group misses.

### Fix Applied
Added eight new `CODE_CLASSIFICATIONS` entries and corresponding `CODE_PATTERNS`:

| New Group | Key patterns added |
|---|---|
| `JS_SPECIFIC` | `process.env.*`, object literal credentials, `.env` assignments, `Authorization: Bearer` headers in fetch/axios |
| `GO_SPECIFIC` | `os.Getenv`, struct literal creds, `const`/`var` secret values |
| `CS_SPECIFIC` | `<add key="...Password..." value="...">`, `connectionString=`, `appsettings.json` credential keys, `readonly const string TOKEN` |
| `PHP_SPECIFIC` | `define('API_KEY', ...)`, `$secret = '...'`, `getenv(...)`, associative array creds |
| `SHELL_SPECIFIC` | `export VAR=secret`, env-var assignment patterns, `curl -H 'Authorization: Bearer ...'` |
| `RUBY_SPECIFIC` | `RAILS_SECRET`, `ENV['KEY']`, constant assignments |
| `SQL_SPECIFIC` | credential comments `-- password=`, `PASSWORD='...'` params, `@password=N'...'` linked server params |
| `KOTLIN_SPECIFIC` | `val TOKEN = "..."`, `BuildConfig.*`, companion object constants |

HTML lang `<select>` and `LANG_PRESETS` updated to include all new languages plus cloud providers (see item 3).

---

## 3. Cloud Provider Coverage

### Problem
Every `CODE_CLASSIFICATIONS` entry and every `CODE_PATTERNS` entry (app.py lines 22–33, 71–135) is GCP-only. The sidebar preset labeled "GCP" (index.html line 404) is the only cloud option. AWS and Azure are completely absent despite being the two largest cloud providers.

### Fix Applied
Added six new `CODE_CLASSIFICATIONS` groups and corresponding patterns:

**AWS**
- `AWS_CORE` — account IDs (12-digit), ARNs, region strings
- `AWS_IAM` — IAM ARNs (user/role/group/policy), access key IDs (`AKIA…`), secret access keys
- `AWS_RES` — S3 bucket references, ECR URLs, Secrets Manager ARNs, KMS key ARNs, RDS endpoints, Lambda ARNs

**Azure**
- `AZURE_CORE` — subscription GUIDs, tenant GUIDs, full resource path URIs
- `AZURE_IAM` — client ID GUIDs, client secrets, service principal object IDs
- `AZURE_RES` — storage account names, Key Vault URLs (`*.vault.azure.net`), storage connection strings, SQL Server FQDNs, Function App URLs

GCP groups renamed to `GCP_CORE`, `GCP_IAM`, `GCP_NET`, `GCP_RES` (unchanged from original) to make the three-provider hierarchy visually clear in the sidebar.

---

## 4. Grouping Restructure

### Problem
The Code/IaC mode mixes cloud-provider identifiers (GCP) with IaC tools (Terraform) with language-specific patterns (Python, Java) into one flat list. The sidebar has no visual hierarchy distinguishing "where this runs" from "what language wrote it."

### Fix Applied
Logical restructure within the existing two-mode UI (avoids a breaking UX change):

**Code / IaC sidebar sections** (via `LANG_PRESETS` and `CLOUD_PRESETS`):

```
☁  Cloud Providers
    [ AWS ]  [ Azure ]  [ GCP ]
🔧 IaC Tools
    [ Terraform ]  [ Kubernetes* ]
⌨  Languages
    [ Python ]  [ JS/TS ]  [ Java ]  [ Go ]
    [ C# ]  [ Ruby ]  [ PHP ]  [ Shell ]  [ SQL ]
    [ All ]
```

*Kubernetes namespace/image patterns extracted from `CODE_INFRA` into a `K8S` group.

New `CATEGORY_GROUPS` map in JS defines the visual grouping and section headers rendered in the sidebar, without changing the backend data model.

---

## 5. Legend Readability

### Problem
Legend pill font is 7px (app.py CSS line 120), description is 9px at `var(--text-dim)` — approximately `#5a6a7a` on `#0a0c0f` background. This is ~2.5:1 contrast (WCAG AA requires 4.5:1 for normal text). The pill label alone gives no context without reading the tiny description.

### Fixes Applied
1. Replaced flat `legend-row` with `legend-card` — a card with a 3px colored left border matching the classification color.
2. Abbreviation pill increased from 7px → 10px.
3. Full classification name displayed at 11px/600 weight in `--text-bright`.
4. Description text increased from 9px → 10.5px with improved line height.
5. Cards use `--surface2` background for separation from the sidebar background.

```
┌╴ PHI ╶─ Protected Health Info   ← 11px, bright
│  HIPAA: patient names, DOB,      ← 10.5px, dim
│  MRN, NPI, DEA, diagnosis
└──────────────────────────────────
```

---

## 6. Sensitive Data Coverage

### Missing categories identified and added:

#### Government IDs → new `GOV` classification (general mode)
| Pattern | Regex approach |
|---|---|
| Passport number | Contextual: `passport\s*[:#]\s*[A-Z0-9]{6,9}` |
| Driver's license | Contextual: `d\.?l\./driver's lic\s*[:#]\s*[A-Za-z0-9]{4,20}` |
| EIN | `\b\d{2}-\d{7}\b` with context keyword |
| ITIN | `\b9\d{2}[-\s][7-9]\d[-\s]\d{4}\b` |
| NHS number (UK) | Contextual: `nhs.*\d{3}\s\d{3}\s\d{4}` |
| NI number (UK) | `[A-Z]{2}\d{6}[A-D]` with context |
| VIN | Contextual: `vin[:#]\s*[A-HJ-NPR-Z0-9]{17}` |

#### Financial Identifiers → new `FIN` classification (general mode)
| Pattern | Regex approach |
|---|---|
| IBAN | `[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,}` |
| SWIFT / BIC | Contextual: `swift\|bic\s*[:#]\s*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2,5}` |
| ABA routing number | Contextual: `routing\|aba\|rtn\s*[:#]\s*\d{9}` |
| Wire transfer ref | Contextual label match |

#### Service Tokens (added to `RST` general mode)
| Service | Pattern |
|---|---|
| GitHub PAT | `ghp_`, `ghs_`, `gho_`, `ghu_`, `github_pat_` prefixes |
| Slack token | `xox[baprs]-` prefix |
| Stripe | `sk_live_`, `pk_live_`, `rk_live_` |
| Twilio SID | `AC[a-f0-9]{32}` |
| SendGrid | `SG.[22-char].[43-char]` |
| HashiCorp Vault | `hvs.[90+ chars]` |
| Google OAuth | `ya29.[alphanum]` |
| NPM token | `npm_[36 chars]` |
| JWT | `ey[header].[payload].[sig]` three-part base64url |

#### Geolocation (added to `DID`)
- GPS coordinates: `lat/lng/lon\s*[=:]\s*-?\d{1,3}\.\d{4,}` — contextual to avoid catching unrelated decimals.

#### Previously overlooked `RST` items
- Base64-encoded private key blobs (already present but improved regex)
- SSH public keys: `ssh-rsa AAAA...` / `ssh-ed25519 AAAA...`
- `-----BEGIN CERTIFICATE-----` blocks (not just private keys)

---

## 7. Additional Production-Ready Improvements

### 7a. Security Headers (implemented)
No security headers were set. Added `@app.after_request` middleware:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; ...
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

### 7b. Input Size Validation (implemented)
`/api/redact` accepted unlimited JSON text. `MAX_CONTENT_LENGTH` only applies to file uploads (multipart). Added explicit check: reject `text` payloads > 2 MB with a 413 error.

### 7c. MIME / Magic-Byte Validation (implemented)
Previously the PDF/DOCX/XLSX parsers could be fed garbage data. Added magic-byte checks before attempting parse:
- PDF: starts with `%PDF`
- DOCX/XLSX/PPTX: valid ZIP magic bytes `PK\x03\x04`

### 7d. Dependency Pinning (implemented)
`requirements.txt` changed from `flask>=3.0.0` to pinned versions with hashes for reproducible installs. Added optional `pdfminer.six` with clear comment.

### 7e. Dockerfile (new file)
Added multi-stage `Dockerfile` using `python:3.12-slim`. Runs as non-root user `appuser`. Exposes port 5000.

### 7f. Pattern False-Positive Tuning (partially implemented)
Several patterns were over-broad:
- `ZIP_CODE` (`\b\d{5}\b`) — now requires preceding comma/space + state abbreviation or "zip"/"postal" keyword to avoid matching port numbers, IDs, years, etc.
- `DATE` — version number strings like `3.12.0` are common false positives; added negative lookahead for `\d+\.\d+\.\d+` (semver).
- `TICKET_NO` — overly broad; tightened to require known prefix formats (JIRA-style `[A-Z]+-\d+` or "TICKET-#").

### 7g. XSS Hardening (implemented)
`renderOutput` in the JS used `.innerHTML` with `data-original` coming from server. Server-side output now HTML-entity escapes the `original` field before returning it in JSON. The client `esc()` function is also applied consistently.

### 7h. Test Suite (new file: `tests/test_patterns.py`)
Added `pytest` test cases covering:
- Each `GENERAL_PATTERNS` entry with a true-positive and a true-negative example
- File extraction for each supported format
- API endpoint smoke tests
- Overlap/deduplication logic

### 7i. `.gitignore` and `.dockerignore` (new files)
Prevent accidental commit of `__pycache__`, `.env`, `*.log`, `uploads/`.

### 7j. README Improvements
- Proper installation section with Python version requirement
- Docker quick-start
- Full detection table updated with all new pattern groups
- Known limitations section (semver false positives, non-English document support)
- Contributing guidelines stub

---

## Line-by-line Critical Fixes

| Location | Issue | Fix |
|---|---|---|
| app.py:211 | Extension allowlist rejects valid files | Removed; fallback UTF-8 decode |
| app.py:286 | Returns "Unsupported file type" for any unlisted ext | Removed; try decode first |
| app.py:162 | `mode == "code"` else falls through to general | Added `"both"` mode reserved for future |
| app.py:300 | `/api/redact` JSON payload size unchecked | Added 2 MB guard |
| index.html:120 | Legend pill 7px — below WCAG contrast minimum | Increased to 10px, added full name |
| index.html:219–226 | Lang select only shows GCP + 2 languages | Expanded to all 10+ languages + 3 clouds |
| index.html:294 | `accept=".txt,.py,..."` blocks valid files | Changed to `accept="*"` |
| index.html:679 | `CLASSIFICATIONS[cls]` misses code-mode classes | Fixed: JS now loads both dicts into one lookup |
| requirements.txt | Single unpinned dep | Pinned with extras; added dev deps |
