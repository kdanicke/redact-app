# REDACT — Sensitive Data Scrubber

A 100% local web app to detect and redact sensitive data from text and files before sharing externally or pasting into AI chats.

> **Privacy first.** No data leaves your machine. No internet connection.. No logging, no telemetry.

---

## What it detects

### General Mode (prose, documents, emails)

| Classification | Examples |
|---|---|
| **PHI** — Protected Health Info | Patient name, DOB, MRN, NPI, DEA number, ICD-10 diagnosis |
| **PCI** — Payment Card | Card number, CVV, expiry date |
| **PII** — Personal Info | Email, phone, address, date, ZIP code (contextual) |
| **RST** — Restricted / Secrets | SSN, API keys, private keys, GitHub/Slack/Stripe/Twilio/SendGrid tokens, JWT, SSH public keys, TLS certificates |
| **FIN** — Financial IDs | IBAN, SWIFT/BIC, ABA routing number, wire transfer reference |
| **GOV** — Government IDs | Passport, driver's license, EIN, ITIN, NHS number, NI number (UK), VIN |
| **DID** — Device / Network | IPv4, IPv6, MAC address, GPS coordinates, serial number |
| **CTRO** — Controlled Internal | Service account names, infra identifiers |
| **INT** — Internal Reference | Account numbers, project IDs, JIRA-style ticket numbers |
| **CUSTOM** | Any names, phrases, or domains you specify |

### Code / IaC Mode (source code, config, IaC)

| Classification | Examples |
|---|---|
| **AWS** — Core | Account IDs, ARNs, regions |
| **AWS-IAM** | IAM ARNs, access key IDs, secret access keys |
| **AWS-RES** | S3 buckets, ECR URLs, Secrets Manager, KMS, RDS endpoints, Lambda ARNs |
| **AZ** — Core | Subscription GUIDs, tenant GUIDs, resource path URIs |
| **AZ-IAM** | Client IDs, client secrets, service principal IDs |
| **AZ-RES** | Storage accounts, Key Vault URLs, SQL Server FQDNs, connection strings |
| **GCP** — Core | Project IDs, org IDs, folder IDs |
| **GCP-IAM** | Service accounts, workload identity, IAM members |
| **GCP-NET** | VPCs, subnets, CIDRs, DNS zones |
| **GCP-RES** | Buckets, Artifact Registry, KMS, Secret Manager, Cloud SQL, Cloud Run URLs |
| **TF** — Terraform | Backend config, provider credentials, workspace names |
| **TF-SEC** | HCL variable defaults, hardcoded locals values |
| **K8S** — Kubernetes | Namespaces, private registry images, internal service hostnames, secret refs |
| **CRED** — Code Credentials | Hardcoded API keys, tokens, passwords in any language |
| **CONN** — Connection Strings | DB URLs, JDBC, DSNs (Postgres, MySQL, Redis, MongoDB, Cassandra…) |
| **PY** — Python | `os.environ`, `os.getenv` defaults, Django `SECRET_KEY`, settings vars |
| **JS** — JavaScript / TypeScript | `process.env`, object literal creds, `.env` assignments, `Authorization` headers |
| **JAVA** — Java / Kotlin | Properties files, Spring config, JDBC, `@Value`, companion object constants |
| **GO** — Go | `os.Getenv`, struct literal creds, `const`/`var` secret values |
| **C#** — C# / .NET | `<add key>` XML, `connectionString`, `appsettings.json` keys |
| **PHP** | `define()` constants, `$var` credentials, `getenv()`, array config |
| **SH** — Shell / Bash | `export VAR=`, env assignments, `curl -H Authorization: Bearer` |
| **RB** — Ruby | `ENV[]`, `config.secret_key_base`, constant credentials |
| **SQL** | Credential comments, `PASSWORD=` params, linked server credentials |

---

## Setup

**Requirements:** Python 3.10+

```bash
# 1. Clone the repo
git clone https://github.com/your-org/redact.git
cd redact

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Enable PDF support
pip install pdfminer.six

# 4. Run
python app.py

# 5. Open http://localhost:5000
```

### Docker

```bash
# Build
docker build -t redact .

# Run (port 5000)
docker run -p 5000:5000 redact

# Run on a different port
docker run -p 8080:8080 -e PORT=8080 redact
```

---

## Usage

1. **Paste** text into the left panel, or click **Upload** to load any file
2. Switch between **General** (prose/docs) and **Code / IaC** (source code) modes
3. In Code mode, use the **Quick Presets** to filter by cloud provider or language
4. **Toggle** individual detection groups on/off in the sidebar
5. Add **Custom Terms** (names, org names, project codenames) in the sidebar
6. Press **Redact ⏎** or use Ctrl+Enter — output appears in the right panel
7. **Copy** or **Download** the redacted output

### Supported file types

Any UTF-8 or Latin-1 text file is accepted regardless of extension (`.py`, `.go`, `.tf`, `.env`, `.log`, `.toml`, `.rs`, `.sql`, `.kt`, `.swift`, config files with no extension, etc.).

Structured binary formats with dedicated parsers:

| Format | Notes |
|---|---|
| PDF | Requires `pip install pdfminer.six` |
| DOCX | Built-in (no extra dependency) |
| XLSX / XLS | Built-in — scans all sheets |
| PPTX | Built-in — scans all slides |

---

## Known Limitations

- **Date false positives** — The `DATE` pattern can match version strings like `3.12.0`. Turn it off if scanning code-heavy content in General mode.
- **ZIP code** — Requires contextual "zip" / "postal" keyword; bare 5-digit numbers are not flagged.
- **Non-English documents** — PHI and PII patterns are tuned for English field labels. Multilingual documents may have lower recall.
- **Scanned PDFs** — Image-based PDFs (no embedded text layer) return no content. Use OCR tooling first.
- **Large files** — Text payloads over 2 MB are rejected. Split very large files before scanning.

---

## Tips

- Use **Custom Terms** for people's names, department names, project codenames, and internal hostnames.
- In Code mode, pick the language/cloud **preset** that matches your file — this filters patterns to the most relevant groups and reduces false positives.
- The **hover tooltip** on any redacted tag shows the original value, so you can verify what was caught.
- You can turn off the **Date** group in General mode if dates aren't sensitive in your context.
- For Terraform state files, use Code mode with the Terraform preset.

---

## Project structure

```
redact/
├── app.py                       # Flask app — patterns, redaction engine, API routes
├── requirements.txt
├── Dockerfile
├── README.md
├── .gitignore
├── extraction/                  # File extraction module
│   ├── __init__.py              # Re-exports extract_text_from_file
│   ├── extractors.py            # PDF, DOCX, XLSX, PPTX, and text fallback logic
│   └── static/
│       └── index.html           # Single-page frontend (served by Flask)
└── tests/
    └── test_patterns.py         # pytest suite — patterns, extraction, API endpoints
```

---

## Contributing

Pull requests welcome. When adding patterns:

1. Add the regex to the appropriate list in `app.py` with a true-positive and true-negative test case comment.
2. Assign it to an existing classification or propose a new one with justification.
3. Test for false-positive rate on sample public code before submitting.
