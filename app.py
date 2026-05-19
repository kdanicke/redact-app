from flask import Flask, request, jsonify, send_from_directory
from extraction import extract_text_from_file
import re, os

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "extraction", "static")
app = Flask(__name__, static_folder=_STATIC_DIR)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit
MAX_TEXT_BYTES = 2 * 1024 * 1024  # 2 MB text payload limit

# ─────────────────────────────────────────────────────────────────────────────
# Security headers
# ─────────────────────────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]          = "DENY"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Referrer-Policy"]          = "no-referrer"
    response.headers["Permissions-Policy"]       = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"]  = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response

# ─────────────────────────────────────────────────────────────────────────────
# General classifications  (prose / document mode)
# ─────────────────────────────────────────────────────────────────────────────
CLASSIFICATIONS = {
    "PHI":    {"id":"PHI",    "name":"Protected Health Info",   "abbr":"PHI",    "color":"#E53935","text_color":"#fff","description":"HIPAA-protected: patient names, DOB, MRN, NPI, DEA, diagnosis codes"},
    "PCI":    {"id":"PCI",    "name":"Payment Card Industry",   "abbr":"PCI",    "color":"#FF6D00","text_color":"#fff","description":"PCI-DSS: card numbers, CVV, card expiry dates"},
    "PII":    {"id":"PII",    "name":"Personal Info (PII)",     "abbr":"PII",    "color":"#F9A825","text_color":"#000","description":"Regulated personal data: email, phone, address, ZIP, dates of birth"},
    "RST":    {"id":"RST",    "name":"Restricted / Secrets",    "abbr":"RST",    "color":"#6A1B9A","text_color":"#fff","description":"Highest sensitivity: SSN, API keys, tokens, private keys, service credentials"},
    "FIN":    {"id":"FIN",    "name":"Financial Identifiers",   "abbr":"FIN",    "color":"#00838F","text_color":"#fff","description":"IBAN, SWIFT/BIC, ABA routing numbers, wire transfer references"},
    "GOV":    {"id":"GOV",    "name":"Government IDs",          "abbr":"GOV",    "color":"#37474F","text_color":"#fff","description":"Passport, driver's license, EIN, ITIN, NHS, NI numbers, VIN"},
    "DID":    {"id":"DID",    "name":"Device / Network IDs",    "abbr":"DID",    "color":"#00897B","text_color":"#fff","description":"Re-identification risk: IPs, MACs, GPS coords, device serials"},
    "CTRO":   {"id":"CTRO",   "name":"Controlled Internal",     "abbr":"CTRO",   "color":"#1565C0","text_color":"#fff","description":"Controlled non-public: service accounts, infra identifiers"},
    "INT":    {"id":"INT",    "name":"Internal Reference",      "abbr":"INT",    "color":"#546E7A","text_color":"#fff","description":"Internal-use: project IDs, account numbers, ticket references"},
    "CUSTOM": {"id":"CUSTOM", "name":"Custom Term",             "abbr":"CUST",   "color":"#558B2F","text_color":"#fff","description":"User-defined custom terms and phrases"},
}

# ─────────────────────────────────────────────────────────────────────────────
# Code / IaC classifications
# ─────────────────────────────────────────────────────────────────────────────
CODE_CLASSIFICATIONS = {
    # ── AWS ───────────────────────────────────────────────────────────────────
    "AWS_CORE":      {"id":"AWS_CORE",  "name":"AWS Core Identifiers", "abbr":"AWS",     "color":"#FF9900","text_color":"#000","description":"Account IDs, ARNs, region strings"},
    "AWS_IAM":       {"id":"AWS_IAM",   "name":"AWS IAM / Identity",   "abbr":"AWS-IAM", "color":"#D93025","text_color":"#fff","description":"IAM ARNs, access key IDs, secret access keys, role names"},
    "AWS_RES":       {"id":"AWS_RES",   "name":"AWS Resource Names",   "abbr":"AWS-RES", "color":"#E37400","text_color":"#fff","description":"S3 buckets, ECR URLs, Secrets Manager, KMS, RDS, Lambda ARNs"},
    # ── Azure ──────────────────────────────────────────────────────────────────
    "AZURE_CORE":    {"id":"AZURE_CORE","name":"Azure Core Identifiers","abbr":"AZ",      "color":"#0078D4","text_color":"#fff","description":"Subscription GUIDs, tenant GUIDs, full resource path URIs"},
    "AZURE_IAM":     {"id":"AZURE_IAM", "name":"Azure IAM / Identity", "abbr":"AZ-IAM",  "color":"#005A9E","text_color":"#fff","description":"Client IDs, client secrets, service principal object IDs"},
    "AZURE_RES":     {"id":"AZURE_RES", "name":"Azure Resource Names", "abbr":"AZ-RES",  "color":"#0063B1","text_color":"#fff","description":"Storage accounts, Key Vault URLs, SQL Server FQDNs, Function App URLs"},
    # ── GCP ───────────────────────────────────────────────────────────────────
    "GCP_CORE":      {"id":"GCP_CORE",  "name":"GCP Core Identifiers", "abbr":"GCP",     "color":"#1A73E8","text_color":"#fff","description":"Project IDs, org IDs, folder IDs, numeric resource IDs"},
    "GCP_IAM":       {"id":"GCP_IAM",   "name":"GCP IAM / Identity",   "abbr":"GCP-IAM", "color":"#D93025","text_color":"#fff","description":"Service accounts, GSAs, workload identity, IAM members"},
    "GCP_NET":       {"id":"GCP_NET",   "name":"GCP Network Resources","abbr":"GCP-NET", "color":"#E37400","text_color":"#fff","description":"VPCs, subnets, CIDRs, PSC attachments, forwarding rules"},
    "GCP_RES":       {"id":"GCP_RES",   "name":"GCP Resource Names",   "abbr":"GCP-RES", "color":"#1E8E3E","text_color":"#fff","description":"Buckets, Artifact Registry, KMS, Secret Manager, Cloud SQL"},
    # ── IaC ───────────────────────────────────────────────────────────────────
    "TF_CORE":       {"id":"TF_CORE",   "name":"Terraform Config",     "abbr":"TF",      "color":"#7B42BC","text_color":"#fff","description":"Backend bucket/prefix, provider credentials, workspace names"},
    "TF_VALS":       {"id":"TF_VALS",   "name":"Terraform Secret Values","abbr":"TF-SEC","color":"#C62828","text_color":"#fff","description":"HCL variable defaults, locals blocks with hardcoded values"},
    "K8S":           {"id":"K8S",       "name":"Kubernetes Resources",  "abbr":"K8S",     "color":"#326CE5","text_color":"#fff","description":"Namespaces, private registry images, internal service hostnames"},
    # ── Generic code ──────────────────────────────────────────────────────────
    "CODE_CRED":     {"id":"CODE_CRED", "name":"Code Credentials",     "abbr":"CRED",    "color":"#6A1B9A","text_color":"#fff","description":"Hardcoded secrets, API keys, tokens in any source code"},
    "CODE_CONN":     {"id":"CODE_CONN", "name":"Connection Strings",   "abbr":"CONN",    "color":"#00695C","text_color":"#fff","description":"DB URLs, JDBC, DSNs, Redis/Mongo/Postgres/MySQL URIs"},
    # ── Languages ─────────────────────────────────────────────────────────────
    "PY_SPECIFIC":   {"id":"PY_SPECIFIC",  "name":"Python Patterns",       "abbr":"PY",   "color":"#0277BD","text_color":"#fff","description":"os.environ, Django/Flask settings, config values, getenv defaults"},
    "JS_SPECIFIC":   {"id":"JS_SPECIFIC",  "name":"JavaScript / TypeScript","abbr":"JS",  "color":"#F7DF1E","text_color":"#000","description":"process.env, object literal creds, .env assignments, fetch auth headers"},
    "JAVA_SPECIFIC": {"id":"JAVA_SPECIFIC","name":"Java / Kotlin Patterns", "abbr":"JAVA","color":"#BF360C","text_color":"#fff","description":"Properties files, Spring config, JDBC URLs, annotations, companion objects"},
    "GO_SPECIFIC":   {"id":"GO_SPECIFIC",  "name":"Go Patterns",            "abbr":"GO",  "color":"#00ACD7","text_color":"#fff","description":"os.Getenv, struct literal credentials, const/var secret values"},
    "CS_SPECIFIC":   {"id":"CS_SPECIFIC",  "name":"C# / .NET Patterns",     "abbr":"C#",  "color":"#68217A","text_color":"#fff","description":"App settings XML, connectionString, appsettings.json, const string secrets"},
    "PHP_SPECIFIC":  {"id":"PHP_SPECIFIC", "name":"PHP Patterns",           "abbr":"PHP", "color":"#777BB4","text_color":"#fff","description":"define() constants, $var credentials, getenv(), array config values"},
    "SHELL_SPECIFIC":{"id":"SHELL_SPECIFIC","name":"Shell / Bash Patterns",  "abbr":"SH",  "color":"#4CAF50","text_color":"#fff","description":"export VAR=secret, env assignments, curl Authorization headers"},
    "RUBY_SPECIFIC": {"id":"RUBY_SPECIFIC","name":"Ruby Patterns",          "abbr":"RB",  "color":"#CC342D","text_color":"#fff","description":"Rails secret_key_base, ENV[], constant credential assignments"},
    "SQL_SPECIFIC":  {"id":"SQL_SPECIFIC", "name":"SQL Patterns",           "abbr":"SQL", "color":"#F57C00","text_color":"#fff","description":"Credential comments, PASSWORD= params, linked server credentials"},
}

# ─────────────────────────────────────────────────────────────────────────────
# General patterns  (prose / document mode)
# ─────────────────────────────────────────────────────────────────────────────
GENERAL_PATTERNS = [
    # ── PHI ───────────────────────────────────────────────────────────────────
    ("MRN",           re.compile(r'\b(?:mrn|patient\s*(?:id|name)|pt\s*(?:id|name))\s*[:#\-]?\s*([A-Za-z0-9][\w\s\-\.]{1,40}?)(?=\s*[,;\n]|$)', re.I), 1, "PHI"),
    ("NPI",           re.compile(r'\b(?:npi)\s*[:#]?\s*(\d{10})\b', re.I), 1, "PHI"),
    ("DEA",           re.compile(r'\b[A-Z]{2}\d{7}\b'), None, "PHI"),
    ("DOB",           re.compile(r'\b(?:dob|date\s+of\s+birth|birth\s*date)\s*[:#\-]?\s*(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})', re.I), 1, "PHI"),
    ("DIAGNOSIS",     re.compile(r'\b(?:diagnosis|dx|condition|icd[_\-]?(?:10|9)?[_\-]?(?:code)?)\s*[:#\-]?\s*([A-Za-z0-9][\w\s\-\.]{2,60}?)(?=\s*[,;\n]|$)', re.I), 1, "PHI"),
    # ── PCI ───────────────────────────────────────────────────────────────────
    ("CREDIT_CARD",   re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|[0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{4}[\s\-][0-9]{4})\b'), None, "PCI"),
    ("CVV",           re.compile(r'\b(?:cvv|cvv2|cvc|cvc2|security\s+code)\s*[:#\-]?\s*(\d{3,4})\b', re.I), 1, "PCI"),
    ("CARD_EXPIRY",   re.compile(r'\b(?:exp(?:ir(?:y|ation))?(?:\s+date)?|valid\s+thru)\s*[:#\-]?\s*(\d{2}[\/\-]\d{2,4})\b', re.I), 1, "PCI"),
    # ── RST — credentials & tokens ────────────────────────────────────────────
    ("SSN",           re.compile(r'\b(?!000|666)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), None, "RST"),
    ("AWS_KEY",       re.compile(r'\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b'), None, "RST"),
    ("GITHUB_TOKEN",  re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{82,}\b'), None, "RST"),
    ("SLACK_TOKEN",   re.compile(r'\bxox[baprs]-[0-9A-Za-z]+-[0-9A-Za-z\-]+\b'), None, "RST"),
    ("STRIPE_KEY",    re.compile(r'\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b'), None, "RST"),
    ("TWILIO_SID",    re.compile(r'\bAC[a-f0-9]{32}\b'), None, "RST"),
    ("SENDGRID_KEY",  re.compile(r'\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}\b'), None, "RST"),
    ("VAULT_TOKEN",   re.compile(r'\bhvs\.[A-Za-z0-9_\-]{90,}\b'), None, "RST"),
    ("GOOGLE_OAUTH",  re.compile(r'\bya29\.[A-Za-z0-9\-_]{10,}\b'), None, "RST"),
    ("NPM_TOKEN",     re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'), None, "RST"),
    ("JWT_TOKEN",     re.compile(r'\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'), None, "RST"),
    ("SSH_PUBKEY",    re.compile(r'\bssh-(?:rsa|ed25519|ecdsa|dss)\s+AAAA[A-Za-z0-9+/]{30,}'), None, "RST"),
    ("CERT_BLOCK",    re.compile(r'-----BEGIN\s+CERTIFICATE-----[\s\S]*?-----END\s+CERTIFICATE-----', re.I), None, "RST"),
    ("PRIVATE_KEY",   re.compile(r'-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----', re.I), None, "RST"),
    ("API_KEY",       re.compile(r'(?:api[_\-]?key|auth[_\-]?token|access[_\-]?token|bearer|secret|password|passwd|pwd)\s*(?:[=:"\'\s]+)\s*([^\s"\',;]{8,})', re.I), 1, "RST"),
    ("URL_CRED",      re.compile(r'https?://[^:@\s]+:[^@\s]+@[^\s]+'), None, "RST"),
    # ── FIN ───────────────────────────────────────────────────────────────────
    ("IBAN",          re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,15}[A-Z0-9]{0,3}\b'), None, "FIN"),
    ("SWIFT_BIC",     re.compile(r'\b(?:swift|bic)\s*[:#]?\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b', re.I), 1, "FIN"),
    ("ABA_ROUTING",   re.compile(r'\b(?:routing|aba|rtn)\s*[:#\-]?\s*(\d{9})\b', re.I), 1, "FIN"),
    ("WIRE_REF",      re.compile(r'\b(?:wire\s+transfer|wire\s+ref(?:erence)?|imad|fed\s*wire)\s*[:#]?\s*([A-Z0-9]{8,25})\b', re.I), 1, "FIN"),
    # ── GOV ───────────────────────────────────────────────────────────────────
    ("PASSPORT",      re.compile(r'\b(?:passport|travel\s+doc(?:ument)?)\s*[:#\-]?\s*([A-Z0-9]{6,9})\b', re.I), 1, "GOV"),
    ("DRIVERS_LIC",   re.compile(r"\b(?:d\.?l\.?|driver'?s?\s+lic(?:ense)?|driving\s+lic(?:ence)?)\s*[:#\-]?\s*([A-Za-z0-9]{5,20})\b", re.I), 1, "GOV"),
    ("EIN",           re.compile(r'\b(?:ein|employer\s+id(?:entification)?(?:\s+number)?|tax\s+id)\s*[:#\-]?\s*(\d{2}-\d{7})\b', re.I), 1, "GOV"),
    ("ITIN",          re.compile(r'\b9\d{2}[-\s]?[7-9]\d[-\s]?\d{4}\b'), None, "GOV"),
    ("NHS_NUMBER",    re.compile(r'\b(?:nhs\s*(?:number|no\.?|#|:))?\s*(\d{3}\s\d{3}\s\d{4})\b', re.I), 1, "GOV"),
    ("NI_NUMBER",     re.compile(r'\b(?:ni|national\s+insurance)\s*[:#]?\s*([A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D])\b', re.I), 1, "GOV"),
    ("VIN",           re.compile(r'\b(?:vin|vehicle\s+id(?:entification)?(?:\s+number)?)\s*[:#\-]?\s*([A-HJ-NPR-Z0-9]{17})\b', re.I), 1, "GOV"),
    # ── PII ───────────────────────────────────────────────────────────────────
    ("EMAIL",         re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), None, "PII"),
    ("PHONE",         re.compile(r'\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b'), None, "PII"),
    ("ZIP_CODE",      re.compile(r'\b(?:zip|postal)\s*(?:code)?\s*[:#\-]?\s*(\d{5}(?:-\d{4})?)\b', re.I), 1, "PII"),
    ("DATE",          re.compile(r'\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})\b(?!\.\d)'), None, "PII"),
    ("ADDRESS",       re.compile(r'\b(?:address|addr|street|st\.?)\s*[:#\-]?\s*(\d+\s+[A-Za-z0-9\s\.,#\-]{5,60}?)(?=\s*[,;\n]|$)', re.I), 1, "PII"),
    # ── DID ───────────────────────────────────────────────────────────────────
    ("IP_ADDRESS",    re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), None, "DID"),
    ("IPV6",          re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), None, "DID"),
    ("MAC_ADDRESS",   re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), None, "DID"),
    ("GPS_COORD",     re.compile(r'\b(?:lat(?:itude)?|lng|lon(?:gitude)?)\s*[=:]\s*(-?\d{1,3}\.\d{4,})\b', re.I), 1, "DID"),
    ("SERIAL_NO",     re.compile(r'\b(?:serial\s*(?:no|num(?:ber)?|#)?|s\/n)\s*[:#\-]?\s*([A-Za-z0-9]{6,20})\b', re.I), 1, "DID"),
    # ── CTRO ──────────────────────────────────────────────────────────────────
    ("SERVICE_ACCT",  re.compile(r'\b(?:svc-|sa-|service[_\-]acct[\-_]?)[A-Za-z0-9_\-]{2,32}\b', re.I), None, "CTRO"),
    # ── INT ───────────────────────────────────────────────────────────────────
    ("ACCOUNT_NO",    re.compile(r'\b(?:acct|account|acc)(?:\s*[#:\-]\s*|\s+)(\d{4,20})\b', re.I), 1, "INT"),
    ("PROJECT_ID",    re.compile(r'\b(?:proj(?:ect)?\s*(?:id|num(?:ber)?|#|no\.?)?)\s*[:#\-]?\s*([A-Za-z0-9][\w\-]{2,30})\b', re.I), 1, "INT"),
    ("TICKET_NO",     re.compile(r'\b([A-Z]{2,8}-\d{1,6})\b'), None, "INT"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Code / IaC patterns
# ─────────────────────────────────────────────────────────────────────────────
CODE_PATTERNS = [
    # ── AWS_CORE ──────────────────────────────────────────────────────────────
    ("AWS_ACCOUNT_ID",   re.compile(r'\b(?:account[_\-]?id|aws[_\-]account[_\-]?id)\s*[=:"\s]+(\d{12})\b', re.I), 1, "AWS_CORE"),
    ("AWS_ARN",          re.compile(r'\barn:aws[^:\s]*:[^:\s]*:[a-z0-9\-]*:\d{0,12}:[^\s"\']+'), None, "AWS_CORE"),
    ("AWS_REGION_VAR",   re.compile(r'(?:AWS_DEFAULT_REGION|AWS_REGION)\s*[=:"\s]+["\']?([a-z]{2}-[a-z]+-\d)["\']?', re.I), 1, "AWS_CORE"),
    # ── AWS_IAM ───────────────────────────────────────────────────────────────
    ("AWS_ACCESS_KEY",   re.compile(r'\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b'), None, "AWS_IAM"),
    ("AWS_SECRET_KEY",   re.compile(r'(?:aws[_\-]secret[_\-]access[_\-]key|secret[_\-]access[_\-]key)\s*[=:"\s]+([A-Za-z0-9/+]{40})\b', re.I), 1, "AWS_IAM"),
    ("AWS_IAM_ARN",      re.compile(r'\barn:aws:iam::\d{12}:(?:user|role|group|policy)/[^\s"\']+'), None, "AWS_IAM"),
    ("AWS_ROLE_ARN",     re.compile(r'(?:role[_\-]?arn|iam[_\-]?role|assume[_\-]?role)\s*[=:"\s]+"?(arn:aws:iam::[^\s"\']+)"?', re.I), 1, "AWS_IAM"),
    # ── AWS_RES ───────────────────────────────────────────────────────────────
    ("AWS_S3_BUCKET",    re.compile(r'(?:s3://|(?:bucket|Bucket)\s*[=:]\s*["\']?)([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])(?:["\']|$|\s|/)', re.I), 1, "AWS_RES"),
    ("AWS_ECR_URL",      re.compile(r'\d{12}\.dkr\.ecr\.[a-z0-9\-]+\.amazonaws\.com/[^\s"\']+'), None, "AWS_RES"),
    ("AWS_SECRET_MGR",   re.compile(r'arn:aws:secretsmanager:[^:\s]+:\d{12}:secret:[^\s"\']+'), None, "AWS_RES"),
    ("AWS_KMS_KEY",      re.compile(r'arn:aws:kms:[^:\s]+:\d{12}:key/[A-Za-z0-9\-]+'), None, "AWS_RES"),
    ("AWS_RDS_HOST",     re.compile(r'[a-z0-9][a-z0-9\-]*\.[a-z0-9]+\.[a-z0-9\-]+\.rds\.amazonaws\.com'), None, "AWS_RES"),
    ("AWS_LAMBDA_ARN",   re.compile(r'arn:aws:lambda:[^:\s]+:\d{12}:function:[^\s"\']+'), None, "AWS_RES"),
    ("AWS_SQS_URL",      re.compile(r'https://sqs\.[a-z0-9\-]+\.amazonaws\.com/\d{12}/[^\s"\']+'), None, "AWS_RES"),
    # ── AZURE_CORE ────────────────────────────────────────────────────────────
    ("AZ_SUBSCRIPTION",  re.compile(r'(?:subscription[_\-]?id|subscriptions?)\s*[/=:"\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), 1, "AZURE_CORE"),
    ("AZ_TENANT",        re.compile(r'(?:tenant[_\-]?id|tenants?)\s*[/=:"\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), 1, "AZURE_CORE"),
    ("AZ_RESOURCE_ID",   re.compile(r'/subscriptions/[0-9a-f\-]{36}/resourcegroups?/[^\s"\']+', re.I), None, "AZURE_CORE"),
    # ── AZURE_IAM ─────────────────────────────────────────────────────────────
    ("AZ_CLIENT_ID",     re.compile(r'(?:client[_\-]?id|app(?:lication)?[_\-]?id)\s*[=:"\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), 1, "AZURE_IAM"),
    ("AZ_CLIENT_SECRET", re.compile(r'(?:client[_\-]?secret|app[_\-]?secret)\s*[=:"\s]+"?([A-Za-z0-9\-_.~]{20,})"?', re.I), 1, "AZURE_IAM"),
    ("AZ_OBJECT_ID",     re.compile(r'(?:object[_\-]?id|principal[_\-]?id)\s*[=:"\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), 1, "AZURE_IAM"),
    # ── AZURE_RES ─────────────────────────────────────────────────────────────
    ("AZ_STORAGE_ACCT",  re.compile(r'(?:storage[_\-]?account(?:[_\-]?name)?)\s*[=:"\s]+["\']?([a-z0-9]{3,24})["\']?', re.I), 1, "AZURE_RES"),
    ("AZ_KEYVAULT",      re.compile(r'https://([a-z][a-z0-9\-]{2,22})\.vault\.azure\.net', re.I), 1, "AZURE_RES"),
    ("AZ_CONN_STRING",   re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+', re.I), None, "AZURE_RES"),
    ("AZ_SQL_SERVER",    re.compile(r'(?:Server\s*=\s*tcp:)?([a-z0-9\-]+)\.database\.windows\.net', re.I), 1, "AZURE_RES"),
    ("AZ_FUNC_URL",      re.compile(r'https://[a-z0-9\-]+\.azurewebsites\.net/[^\s"\']*'), None, "AZURE_RES"),
    # ── GCP_CORE ──────────────────────────────────────────────────────────────
    ("GCP_PROJECT_ID",   re.compile(r'(?:^|[\s,{(])project\s*=\s*["\']([a-z][a-z0-9\-]{4,28}[a-z0-9])["\']', re.I|re.M), 1, "GCP_CORE"),
    ("GCP_PROJECT_REF",  re.compile(r'(?:project_id|projectId)\s*[=:]\s*["\']?([a-z][a-z0-9\-]{4,28}[a-z0-9])["\']?', re.I), 1, "GCP_CORE"),
    ("GCP_ORG_ID",       re.compile(r'(?:org(?:anization)?[_\-]?id|organizations?)\s*[/=:"\s]+(\d{10,12})\b', re.I), 1, "GCP_CORE"),
    ("GCP_FOLDER_ID",    re.compile(r'(?:folder[_\-]?id|folders?)\s*[/=:"\s]+(\d{10,12})\b', re.I), 1, "GCP_CORE"),
    ("GCP_NUMERIC_ID",   re.compile(r'/projects/(\d{8,12})\b'), 1, "GCP_CORE"),
    # ── GCP_IAM ───────────────────────────────────────────────────────────────
    ("GCP_SA_EMAIL",     re.compile(r'[a-z][a-z0-9\-]{0,28}[a-z0-9]@[a-z][a-z0-9\-]{0,28}\.iam\.gserviceaccount\.com'), None, "GCP_IAM"),
    ("GCP_IAM_MEMBER",   re.compile(r'(?:serviceAccount|user|group|domain):[A-Za-z0-9@\.\-_]+'), None, "GCP_IAM"),
    ("GCP_WI_POOL",      re.compile(r'projects/[^/]+/locations/[^/]+/workloadIdentityPools/([A-Za-z0-9\-_]+)', re.I), 1, "GCP_IAM"),
    ("GCP_SA_FIELD",     re.compile(r'service_account(?:_email)?\s*=\s*["\']([^"\']+)["\']', re.I), 1, "GCP_IAM"),
    ("GCP_IMPERSONATE",  re.compile(r'impersonate_service_account\s*=\s*["\']([^"\']+)["\']', re.I), 1, "GCP_IAM"),
    # ── GCP_NET ───────────────────────────────────────────────────────────────
    ("GCP_SELF_LINK",    re.compile(r'https://www\.googleapis\.com/compute/v1/projects/[^\s"\']+'), None, "GCP_NET"),
    ("GCP_NETWORK_REF",  re.compile(r'(?:network|subnetwork)\s*=\s*["\']([^"\']+)["\']', re.I), 1, "GCP_NET"),
    ("GCP_SVC_ATTACH",   re.compile(r'projects/[a-z][a-z0-9\-]*/regions/[a-z0-9\-]+/serviceAttachments/([A-Za-z0-9\-_]+)'), 1, "GCP_NET"),
    ("GCP_CIDR",         re.compile(r'ip_cidr_range\s*=\s*["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})["\']', re.I), 1, "GCP_NET"),
    ("GCP_DNS_ZONE",     re.compile(r'(?:dns_name|managed_zone)\s*=\s*["\']([^"\']+)["\']', re.I), 1, "GCP_NET"),
    ("CODE_IP",          re.compile(r'(?:^|\s)(?:host_ip|server_ip|bind_ip|nameserver|nat_ip)\s*(?:=|:)\s*["\']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["\']?', re.I|re.M), 1, "GCP_NET"),
    # ── GCP_RES ───────────────────────────────────────────────────────────────
    ("GCP_BUCKET",       re.compile(r'\bbucket\s*=\s*["\']([^"\']+)["\']', re.I), 1, "GCP_RES"),
    ("GCP_AR_REPO",      re.compile(r'[a-z]+-docker\.pkg\.dev/([A-Za-z0-9\-_/]+)'), 1, "GCP_RES"),
    ("GCP_KMS_KEY",      re.compile(r'projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/([A-Za-z0-9\-_]+)'), 1, "GCP_RES"),
    ("GCP_SECRET",       re.compile(r'projects/[^/]+/secrets/([A-Za-z0-9\-_]+)'), 1, "GCP_RES"),
    ("GCP_SQL_CONN",     re.compile(r'[a-z][a-z0-9\-]{3,28}:[a-z]+-[a-z0-9]+:[a-z][a-z0-9\-_]{0,40}'), None, "GCP_RES"),
    ("GCP_RUN_URL",      re.compile(r'https://[a-z0-9\-]+-[a-z0-9]+\.[a-z]+-[a-z0-9]+\.run\.app'), None, "GCP_RES"),
    # ── TF_CORE ───────────────────────────────────────────────────────────────
    ("TF_BACKEND_PREFIX",re.compile(r'\bprefix\s*=\s*["\']([^"\']+)["\']', re.I), 1, "TF_CORE"),
    ("TF_WORKSPACE",     re.compile(r'TF_WORKSPACE[=:\s]+["\']?([A-Za-z0-9_\-]+)["\']?'), 1, "TF_CORE"),
    ("TF_PROVIDER_CRED", re.compile(r'credentials\s*=\s*(?:file\(["\']([^"\']+)["\']|["\']([^"\']+)["\'])'), 1, "TF_CORE"),
    ("TF_REMOTE_STATE",  re.compile(r'data\s*["\']terraform_remote_state["\'].*?config\s*=\s*\{[^}]+\}', re.S), None, "TF_CORE"),
    # ── TF_VALS ───────────────────────────────────────────────────────────────
    ("TF_VAR_DEFAULT",   re.compile(r'^\s*default\s*=\s*["\']([^"\']{4,})["\']', re.M), 1, "TF_VALS"),
    ("TF_LOCAL_VAL",     re.compile(r'\blocals?\s*\{[^}]{0,500}?[\w_]+\s*=\s*["\']([^"\']{4,})["\']', re.S), 1, "TF_VALS"),
    # ── K8S ───────────────────────────────────────────────────────────────────
    ("K8S_NAMESPACE",    re.compile(r'\bnamespace\s*[=:]\s*["\']?([A-Za-z0-9\-_]{3,})["\']?', re.I), 1, "K8S"),
    ("K8S_IMAGE",        re.compile(r'(?:image|from)\s*[=:"\s]+([a-z0-9\.\-]+\.[a-z]{2,}/[A-Za-z0-9\-_/]+(?::[A-Za-z0-9\.\-_]+)?)', re.I), 1, "K8S"),
    ("K8S_INT_HOST",     re.compile(r'https?://[a-z][a-z0-9\-]+\.[a-z][a-z0-9\-]+\.(?:internal|cluster\.local|svc)[^\s"\']*'), None, "K8S"),
    ("K8S_SECRET_REF",   re.compile(r'secretKeyRef\s*:\s*\n\s*name\s*:\s*([A-Za-z0-9\-_]+)', re.M), 1, "K8S"),
    # ── CODE_CRED ─────────────────────────────────────────────────────────────
    ("CODE_API_KEY",     re.compile(r'(?:api[_\-]?key|api[_\-]?secret|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["\']([^"\']{6,})["\']', re.I), 1, "CODE_CRED"),
    ("CODE_TOKEN",       re.compile(r'(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token|id[_\-]?token|refresh[_\-]?token)\s*[=:]\s*["\']([^"\']{6,})["\']', re.I), 1, "CODE_CRED"),
    ("CODE_PASSWORD",    re.compile(r'(?:password|passwd|db[_\-]pass(?:word)?)\s*[=:]\s*["\']([^"\']{4,})["\']', re.I), 1, "CODE_CRED"),
    ("CODE_AWS_KEY",     re.compile(r'\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b'), None, "CODE_CRED"),
    ("CODE_PRIVATE_KEY", re.compile(r'-----BEGIN[^-]+PRIVATE KEY-----[\s\S]*?-----END[^-]+PRIVATE KEY-----', re.I), None, "CODE_CRED"),
    ("CODE_SECRET_VAR",  re.compile(r'(?<!#)(?<!\/\/)(?:secret|private_key)\s*=\s*["\']([^"\']{4,})["\']', re.I), 1, "CODE_CRED"),
    ("CODE_JWT",         re.compile(r'\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'), None, "CODE_CRED"),
    ("CODE_GITHUB_PAT",  re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'), None, "CODE_CRED"),
    ("CODE_STRIPE",      re.compile(r'\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b'), None, "CODE_CRED"),
    # ── CODE_CONN ─────────────────────────────────────────────────────────────
    ("CONN_URL_CRED",    re.compile(r'[a-z][a-z0-9+\-\.]+://[^:@\s]+:[^@\s]+@[^\s"\']+', re.I), None, "CODE_CONN"),
    ("CONN_JDBC",        re.compile(r'jdbc:[a-z]+://[^\s"\']+', re.I), None, "CODE_CONN"),
    ("CONN_DSN",         re.compile(r'(?:mongodb(?:\+srv)?|redis|rediss|postgres|postgresql|mysql|mssql|sqlserver|cassandra|couchdb|neo4j)://[^\s"\']+', re.I), None, "CODE_CONN"),
    ("CONN_HOST",        re.compile(r'(?:Server|Host|Data\s+Source)\s*=\s*([A-Za-z0-9\.\-]+\.[A-Za-z]{2,}(?::\d+)?)', re.I), 1, "CODE_CONN"),
    # ── PY_SPECIFIC ───────────────────────────────────────────────────────────
    ("PY_ENV_KEY",       re.compile(r'os\.environ(?:\.get)?\s*\(\s*["\']([A-Z][A-Z0-9_]{2,})["\']', re.I), 1, "PY_SPECIFIC"),
    ("PY_GETENV_DEFAULT",re.compile(r'os\.getenv\s*\(\s*["\'][^"\']+["\'],\s*["\']([^"\']{4,})["\']'), 1, "PY_SPECIFIC"),
    ("PY_DJANGO_SECRET", re.compile(r'SECRET_KEY\s*=\s*["\']([^"\']{8,})["\']'), 1, "PY_SPECIFIC"),
    ("PY_SETTINGS_VAL",  re.compile(r'(?:DATABASE_URL|REDIS_URL|BROKER_URL|CELERY_BROKER)\s*=\s*["\']([^"\']{6,})["\']'), 1, "PY_SPECIFIC"),
    ("PY_CONFIG_VAL",    re.compile(r'^[ \t]+(?:password|host|server|token|key|secret)\s*=\s*([^\s#\n]{4,})', re.I|re.M), 1, "PY_SPECIFIC"),
    ("PY_GCP_PROJECT",   re.compile(r'(?:^|\s)(?:PROJECT|GCP_PROJECT|GOOGLE_CLOUD_PROJECT)\s*=\s*["\']([a-z][a-z0-9\-]{4,28}[a-z0-9])["\']', re.I|re.M), 1, "PY_SPECIFIC"),
    # ── JS_SPECIFIC ───────────────────────────────────────────────────────────
    ("JS_PROCESS_ENV",   re.compile(r'process\.env\.([A-Z][A-Z0-9_]{2,})', re.I), 1, "JS_SPECIFIC"),
    ("JS_SECRET_CONST",  re.compile(r'(?:const|let|var)\s+\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CRED)\w*\s*=\s*["`\']([^`"\']{4,})["`\']', re.I), 1, "JS_SPECIFIC"),
    ("JS_OBJ_CRED",      re.compile(r'(?:apiKey|authToken|secretKey|clientSecret|accessToken|apiSecret)\s*:\s*["\']([^"\']{4,})["\']', re.I), 1, "JS_SPECIFIC"),
    ("JS_BEARER_HEADER", re.compile(r'Authorization["\']?\s*:\s*["\'](?:Bearer|Basic)\s+([^"\']{4,})["\']', re.I), 1, "JS_SPECIFIC"),
    ("JS_DOTENV_ASSIGN", re.compile(r'^([A-Z][A-Z0-9_]+)\s*=\s*(?!true$|false$|\d+$)([^\n#]{4,})$', re.M), 2, "JS_SPECIFIC"),
    # ── JAVA_SPECIFIC ─────────────────────────────────────────────────────────
    ("JAVA_PROP_VAL",    re.compile(r'(?:spring\.datasource\.(?:url|password|username)|spring\.security\.user\.password|server\.port)\s*=\s*([^\s\n]{3,})'), 1, "JAVA_SPECIFIC"),
    ("JAVA_STRING_CONST",re.compile(r'(?:private|public|protected)?\s*(?:static\s+)?(?:final\s+)?String\s+\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CRED)\w*\s*=\s*"([^"]{4,})"', re.I), 1, "JAVA_SPECIFIC"),
    ("JAVA_SPRING_VAL",  re.compile(r'@Value\s*\(\s*"\$\{([^}]+)\}"\s*\)'), 1, "JAVA_SPECIFIC"),
    ("JAVA_JDBC",        re.compile(r'getConnection\s*\(\s*"(jdbc:[^"]+)"'), 1, "JAVA_SPECIFIC"),
    ("KOTLIN_CONST",     re.compile(r'(?:val|const val)\s+\w*(?:KEY|TOKEN|SECRET|PASSWORD)\w*\s*=\s*"([^"]{4,})"', re.I), 1, "JAVA_SPECIFIC"),
    ("KOTLIN_BUILDCFG",  re.compile(r'BuildConfig\.([A-Z][A-Z0-9_]+)'), 1, "JAVA_SPECIFIC"),
    # ── GO_SPECIFIC ───────────────────────────────────────────────────────────
    ("GO_OS_GETENV",     re.compile(r'os\.Getenv\s*\(\s*"([A-Z][A-Z0-9_]{2,})"\s*\)', re.I), 1, "GO_SPECIFIC"),
    ("GO_CONST_SECRET",  re.compile(r'(?:const|var)\s+\w*(?:Key|Token|Secret|Password|Cred)\w*\s+\w+\s*=\s*"([^"]{4,})"', re.I), 1, "GO_SPECIFIC"),
    ("GO_STRUCT_CRED",   re.compile(r'(?:Password|APIKey|Token|Secret|Key)\s*:\s*"([^"]{4,})"', re.I), 1, "GO_SPECIFIC"),
    # ── CS_SPECIFIC ───────────────────────────────────────────────────────────
    ("CS_APP_SETTING",   re.compile(r'<add\s+key="[^"]*(?:Password|Token|Key|Secret|Credential)[^"]*"\s+value="([^"]{4,})"', re.I), 1, "CS_SPECIFIC"),
    ("CS_CONN_STRING",   re.compile(r'connectionString\s*=\s*"([^"]{10,})"', re.I), 1, "CS_SPECIFIC"),
    ("CS_CONST_SECRET",  re.compile(r'(?:private|public|internal)?\s*(?:static\s+)?(?:readonly\s+)?(?:const\s+)?string\s+\w*(?:Key|Token|Secret|Password)\w*\s*=\s*"([^"]{4,})"', re.I), 1, "CS_SPECIFIC"),
    ("CS_APPSETTINGS",   re.compile(r'"(?:ConnectionString|ApiKey|SecretKey|Password|Token)"\s*:\s*"([^"]{4,})"', re.I), 1, "CS_SPECIFIC"),
    # ── PHP_SPECIFIC ──────────────────────────────────────────────────────────
    ("PHP_DEFINE_CRED",  re.compile(r"define\s*\(\s*'[^']*(?:KEY|TOKEN|SECRET|PASSWORD|PASS)[^']*'\s*,\s*'([^']{4,})'", re.I), 1, "PHP_SPECIFIC"),
    ("PHP_VAR_CRED",     re.compile(r'\$\w*(?:key|token|secret|password|pass)\w*\s*=\s*["\']([^"\']{4,})["\']', re.I), 1, "PHP_SPECIFIC"),
    ("PHP_GETENV",       re.compile(r'getenv\s*\(\s*["\']([A-Z][A-Z0-9_]{2,})["\']', re.I), 1, "PHP_SPECIFIC"),
    ("PHP_ARRAY_CRED",   re.compile(r"'(?:db_pass(?:word)?|api_key|secret|token|password)'\s*=>\s*'([^']{4,})'", re.I), 1, "PHP_SPECIFIC"),
    # ── SHELL_SPECIFIC ────────────────────────────────────────────────────────
    ("SHELL_EXPORT",     re.compile(r'^export\s+([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CRED|ID)[A-Z0-9_]*)\s*=\s*["\']?([^"\';\n]{4,})["\']?', re.M), 2, "SHELL_SPECIFIC"),
    ("SHELL_VAR_ASSIGN", re.compile(r'^([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CRED)[A-Z0-9_]*)\s*=\s*["\']([^"\';\n]{4,})["\']', re.M), 2, "SHELL_SPECIFIC"),
    ("SHELL_CURL_AUTH",  re.compile(r"curl\s+.*?-H\s+['\"]Authorization:\s+(?:Bearer|Basic)\s+([^'\"]{4,})['\"]", re.I|re.S), 1, "SHELL_SPECIFIC"),
    # ── RUBY_SPECIFIC ─────────────────────────────────────────────────────────
    ("RUBY_CONST_CRED",  re.compile(r'[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)\s*=\s*["\']([^"\']{4,})["\']', re.I), 1, "RUBY_SPECIFIC"),
    ("RUBY_RAILS_SEC",   re.compile(r'config\.secret_key_base\s*=\s*["\']([^"\']{8,})["\']'), 1, "RUBY_SPECIFIC"),
    ("RUBY_ENV_REF",     re.compile(r"ENV\[\s*['\"]([A-Z][A-Z0-9_]{2,})['\"]\s*\]"), 1, "RUBY_SPECIFIC"),
    # ── SQL_SPECIFIC ──────────────────────────────────────────────────────────
    ("SQL_CRED_COMMENT", re.compile(r'--\s*(?:password|pw|pass|token|key|secret)\s*[=:]\s*([^\n]{4,})', re.I), 1, "SQL_SPECIFIC"),
    ("SQL_CONN_PARAM",   re.compile(r"(?:PASSWORD|USER(?:NAME)?|SERVER|DATABASE)\s*=\s*'([^']{2,})'", re.I), 1, "SQL_SPECIFIC"),
    ("SQL_LINKED_SRV",   re.compile(r"@(?:password|username|datasrc)\s*=\s*N?'([^']{2,})'", re.I), 1, "SQL_SPECIFIC"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Core redaction engine
# ─────────────────────────────────────────────────────────────────────────────
def _run_patterns(text, patterns, selected_types):
    findings = []
    for label, pattern, value_group, cls_id in patterns:
        if selected_types is not None and label not in selected_types:
            continue
        for m in pattern.finditer(text):
            if value_group is not None:
                try:
                    grp = m.group(value_group)
                    if not grp or not grp.strip():
                        continue
                    findings.append({"start": m.start(value_group), "end": m.end(value_group),
                                     "label": label, "cls": cls_id, "original": grp})
                except IndexError:
                    continue
            else:
                findings.append({"start": m.start(), "end": m.end(),
                                 "label": label, "cls": cls_id, "original": m.group()})
    return findings


# ── Classification ID sets used to split CODE_PATTERNS by mode ───────────────
CLOUD_CLS_IDS = {
    'AWS_CORE','AWS_IAM','AWS_RES',
    'AZURE_CORE','AZURE_IAM','AZURE_RES',
    'GCP_CORE','GCP_IAM','GCP_NET','GCP_RES',
    'TF_CORE','TF_VALS','K8S',
    'CODE_CRED','CODE_CONN',
}
LANG_CLS_IDS = {
    'PY_SPECIFIC','JS_SPECIFIC','JAVA_SPECIFIC','GO_SPECIFIC',
    'CS_SPECIFIC','PHP_SPECIFIC','SHELL_SPECIFIC','RUBY_SPECIFIC','SQL_SPECIFIC',
    'CODE_CRED','CODE_CONN',
}


def redact_text(text, mode, selected_types, custom_words):
    if mode == "general":
        patterns = GENERAL_PATTERNS
    else:
        # cloud, language, code, both — all draw from CODE_PATTERNS.
        # selected_types (checked boxes) handles per-mode filtering.
        patterns = CODE_PATTERNS
        if mode == "both":
            patterns = GENERAL_PATTERNS + CODE_PATTERNS

    findings = _run_patterns(text, patterns, selected_types)

    for word in (custom_words or []):
        word = word.strip()
        if not word:
            continue
        for m in re.finditer(re.escape(word), text, re.I):
            findings.append({"start": m.start(), "end": m.end(),
                             "label": "CUSTOM", "cls": "CUSTOM", "original": m.group()})

    findings.sort(key=lambda x: (x["start"], -(x["end"] - x["start"])))
    deduped, last_end = [], -1
    for f in findings:
        if f["start"] >= last_end:
            deduped.append(f)
            last_end = f["end"]

    result, pos = [], 0
    for f in deduped:
        result.append(text[pos:f["start"]])
        result.append(f"[{f['cls']}-{f['label']}]")
        pos = f["end"]
    result.append(text[pos:])

    all_cls = {**CLASSIFICATIONS, **CODE_CLASSIFICATIONS}
    highlights = []
    for f in deduped:
        cls_meta = all_cls.get(f["cls"], CLASSIFICATIONS["INT"])
        # HTML-escape the original value server-side to prevent XSS
        safe_original = (f["original"]
                         .replace("&", "&amp;").replace("<", "&lt;")
                         .replace(">", "&gt;").replace('"', "&quot;"))
        highlights.append({
            "start": f["start"], "end": f["end"],
            "label": f["label"], "cls": f["cls"],
            "cls_name": cls_meta["name"], "cls_abbr": cls_meta["abbr"],
            "color": cls_meta["color"], "text_color": cls_meta["text_color"],
            "original": safe_original,
        })

    return {"redacted": "".join(result), "original": text, "highlights": highlights, "count": len(deduped)}

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(_STATIC_DIR, "index.html")


@app.route("/api/redact", methods=["POST"])
def api_redact():
    data = request.get_json(force=True)

    text = data.get("text", "")
    if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
        return jsonify({"error": f"Text payload exceeds {MAX_TEXT_BYTES // 1024 // 1024} MB limit. "
                                  "Split the content into smaller chunks."}), 413

    result = redact_text(
        text,
        data.get("mode", "general"),
        data.get("types"),           # None = all patterns
        data.get("custom_words", []),
    )
    return jsonify(result)


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    text, err = extract_text_from_file(f)
    if err:
        return jsonify({"error": err}), 422
    return jsonify({"text": text, "filename": f.filename})


@app.route("/api/patterns", methods=["GET"])
def api_patterns():
    def group_patterns(patterns, cls_defs):
        grouped = {}
        for label, _, _, cls_id in patterns:
            grouped.setdefault(cls_id, []).append(label)
        out = []
        for cls_id, labels in grouped.items():
            m = cls_defs[cls_id]
            out.append({"cls_id": cls_id, "cls_name": m["name"], "cls_abbr": m["abbr"],
                        "color": m["color"], "text_color": m["text_color"],
                        "description": m["description"], "labels": labels})
        return out

    c = CLASSIFICATIONS["CUSTOM"]
    custom_entry = {"cls_id": "CUSTOM", "cls_name": c["name"], "cls_abbr": c["abbr"],
                    "color": c["color"], "text_color": c["text_color"],
                    "description": c["description"], "labels": ["CUSTOM"]}

    cloud_pats = [(l,p,g,c) for l,p,g,c in CODE_PATTERNS if c in CLOUD_CLS_IDS]
    lang_pats  = [(l,p,g,c) for l,p,g,c in CODE_PATTERNS if c in LANG_CLS_IDS]

    return jsonify({
        "general":  group_patterns(GENERAL_PATTERNS, CLASSIFICATIONS) + [custom_entry],
        "cloud":    group_patterns(cloud_pats, CODE_CLASSIFICATIONS) + [custom_entry],
        "language": group_patterns(lang_pats,  CODE_CLASSIFICATIONS) + [custom_entry],
    })


@app.route("/health", methods=["GET"])
def health():
    """Simple liveness probe for container orchestration."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    os.makedirs(_STATIC_DIR, exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"🔒 Redact running at http://localhost:{port}")
    app.run(debug=debug, host="0.0.0.0", port=port)
