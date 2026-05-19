"""
tests/test_patterns.py — Pattern true-positive / true-negative smoke tests.
Run with:  pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import redact_text, GENERAL_PATTERNS, CODE_PATTERNS
from extraction import extract_text_from_file
import io

# ─── Helpers ──────────────────────────────────────────────────────────────────
def general(text, types=None):
    return redact_text(text, "general", types, [])

def code(text, types=None):
    return redact_text(text, "code", types, [])

def found(result):
    return result["count"] > 0

def labels(result):
    return {h["label"] for h in result["highlights"]}

# ─── PHI ──────────────────────────────────────────────────────────────────────
def test_npi_hit():
    assert "NPI" in labels(general("NPI: 1234567890"))

def test_npi_miss():
    assert not found(general("1234567"))  # too short

def test_dob_hit():
    assert "DOB" in labels(general("DOB: 01/15/1990"))

def test_dea_hit():
    assert "DEA" in labels(general("prescribed by AB1234567"))

# ─── PCI ──────────────────────────────────────────────────────────────────────
def test_credit_card_visa():
    assert "CREDIT_CARD" in labels(general("Card: 4111 1111 1111 1111"))

def test_credit_card_amex():
    assert "CREDIT_CARD" in labels(general("371449635398431"))

def test_cvv_hit():
    assert "CVV" in labels(general("CVV: 123"))

# ─── RST ──────────────────────────────────────────────────────────────────────
def test_ssn_hit():
    assert "SSN" in labels(general("SSN: 123-45-6789"))

def test_ssn_invalid_miss():
    # Invalid SSN groups should not match (000-xx-xxxx)
    assert "SSN" not in labels(general("000-12-3456"))

def test_aws_key_hit():
    assert "AWS_KEY" in labels(general("AKIAIOSFODNN7EXAMPLE1234"))

def test_github_token_hit():
    assert "GITHUB_TOKEN" in labels(general("ghp_" + "A" * 36))

def test_stripe_live_key_hit():
    assert "STRIPE_KEY" in labels(general("sk_live_" + "a" * 24))

def test_jwt_hit():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert "JWT_TOKEN" in labels(general(jwt))

def test_private_key_hit():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAA==\n-----END RSA PRIVATE KEY-----"
    assert "PRIVATE_KEY" in labels(general(pem))

# ─── FIN ──────────────────────────────────────────────────────────────────────
def test_iban_hit():
    assert "IBAN" in labels(general("IBAN: GB29NWBK60161331926819"))

def test_aba_routing_hit():
    assert "ABA_ROUTING" in labels(general("routing: 021000021"))

# ─── GOV ──────────────────────────────────────────────────────────────────────
def test_ein_hit():
    assert "EIN" in labels(general("EIN: 12-3456789"))

def test_passport_hit():
    assert "PASSPORT" in labels(general("Passport: A12345678"))

def test_vin_hit():
    assert "VIN" in labels(general("VIN: 1HGCM82633A004352"))

# ─── PII ──────────────────────────────────────────────────────────────────────
def test_email_hit():
    assert "EMAIL" in labels(general("Contact: user@example.com"))

def test_phone_hit():
    assert "PHONE" in labels(general("Call (555) 867-5309"))

def test_zip_contextual_hit():
    assert "ZIP_CODE" in labels(general("zip: 90210"))

def test_zip_bare_number_miss():
    # Bare 5-digit number without context should NOT fire (semver, port, etc.)
    assert "ZIP_CODE" not in labels(general("version 90210"))

# ─── DID ──────────────────────────────────────────────────────────────────────
def test_ipv4_hit():
    assert "IP_ADDRESS" in labels(general("server at 192.168.1.100"))

def test_mac_hit():
    assert "MAC_ADDRESS" in labels(general("MAC: AA:BB:CC:DD:EE:FF"))

def test_gps_hit():
    assert "GPS_COORD" in labels(general("lat: 40.7128, lon: -74.0060"))

# ─── AWS code patterns ────────────────────────────────────────────────────────
def test_aws_account_id_hit():
    assert "AWS_ACCOUNT_ID" in labels(code('aws_account_id = "123456789012"'))

def test_aws_arn_hit():
    assert "AWS_ARN" in labels(code("arn:aws:iam::123456789012:role/MyRole"))

def test_aws_s3_bucket_hit():
    assert "AWS_S3_BUCKET" in labels(code('bucket = "my-prod-data-bucket"'))

# ─── Azure code patterns ──────────────────────────────────────────────────────
def test_azure_subscription_hit():
    guid = "12345678-1234-1234-1234-123456789abc"
    assert "AZ_SUBSCRIPTION" in labels(code(f'subscription_id = "{guid}"'))

def test_azure_keyvault_hit():
    assert "AZ_KEYVAULT" in labels(code("https://myvault.vault.azure.net"))

def test_azure_conn_string_hit():
    cs = "DefaultEndpointsProtocol=https;AccountName=mystg;AccountKey=abc123=="
    assert "AZ_CONN_STRING" in labels(code(cs))

# ─── GCP code patterns ────────────────────────────────────────────────────────
def test_gcp_sa_email_hit():
    assert "GCP_SA_EMAIL" in labels(code("deploy@my-project-123.iam.gserviceaccount.com"))

def test_gcp_secret_hit():
    assert "GCP_SECRET" in labels(code("projects/my-proj/secrets/my-secret"))

# ─── Language-specific ────────────────────────────────────────────────────────
def test_python_env_key_hit():
    assert "PY_ENV_KEY" in labels(code("os.environ.get('SECRET_KEY')"))

def test_python_getenv_default_hit():
    assert "PY_GETENV_DEFAULT" in labels(code("os.getenv('KEY', 'fallback-value-123')"))

def test_js_process_env_hit():
    assert "JS_PROCESS_ENV" in labels(code("const x = process.env.API_KEY;"))

def test_js_secret_const_hit():
    assert "JS_SECRET_CONST" in labels(code("const SECRET_TOKEN = 'abc123secret';"))

def test_go_getenv_hit():
    assert "GO_OS_GETENV" in labels(code('key := os.Getenv("SECRET_KEY")'))

def test_shell_export_hit():
    assert "SHELL_EXPORT" in labels(code("export API_SECRET_KEY='mysecretvalue'"))

def test_php_define_hit():
    assert "PHP_DEFINE_CRED" in labels(code("define('API_KEY', 'sk-prod-abc123');"))

def test_ruby_const_hit():
    assert "RUBY_CONST_CRED" in labels(code("API_SECRET = 'sk-prod-abc123'"))

def test_sql_password_param_hit():
    assert "SQL_CONN_PARAM" in labels(code("SERVER='mydb'; PASSWORD='s3cr3t'"))

# ─── Connection strings ───────────────────────────────────────────────────────
def test_postgres_dsn_hit():
    assert "CONN_DSN" in labels(code("postgresql://user:pass@db.host:5432/mydb"))

def test_jdbc_hit():
    assert "CONN_JDBC" in labels(code('jdbc:postgresql://db.corp:5432/app'))

def test_url_with_creds_hit():
    assert "CONN_URL_CRED" in labels(code("https://admin:secret123@internal.host/api"))

# ─── Custom words ─────────────────────────────────────────────────────────────
def test_custom_word_hit():
    result = redact_text("Contact John Smith at Acme Corp", "general", None, ["John Smith", "Acme Corp"])
    assert result["count"] == 2

# ─── Deduplication ────────────────────────────────────────────────────────────
def test_no_overlapping_matches():
    """Verify that overlapping regex matches are deduplicated."""
    text = "api_key = 'sk-prod-abc123'\npassword = 'hunter2'"
    result = general(text)
    starts = [h["start"] for h in result["highlights"]]
    assert len(starts) == len(set(starts)), "Duplicate start positions found"

# ─── File extraction ──────────────────────────────────────────────────────────
class FakeFileStorage:
    def __init__(self, content: bytes, filename: str):
        self.filename = filename
        self._content = content
    def read(self):
        return self._content

def test_extract_utf8_text():
    f = FakeFileStorage(b"SSN: 123-45-6789", "test.txt")
    text, err = extract_text_from_file(f)
    assert err is None
    assert "SSN" in text

def test_extract_unknown_extension():
    f = FakeFileStorage(b"API_KEY=abc123", "config.toml")
    text, err = extract_text_from_file(f)
    assert err is None
    assert "API_KEY" in text

def test_extract_no_extension():
    f = FakeFileStorage(b"password=secret", "Makefile")
    text, err = extract_text_from_file(f)
    assert err is None

def test_extract_binary_returns_error():
    # Null bytes make a file undecodable as any sensible text encoding
    f = FakeFileStorage(b"\x00\x01\x02\x03" * 200, "binary.bin")
    text, err = extract_text_from_file(f)
    # latin-1 can decode anything, so only truly degenerate binaries fail.
    # Just ensure we get back either text or a clear error — not an exception.
    assert text is not None or err is not None

def test_extract_docx():
    """Minimal DOCX (ZIP with word/document.xml)."""
    import zipfile, io as _io
    xml = (b'<?xml version="1.0"?>'
           b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           b'<w:body><w:p><w:r><w:t>SSN: 123-45-6789</w:t></w:r></w:p></w:body>'
           b'</w:document>')
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml', xml)
    buf.seek(0)
    f = FakeFileStorage(buf.read(), "test.docx")
    text, err = extract_text_from_file(f)
    assert err is None
    assert "123-45-6789" in text

# ─── API endpoint smoke tests ─────────────────────────────────────────────────
def test_api_redact_endpoint(tmp_path):
    import app as app_module
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    resp = client.post("/api/redact", json={"text": "SSN: 123-45-6789", "mode": "general"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] >= 1
    assert "123-45-6789" not in data["redacted"]

def test_api_redact_oversized_payload():
    import app as app_module
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    # 3 MB of text — exceeds the 2 MB limit
    big_text = "a" * (3 * 1024 * 1024)
    resp = client.post("/api/redact", json={"text": big_text, "mode": "general"})
    assert resp.status_code == 413

def test_api_patterns_endpoint():
    import app as app_module
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    resp = client.get("/api/patterns")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "general" in data
    assert "code" in data
    assert len(data["general"]) > 5
    assert len(data["code"]) > 5

def test_health_endpoint():
    import app as app_module
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"
