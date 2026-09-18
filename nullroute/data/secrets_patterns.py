# ============================================================
#  File: nullroute/data/secrets_patterns.py
#
#  Regex rules for hardcoded secret detection.
#
#  NOTE: several patterns build the "prefix" via string concatenation
#  (e.g. "sk_" + "live_") so that GitHub's own secret scanner does
#  not flag our source code as containing real credentials.  Python
#  folds these at parse time, so the compiled regex is identical.
# ============================================================
import re


PATTERNS = [
    # ---------- AWS ----------
    {"kind": "AWS Access Key ID",
     "pattern": r"\b(A" + "KIA" + r"[0-9A-Z]{16})\b",
     "severity": "HIGH"},
    {"kind": "AWS Secret Access Key",
     "pattern": r"""(?i)aws[_-]?(?:secret|access)[_-]?(?:access[_-]?)?key"""
                r"""[^A-Za-z0-9]{0,10}([A-Za-z0-9/+=]{40})\b""",
     "severity": "HIGH"},

    # ---------- Google / Firebase ----------
    {"kind": "Google API Key",
     "pattern": r"\b(AI" + "za" + r"[0-9A-Za-z\-_]{35})\b",
     "severity": "HIGH"},
    {"kind": "Firebase URL",
     "pattern": r"(https?://[a-z0-9\-]+\.firebaseio\.com)",
     "severity": "MEDIUM"},
    {"kind": "Firebase Database Secret",
     "pattern": r"""(?i)firebase[_-]?(?:api[_-]?)?(?:secret|key)"""
                r"""[^A-Za-z0-9]{0,10}([A-Za-z0-9_\-]{20,})\b""",
     "severity": "HIGH"},

    # ---------- Stripe / Payments ----------
    {"kind": "Stripe Secret Key (live)",
     "pattern": r"\b(sk_" + "live_" + r"[0-9a-zA-Z]{24,})\b",
     "severity": "HIGH"},
    {"kind": "Stripe Secret Key (test)",
     "pattern": r"\b(sk_" + "test_" + r"[0-9a-zA-Z]{24,})\b",
     "severity": "LOW"},
    {"kind": "Stripe Publishable Key",
     "pattern": r"\b(pk_" + r"(?:live|test)_[0-9a-zA-Z]{24,})\b",
     "severity": "LOW"},
    {"kind": "PayPal Client ID",
     "pattern": r"""(?i)paypal[_-]?(?:client[_-]?id|app[_-]?id)"""
                r"""[^A-Za-z0-9]{0,10}([A-Za-z0-9_\-]{30,})\b""",
     "severity": "MEDIUM"},

    # ---------- GitHub ----------
    {"kind": "GitHub Personal Access Token",
     "pattern": r"\b(" + "gh" + "p_" + r"[0-9A-Za-z]{36})\b",
     "severity": "HIGH"},
    {"kind": "GitHub OAuth Token",
     "pattern": r"\b(" + "gh" + "o_" + r"[0-9A-Za-z]{36})\b",
     "severity": "HIGH"},
    {"kind": "GitHub App Token",
     "pattern": r"\b(" + "gh" + r"[us]_[0-9A-Za-z]{36})\b",
     "severity": "HIGH"},
    {"kind": "GitHub Refresh Token",
     "pattern": r"\b(" + "gh" + "r_" + r"[0-9A-Za-z]{76})\b",
     "severity": "HIGH"},

    # ---------- Slack / Discord / Telegram ----------
    {"kind": "Slack Token",
     "pattern": r"\b(" + "xo" + r"x[abprs]-[0-9A-Za-z\-]{10,})\b",
     "severity": "HIGH"},
    {"kind": "Slack Webhook",
     "pattern": r"(https://hooks\.slack\.com/services/[A-Z0-9/]{40,})",
     "severity": "HIGH"},
    {"kind": "Discord Webhook",
     "pattern": r"(https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)",
     "severity": "HIGH"},
    {"kind": "Telegram Bot Token",
     "pattern": r"\b(\d{9,10}:AA[A-Za-z0-9_\-]{33})\b",
     "severity": "HIGH"},

    # ---------- Comms / Email ----------
    {"kind": "Twilio API Key",
     "pattern": r"\b(" + "S" + r"K[0-9a-fA-F]{32})\b",
     "severity": "HIGH"},
    {"kind": "Twilio Account SID",
     "pattern": r"\b(" + "A" + r"C[0-9a-fA-F]{32})\b",
     "severity": "MEDIUM"},
    {"kind": "SendGrid API Key",
     "pattern": r"\b(" + "SG" + r"\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
     "severity": "HIGH"},
    {"kind": "Mailgun API Key",
     "pattern": r"\b(key-[0-9a-z]{32})\b",
     "severity": "HIGH"},
    {"kind": "Mailchimp API Key",
     "pattern": r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
     "severity": "HIGH"},

    # ---------- Package registries ----------
    {"kind": "npm Token",
     "pattern": r"\b(" + "np" + "m_" + r"[A-Za-z0-9]{36})\b",
     "severity": "HIGH"},
    {"kind": "PyPI Token",
     "pattern": r"\b(" + "pyp" + r"i-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
     "severity": "HIGH"},
    {"kind": "NuGet API Key",
     "pattern": r"\b(oy2[a-z0-9]{43})\b",
     "severity": "HIGH"},

    # ---------- Auth ----------
    {"kind": "JWT",
     "pattern": r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
     "severity": "LOW"},
    {"kind": "Bearer Token (looks real)",
     "pattern": r"""(?i)bearer\s+([A-Za-z0-9\-_\.]{30,})\b""",
     "severity": "LOW"},
    {"kind": "Basic Auth (base64)",
     "pattern": r"""(?i)basic\s+([A-Za-z0-9+/=]{20,})\b""",
     "severity": "LOW"},

    # ---------- Crypto ----------
    {"kind": "RSA Private Key",
     "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
     "severity": "HIGH"},
    {"kind": "EC Private Key",
     "pattern": r"-----BEGIN EC PRIVATE KEY-----",
     "severity": "HIGH"},
    {"kind": "OpenSSH Private Key",
     "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
     "severity": "HIGH"},
    {"kind": "PGP Private Key",
     "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     "severity": "HIGH"},

    # ---------- Databases / infra ----------
    {"kind": "MongoDB URI (with auth)",
     "pattern": r"(mongodb(?:\+srv)?://[^:\s\"']+:[^@\s\"']+@[^\s\"']+)",
     "severity": "HIGH"},
    {"kind": "PostgreSQL URI (with auth)",
     "pattern": r"(postgres(?:ql)?://[^:\s\"']+:[^@\s\"']+@[^\s\"']+)",
     "severity": "HIGH"},
    {"kind": "MySQL URI (with auth)",
     "pattern": r"(mysql://[^:\s\"']+:[^@\s\"']+@[^\s\"']+)",
     "severity": "HIGH"},
    {"kind": "Redis URI (with auth)",
     "pattern": r"(redis://[^:\s\"']*:[^@\s\"']+@[^\s\"']+)",
     "severity": "HIGH"},

    # ---------- Generic API key ----------
    {"kind": "Generic API Key",
     "pattern": r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)"""
                r"""['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,64})['"]""",
     "severity": "MEDIUM"},

    # ---------- Secret-ish high-entropy strings in plain assignment -----
    {"kind": "Hardcoded Secret (suspicious)",
     "pattern": r"""(?i)(?:secret|token|password|passwd|pwd)['"]?\s*[:=]\s*"""
                r"""['"]([A-Za-z0-9_\-\.!@#$%^&*]{12,80})['"]""",
     "severity": "MEDIUM"},
]


# Compile once
for _entry in PATTERNS:
    _entry["_compiled"] = re.compile(_entry["pattern"])


# -------- allow-list: values we should never report --------------------
IGNORE_VALUES = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "changeme", "example", "your_api_key", "xxxxxxxx", "todo",
    "undefined", "null", "true", "false",
    "pk_" + "test_" + "xxxxxxxxxxxxxxxxxxxxxxxx",   # Stripe docs example
    "sk_" + "test_" + "xxxxxxxxxxxxxxxxxxxxxxxx",   # Stripe docs example
}
