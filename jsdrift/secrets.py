"""Secret detection tuned for *low false positives*.

Pipeline for every candidate:
  1. provider-specific pattern (strong prefix/format) or key-name-driven generic rule
  2. structural validator (checksum / decode / parse) - drops lookalikes
  3. placeholder / example / i18n / identifier filters
  4. entropy + character-class sanity checks
  5. confidence + severity assignment, with "public by design" keys downgraded to info
Every rejection can be explained (``jsdrift analyze --explain``) so you can tune it.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable

from .models import Finding, SEV_RANK, mask, min_sev
from .util import char_classes, entropy


@dataclass
class Rejection:
    kind: str
    value: str
    reason: str


@dataclass
class Verdict:
    ok: bool = True
    delta: int = 0
    why: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    severity: str | None = None


# --------------------------------------------------------------------------- placeholders

_PLACEHOLDER_WORDS = (
    "your", "example", "changeme", "change_me", "change-me", "placeholder", "dummy", "sample", "lorem",
    "fake", "todo", "insert", "replace", "redacted", "xxxx", "****", "<", ">", "{{", "${", "{expr}",
    "process.env", "undefined", "enter_", "enter-", "my_secret", "mysecret", "foobar", "notasecret",
)
_KNOWN_DOC_KEYS = ("4eC39HqLyjWDarjtT1zdp7dc", "TYooMQauvdEDq54NiTphI7jx", "wJalrXUtnFEMI/K7MDENG")
_COMMON_DEFAULTS = {
    "password", "passw0rd", "admin", "administrator", "123456", "12345678", "qwerty", "letmein", "secret",
    "changeit", "default", "test", "testing", "true", "false", "null", "none", "bearer", "basic", "token",
}


def is_placeholder(v: str) -> str | None:
    low = v.lower()
    for w in _PLACEHOLDER_WORDS:
        if w in low:
            return f"placeholder/example text ('{w}')"
    for k in _KNOWN_DOC_KEYS:
        if k in v:
            return "known documentation example key"
    if low in _COMMON_DEFAULTS:
        return "common default word"
    if len(v) >= 8 and len(set(v)) <= 3:
        return "repeated characters"
    if len(v) >= 8:
        diffs = [ord(b) - ord(a) for a, b in zip(v, v[1:])]
        if diffs and sum(d in (1, -1) for d in diffs) / len(diffs) > 0.7:
            return "sequential characters"
    return None


# --------------------------------------------------------------------------- validators

def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def v_aws_key(value: str, **_) -> Verdict:
    try:
        raw = base64.b32decode(value[4:].upper())
        acct = (int.from_bytes(raw[:6], "big") & 0x7FFFFFFFFF80) >> 7
    except (binascii.Error, ValueError):
        return Verdict(False, why=["AWS key id does not base32-decode"])
    if not (0 < acct < 10 ** 12):
        return Verdict(False, why=["decoded AWS account id out of range"])
    sev = "high"
    why = [f"decodes to AWS account {acct:012d}"]
    if value.startswith("ASIA"):
        sev = "medium"
        why.append("ASIA = temporary STS credential (needs session token, usually short-lived)")
    return Verdict(True, 0, why, {"aws_account_id": f"{acct:012d}"}, sev)


_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _base62(n: int, width: int) -> str:
    s = ""
    while n:
        n, r = divmod(n, 62)
        s = _B62[r] + s
    return s.rjust(width, "0")


def v_github_token(value: str, **_) -> Verdict:
    body = value[4:]
    if len(body) != 36:
        return Verdict(True)
    if _base62(zlib.crc32(body[:30].encode()) & 0xFFFFFFFF, 6) == body[30:]:
        return Verdict(True, 5, ["embedded CRC32 checksum is valid"])
    return Verdict(True, -30, ["embedded checksum mismatch (likely fake/example)"])


def v_jwt(value: str, **_) -> Verdict:
    parts = value.split(".")
    try:
        hdr = json.loads(_b64url(parts[0]))
        pl = json.loads(_b64url(parts[1]))
    except Exception:  # noqa: BLE001 - any decode failure means "not a JWT"
        return Verdict(False, why=["not a decodable JWT"])
    if not isinstance(hdr, dict) or "alg" not in hdr or not isinstance(pl, dict):
        return Verdict(False, why=["JWT header/payload malformed"])
    if pl.get("name") == "John Doe" and pl.get("iat") == 1516239022:
        return Verdict(False, why=["jwt.io documentation example token"])
    meta: dict = {"alg": hdr.get("alg")}
    for k in ("iss", "aud", "role"):
        if isinstance(pl.get(k), (str, list)):
            meta[k] = pl[k]
    sev, delta, why = "medium", 0, []
    role = pl.get("role")
    if role == "service_role":
        sev = "critical"
        why.append("Supabase service_role JWT - bypasses row level security")
    elif role == "anon":
        sev = "info"
        why.append("role=anon (public by design)")
    exp = pl.get("exp")
    if isinstance(exp, (int, float)):
        meta["exp"] = int(exp)
        if exp < time.time():
            sev = min_sev(sev, "low")
            delta -= 20
            why.append("token already expired")
    if str(hdr.get("alg", "")).lower() == "none":
        why.append("alg=none")
    return Verdict(True, delta, why, meta, sev)


def v_private_key(value: str, m: re.Match, text: str, **_) -> Verdict:
    end = text.find("-----END", m.end())
    body = text[m.end(): end if end != -1 else m.end() + 4000]
    payload = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    if len(payload) < 100:
        return Verdict(False, why=["PEM header only (crypto-library constant, no key material)"])
    return Verdict(True, 0, [f"{len(payload)} base64 chars of key material follow header"])


def v_discord_bot(value: str, **_) -> Verdict:
    try:
        uid = _b64url(value.split(".")[0]).decode()
    except Exception:  # noqa: BLE001
        return Verdict(False, why=["first segment is not a base64 user id"])
    if not uid.isdigit():
        return Verdict(False, why=["first segment does not decode to a numeric id"])
    return Verdict(True, 0, [f"decodes to Discord user id {uid}"])


def v_basic_url(value: str, **_) -> Verdict:
    m = re.match(r"\w+://([^:/@]+):([^@/]+)@", value)
    if not m:
        return Verdict(False)
    pw = m.group(2)
    why = is_placeholder(pw)
    if why or pw.startswith("{") or pw.startswith("$"):
        return Verdict(False, why=[f"password portion is {why or 'a template variable'}"])
    return Verdict(True)


def v_basic_header(value: str, **_) -> Verdict:
    try:
        dec = base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8")
    except Exception:  # noqa: BLE001
        return Verdict(False, why=["not valid base64 credentials"])
    if ":" not in dec or not dec.isprintable():
        return Verdict(False, why=["decoded value is not user:pass"])
    pw = dec.split(":", 1)[1]
    why = is_placeholder(pw)
    if why or not pw:
        return Verdict(False, why=[f"password portion is {why or 'empty'}"])
    return Verdict(True, 0, ["Basic credentials decode to user:password"])


def v_slack(value: str, **_) -> Verdict:
    if not re.search(r"-\d{6,}", value):
        return Verdict(False, why=["Slack token lacks numeric workspace/user segments"])
    return Verdict(True)


# --------------------------------------------------------------------------- rule table

@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: re.Pattern
    severity: str
    confidence: int
    public: bool = False
    validator: Callable | None = None
    note: str = ""


def _r(id_, title, pat, sev, conf, public=False, validator=None, note="") -> Rule:
    return Rule(id_, title, re.compile(pat), sev, conf, public, validator, note)


RULES: list[Rule] = [
    _r("aws_access_key_id", "AWS access key ID", r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b", "high", 85, validator=v_aws_key,
       note="Key ID alone is not exploitable; look for the paired secret key in the same bundle."),
    _r("github_token", "GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36})\b", "high", 90, validator=v_github_token),
    _r("github_pat_fine", "GitHub fine-grained PAT", r"\b(github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b", "high", 92),
    _r("gitlab_pat", "GitLab personal access token", r"\b(glpat-[A-Za-z0-9_\-]{20})\b", "high", 90),
    _r("slack_token", "Slack token", r"\b(xox[abposr]-[A-Za-z0-9\-]{20,100})\b", "high", 88, validator=v_slack),
    _r("slack_webhook", "Slack incoming webhook",
       r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})", "high", 92,
       note="Allows posting messages into the workspace."),
    _r("discord_webhook", "Discord webhook",
       r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[\w\-]{60,70})", "high", 92),
    _r("discord_bot", "Discord bot token", r"\b([MNO][A-Za-z\d_\-]{23,25}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,38})\b", "high", 80,
       validator=v_discord_bot),
    _r("stripe_secret_live", "Stripe live secret key", r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,99})\b", "critical", 95),
    _r("stripe_secret_test", "Stripe test secret key", r"\b(sk_test_[0-9A-Za-z]{24,99})\b", "low", 90,
       note="Test-mode key: limited impact, but indicates secrets are shipped to the client."),
    _r("stripe_publishable", "Stripe publishable key", r"\b(pk_(?:live|test)_[0-9A-Za-z]{24,99})\b", "info", 90, public=True,
       note="Publishable keys are public by design."),
    _r("google_api_key", "Google API key", r"\b(AIza[0-9A-Za-z_\-]{35})\b", "low", 90, public=True,
       note="Usually public (Maps/Firebase). Reportable only if unrestricted - test referrer/API restrictions out-of-band, with permission."),
    _r("google_oauth_secret", "Google OAuth client secret", r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b", "high", 92),
    _r("sendgrid", "SendGrid API key", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "critical", 95),
    _r("twilio_key", "Twilio API key SID", r"\b(SK[0-9a-f]{32})\b", "medium", 60),
    _r("mailgun", "Mailgun API key", r"\b(key-[0-9a-f]{32})\b", "high", 75),
    _r("mailchimp", "Mailchimp API key", r"\b([0-9a-f]{32}-us\d{1,2})\b", "high", 85),
    _r("npm_token", "npm access token", r"\b(npm_[A-Za-z0-9]{36})\b", "high", 92),
    _r("openai_key", "OpenAI API key", r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{40,})\b", "high", 78),
    _r("anthropic_key", "Anthropic API key", r"\b(sk-ant-[A-Za-z0-9_\-]{80,})\b", "high", 92),
    _r("shopify", "Shopify access token", r"\b(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b", "high", 92),
    _r("digitalocean", "DigitalOcean token", r"\b(dop_v1_[a-f0-9]{64})\b", "high", 92),
    _r("telegram_bot", "Telegram bot token", r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b", "high", 88),
    _r("private_key", "Private key block",
       r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)", "critical", 95,
       validator=v_private_key),
    _r("jwt", "JSON Web Token", r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*)", "medium", 80,
       validator=v_jwt),
    _r("basic_auth_url", "Credentials embedded in URL", r"\b(https?://[^\s/:@\"'`]{1,64}:[^\s/@\"'`]{3,64}@[\w.\-]+[^\s\"'`]*)",
       "high", 85, validator=v_basic_url),
    _r("db_connection", "Database/queue connection string with credentials",
       r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@\"'`]+:[^\s@\"'`]+@[^\s\"'`]+)", "critical", 90,
       validator=v_basic_url),
    _r("azure_storage", "Azure storage connection string",
       r"(DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{40,})", "critical", 95),
    _r("azure_sas", "Azure SAS token", r"(\?sv=\d{4}-\d\d-\d\d&[^\s\"'`]*sig=[A-Za-z0-9%+/=]{20,})", "high", 85),
    _r("sentry_dsn", "Sentry DSN", r"(https://[0-9a-f]{32}@(?:o\d+\.)?(?:ingest\.)?sentry\.io/\d+)", "info", 90, public=True,
       note="Sentry DSNs are public by design."),
    _r("mapbox_public", "Mapbox public token", r"\b(pk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b", "info", 85, public=True),
    _r("mapbox_secret", "Mapbox secret token", r"\b(sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b", "high", 90),
    _r("cloudinary_url", "Cloudinary URL with API secret", r"\b(cloudinary://\d+:[\w\-]+@\w+)", "high", 90),
    _r("google_oauth_client", "Google OAuth client ID", r"\b(\d{6,}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b", "info", 90, public=True),
]

_BEARER = re.compile(r"\bBearer\s+([A-Za-z0-9_\-.=+/]{20,})")
_BASIC = re.compile(r"\bBasic\s+([A-Za-z0-9+/=]{16,})")

# --------------------------------------------------------------------------- generic (key-name driven)

_SECRET_KEY = re.compile(
    r"(?i)(api[_\-]?key|apikey|secret|passw(?:or)?d|passwd|pwd|auth[_\-]?token|access[_\-]?token|bearer|credential|"
    r"private[_\-]?key|client[_\-]?secret|access[_\-]?key|signing[_\-]?key|salt|webhook|token)"
)
_LABEL_SUFFIX = re.compile(
    r"(?i)(label|placeholder|text|title|msg|message|error|hint|desc|description|regex|pattern|type|field|name|length|"
    r"min|max|policy|required|valid|validation|rule|rules|enabled|expired|expires|expiry|expiration|url|uri|endpoint|"
    r"path|header|prefix|suffix|format|class|icon|help|tooltip|link|route|param|params|storage|cache|cookie|"
    r"strength|confirm|reset|forgot|visible|show|hide|toggle|status|state|count|size|input|button|action|id)$"
)
_PUBLIC_NAME = re.compile(
    r"(?i)(csrf|xsrf|nonce|captcha|sitekey|site[_\-]?key|publishable|public[_\-]?key|publickey|vapid|anon[_\-]?key)"
)
_KEY_AT_END = re.compile(r"""([A-Za-z_$][\w$\-]{1,60}|"[^"\n]{2,60}"|'[^'\n]{2,60}')\s*(?:\|\||\?\?|:|=)\s*$""")
_KV = re.compile(r"""["']?([A-Za-z_][\w\-]{2,50})["']?\s*[:=]\s*["']([^"'\s]{8,200})["']""")
_IDENT = re.compile(r"^[A-Za-z]+(?:[A-Z][a-z0-9]+)+$|^[a-z0-9]+(?:[_\-][a-z0-9]+)+$|^[A-Za-z]+(?:\.[A-Za-z0-9_]+)+$")


def _key_name_before(src: str, start: int) -> str | None:
    m = _KEY_AT_END.search(src[max(0, start - 90):start])
    return m.group(1).strip("\"'") if m else None


def generic_candidate(key: str, value: str, vendor: bool) -> tuple[Finding | None, str | None]:
    """Evaluate ``key: "value"`` as a hardcoded secret. Returns (finding, rejection_reason)."""
    if not _SECRET_KEY.search(key):
        return None, None
    if _PUBLIC_NAME.search(key):
        return None, f"key name '{key}' is public by design (CSRF/nonce/site key/public key)"
    if _LABEL_SUFFIX.search(key) and not re.search(r"(?i)(secret|key|token|passw)", key.rsplit(".", 1)[-1][-8:]):
        return None, f"key name '{key}' looks like UI/config metadata"
    ph = is_placeholder(value)
    if ph:
        return None, ph
    if re.search(r"\s", value) or value[0] in "/.#{<$%" or value.startswith(("http:", "https:")):
        return None, "value is text/URL/path/template, not a credential"
    if _IDENT.match(value):
        return None, "value is an identifier / i18n key / dotted path"
    if value.isalpha() and len(value) < 30:
        return None, "value is a plain word"
    if value.isdigit() and len(value) < 14:
        return None, "value is a short number"
    ent = entropy(value)
    if ent < 3.0 or (len(value) >= 16 and ent < 3.4):
        return None, f"low entropy ({ent:.2f} bits/char)"
    f = Finding("secret", value, 45, "medium", "generic_assignment", context="")
    f.why.append(f"key name '{key}' implies a credential")
    if len(value) >= 24:
        f.bump(10, "length >= 24")
    if ent >= 4.0:
        f.bump(10, f"high entropy ({ent:.2f})")
    if re.search(r"(?i)(secret|passw|private)", key):
        f.bump(8, "key name strongly implies a secret")
    if char_classes(value) >= 3:
        f.bump(5, "mixed character classes")
    if vendor:
        f.bump(-15, "found in vendor/library file")
    f.confidence = min(f.confidence, 80)
    if len(value) >= 32 and ent >= 4.0:
        f.severity = "high"
    f.meta["key"] = key
    return f, None


# --------------------------------------------------------------------------- scanner

def _context(src: str, start: int, end: int, value: str) -> str:
    a, b = max(0, start - 50), min(len(src), end + 30)
    snippet = src[a:b].replace(value, mask(value))
    return re.sub(r"\s+", " ", snippet)[:200]


def scrub_context(ctx: str, secrets: list[str]) -> str:
    """Remove every known secret (and any fragment >= 8 chars of one) from a display snippet.

    A snippet is cut from the source around one finding, so it can contain a *neighbouring* secret
    in full or in part; without this, "masked" reports would leak it.
    """
    if not ctx or not secrets:
        return ctx
    dead = [False] * len(ctx)
    for v in secrets:
        if len(v) < 8:
            continue
        for i in range(len(v) - 7):
            gram, j = v[i:i + 8], ctx.find(v[i:i + 8])
            while j != -1:
                for k in range(j, j + 8):
                    dead[k] = True
                j = ctx.find(gram, j + 1)
    out: list[str] = []
    for ch, d in zip(ctx, dead):
        if d:
            if not out or out[-1] != "…":
                out.append("…")
        else:
            out.append(ch)
    return "".join(out)


def scan_units(units: list[tuple[str, int, int, str]], src: str, vendor: bool = False,
               explain: bool = False) -> tuple[list[Finding], list[Rejection]]:
    """units: (text, start, end, kind) for each string/template/comment token."""
    found: dict[str, Finding] = {}
    rejected: list[Rejection] = []

    def rej(value: str, reason: str) -> None:
        if explain:
            rejected.append(Rejection("secret", mask(value), reason))

    def keep(f: Finding) -> None:
        old = found.get(f.value)
        if old is None or f.confidence > old.confidence:
            found[f.value] = f

    for text, start, end, tkind in units:
        # 1) provider rules
        for rule in RULES:
            for m in rule.pattern.finditer(text):
                value = m.group(1)
                ph = is_placeholder(value) if rule.id not in ("private_key",) else None
                if ph:
                    rej(value, f"{rule.id}: {ph}")
                    continue
                f = Finding("secret", value, rule.confidence, rule.severity, rule.id, hint=rule.title)
                f.why.append(f"matches {rule.title} format")
                if rule.note:
                    f.meta["note"] = rule.note
                if rule.validator:
                    v = rule.validator(value, m=m, text=text)
                    if not v.ok:
                        rej(value, f"{rule.id}: {'; '.join(v.why)}")
                        continue
                    f.bump(v.delta)
                    f.why += v.why
                    f.meta.update(v.meta)
                    if v.severity:
                        f.severity = v.severity
                if rule.public:
                    f.meta["public_by_design"] = True
                if tkind == "comment":
                    f.bump(-5, "found inside a comment")
                    f.meta["in_comment"] = True
                if "{expr}" in text[max(0, m.start() - 8): m.end() + 8]:
                    f.bump(-20, "adjacent to template expression (partially dynamic)")
                f.context = _context(src, start, end, value)
                keep(f)

        # 2) Bearer / Basic header literals
        for m in _BEARER.finditer(text):
            tok = m.group(1)
            if tok.startswith("eyJ") or is_placeholder(tok) or "{expr}" in tok or entropy(tok) < 3.3:
                continue
            f = Finding("secret", tok, 62, "medium", "bearer_literal", hint="Hardcoded Bearer token")
            f.why.append("literal 'Bearer <token>' string")
            f.context = _context(src, start, end, tok)
            keep(f)
        for m in _BASIC.finditer(text):
            v = v_basic_header(m.group(1))
            if not v.ok:
                rej(m.group(1), f"basic_header: {'; '.join(v.why)}")
                continue
            f = Finding("secret", m.group(1), 80, "high", "basic_header", hint="Hardcoded Basic auth header")
            f.why += v.why
            f.context = _context(src, start, end, m.group(1))
            keep(f)

        # 3) generic: key-name before the string literal
        if tkind in ("str", "tpl") and 8 <= len(text) <= 200:
            key = _key_name_before(src, start)
            if key:
                f, why = generic_candidate(key, text, vendor)
                if f:
                    f.context = _context(src, start, end, text)
                    keep(f)
                elif why:
                    rej(text, f"generic[{key}]: {why}")

        # 4) generic: key/value pairs *inside* a string (JSON.parse('{"apiKey":"..."}') etc.)
        if tkind in ("str", "tpl") and len(text) >= 20 and ("{" in text or "=" in text):
            for m in _KV.finditer(text):
                f, why = generic_candidate(m.group(1), m.group(2), vendor)
                if f:
                    f.context = _context(src, start, end, m.group(2))
                    keep(f)
                elif why:
                    rej(m.group(2), f"generic[{m.group(1)}]: {why}")

    findings = list(found.values())
    _pair_aws(findings, src)
    # a bare Bearer/generic hit that is really a longer provider hit is redundant
    provider_values = [f.value for f in findings if f.rule not in ("generic_assignment", "bearer_literal")]
    findings = [f for f in findings
                if f.rule not in ("generic_assignment", "bearer_literal")
                or not any(f.value in pv or pv in f.value for pv in provider_values)]
    findings.sort(key=lambda f: (-SEV_RANK[f.severity], -f.confidence))
    return findings, rejected


_B64_40 = re.compile(r"(?<=[\"'`])[A-Za-z0-9/+]{40}(?=[\"'`])")  # a standalone 40-char literal, not a slice of a longer token


def _pair_aws(findings: list[Finding], src: str) -> None:
    """If an AWS key ID has a 40-char high-entropy string within 400 chars, call it a key pair."""
    for f in findings:
        if f.rule != "aws_access_key_id":
            continue
        i = src.find(f.value)
        if i < 0:
            continue
        window = src[max(0, i - 400): i + 400]
        for m in _B64_40.finditer(window):
            cand = m.group(0)
            if cand != f.value and entropy(cand) > 4.2 and not is_placeholder(cand) and char_classes(cand) >= 3:
                f.severity = "critical"
                f.bump(8, "paired 40-char secret access key candidate nearby")
                f.meta["paired_secret"] = mask(cand)
                break
