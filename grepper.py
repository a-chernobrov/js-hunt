#!/usr/bin/env python3
"""
grepper.py — Анализ собранных JS файлов на предмет:
  1. Секретов и ключей (API keys, tokens, passwords)
  2. API endpoint'ов (swagger, graphql, REST)
  3. Чувствительных путей (admin, debug, etc.)

Usage:
  python3 grepper.py [-o output] [-j jobs] [--json] [--save-txt]
                     [--severity secrets|all] [--no-color]
"""

import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
from collections import defaultdict

try:
    import jsbeautifier as _jsb
    _BEAUTIFY_OPTS = _jsb.default_options()
    _BEAUTIFY_OPTS.max_preserve_newlines = 2
    HAS_BEAUTIFIER = True
except ImportError:
    HAS_BEAUTIFIER = False

# ─── ANSI Colors ─────────────────────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

USE_COLOR = True

def col(color: str, text: str) -> str:
    return f"{color}{text}{C.RESET}" if USE_COLOR else text


# ─── Patterns ────────────────────────────────────────────────────────────────

GOOGLE_MAPS_PUBKEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")

SECRET_PATTERNS = {
    "AWS Access Key":          r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":          r"(?i)aws[._ -]?(secret|access|session)[._ -]?key[ .:='\"]+[A-Za-z0-9/+=]{40}",
    "Google API Key":          r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Client":     r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase DB URL":         r"['\"][A-Za-z0-9_]+-[A-Za-z0-9_]{6}\.firebaseio\.com['\"]",
    "Slack Token":             r"xox[baprs]-[0-9a-zA-Z\-]{10,70}",
    "Slack Webhook":           r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,60}",
    "GitHub Token":            r"gh[pousr]_[A-Za-z0-9_]{36,255}",
    "GitLab Token":            r"glpat-[0-9A-Za-z\-]{20,34}",
    "JWT Token":               r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}",
    "Bearer Token":            r"['\"]Bearer\s+[A-Za-z0-9\-._~+/]{20,}['\"]",
    "Basic Auth":              r"['\"]Basic\s+[A-Za-z0-9+/=]{10,}['\"]",
    "Generic API Key":         r"(?i)(api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./]{16,64}",
    "MongoDB URI":             r"mongodb(?:\+srv)?://[^\s'\"]{8,}",
    "PostgreSQL URI":          r"postgres(?:ql)?://[^\s'\"]{8,}",
    "MySQL URI":               r"mysql://[^\s'\"]{8,}",
    "Redis URI":               r"redis://[^\s'\"]{8,}",
    "Private Key Block":       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Stripe Live Key":         r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}",
    "Twilio SID/Token":        r"AC[0-9a-fA-F]{32}|SK[0-9a-fA-F]{32}",
    "SendGrid Key":            r"SG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}",
    "Telegram Bot Token":      r"[0-9]{8,11}:[A-Za-z0-9\-_]{35}",
    "Mapbox Token":            r"pk\.[A-Za-z0-9]{60}\.mapbox",
    "Sentry DSN":              r"https://[0-9a-f]{32}@[A-Za-z0-9.\-]+\.ingest\.sentry\.io",
    "Google Service Account":  r'"type"\s*:\s*"service_account"',
    "NPM Token":               r"npm_[A-Za-z0-9]{36}",
    "Heroku API Key":          r"(?i)heroku[^\n]{0,30}['\"]?[A-Za-z0-9\-]{30,40}['\"]?",
    "Password Assignment":     r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^\s'\"]{8,60}['\"]",
    "Secret Assignment":       r"(?i)(secret|secret_key|secretKey|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-./]{8,60}['\"]",
    "Authorization Header":    r"(?i)headers\s*[=:]\s*\{[^}]*['\"](?:Authorization|X-Api-Key)['\"][^}]*:\s*['\"][^'\"]{8,}",
    "Internal IPv4":           r"(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|localhost(?::\d{2,5})?)(?:/[^\s'\"]{2,}|:\d{2,5})",
    "S3 Bucket URL":           r"[a-z0-9][a-z0-9\-]{2,62}\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com",
    "SMTP Credentials":        r"(?i)smtp[^\n]{0,60}(?:user|pass|login|password)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "Vite /@fs/ LFI":          r"/@fs/[/a-zA-Z0-9_.\-]{4,}",
    "Vite Env Variable":       r"VITE_[A-Z0-9_]{3,}\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "import.meta.env":         r"import\.meta\.env\.VITE_[A-Z0-9_]{3,}",
    
}

API_PATTERNS = {
    "Swagger/OpenAPI URL":     r"['\"]/(?:api/)?(?:docs|swagger|openapi\.json|api-docs|spec)['\"]",
    "GraphQL Endpoint":        r"['\"]/(?:api/)?graphql['\"]",
    "API Route v1/v2/v3":      r"['\"]/(?:api/)?v[1-9]/[a-zA-Z0-9_/{}:\-]+['\"]",
    "REST Resource":           r"['\"]/(?:api|rest)/[a-z][a-zA-Z0-9_/:\-]{3,}['\"]",
    "HTTP Method + Route":     r"(?i)(?:get|post|put|delete|patch)\s*\(\s*['\"][/][a-z0-9_/{}:.\-]+['\"]",
    "Relative API Path": r"(?:get|post|put|delete|patch)\s*\(\s*['\"][a-z][a-z0-9_/\-]+\.(?:json|xml|csv|graphql)['\"]",
    "External API Call":       r"(?:axios|fetch)\s*\(\s*['\"]https?://[a-zA-Z0-9.\-]+/[^'\"]{4,}['\"]",
    "GraphQL Query/Mutation":  r"(?:query|mutation)\s+\w+\s*[({]",
    "WebSocket URL":           r"wss?://[a-zA-Z0-9.\-]+/[^\s'\"]{3,}",
    "Template Literal API":    r"`\$\{[^}]+\}/([a-z][a-z0-9_/\-?=&.]{2,})",
    "Fetch/Axios Template":    r"(?:fetch|axios)\s*\(\s*`[^`]{0,60}\$\{[^}]+\}/([a-z][a-z0-9_/\-?=&.]{2,})",
    
}

SENSITIVE_PATTERNS = {
    "Admin/Dashboard":   r"['\"]/(?:admin|administrator|backoffice|dashboard|manage)[/'\"?]",
    "Debug/Dev":         r"['\"]/(?:debug|dev|_debug|phpinfo|test|testing)[/'\"?]",
    "Health/Metrics":    r"['\"]/(?:healthz?|readyz|livez|metrics|prometheus|actuator)[/'\"?]",
    "Config/Env":        r"['\"]/(?:config|configuration|env|\.env|settings|setup|install)[/'\"?]",
    "Internal/Private":  r"['\"]/(?:internal|private|secret|hidden|restricted)[/'\"?]",
    "Auth Endpoints":    r"['\"]/(?:login|register|signin|signup|auth|oauth|callback|logout|sso)[/'\"?]",
    "Upload/File":          r'[\'"]/(?:upload|download|files|media|attachments)[/\'"?]',
    "PHP Endpoint":         r'[\'""][^\s\'"]{0,60}\.php(?:\?[^\s\'"]{0,40})?[\'"]',
    "PHP Upload Handler":   r'(?i)[\'"]\.\./[^\s\'"]{0,80}(?:upload|fileupload|file[_-]?upload)[^\s\'"]{0,40}\.php[\'"]',
    "Vulnerable Upload Lib":r'(?i)(jquery[.\-]file[.\-]upload|blueimp|plupload|dropzone)[^\s\'"]{0,60}server/php',
    "DB/Storage":        r"['\"]/(?:database|db|backup|export|import|elasticsearch|kibana)[/'\"?]",
    "Webhook/Callback":  r"['\"]/(?:webhook|callback|hook|notify|notification)[/'\"?]",
    "CI/CD":             r"['\"]/(?:jenkins|gitlab|ci|cd|deploy|pipeline|runner)[/'\"?]",
    "Monitoring":        r"['\"]/(?:monitor(?:ing)?|grafana|sentry|zabbix|datadog)[/'\"?]",
    "WebSocket Path":    r"['\"]/(?:ws|socket|websocket|sockjs|stream)[/'\"?]",
    "Proxy/Tunnel":      r"['\"]/(?:proxy|vpn|tunnel|forward)[/'\"?]",
    "Kubernetes/API":    r"['\"]/(?:api/v1|apis/apps|kube|k8s)[/'\"?]",
    "Bitrix":            r"['\"]/(?:bitrix|rest/\d+/[a-z]+)[/'\"?]",
    "Vite Dev Paths":    r"['\"/](?:@vite|@fs|@id|__vite_ping)[/'\"?]?",
    "Vite Proxy Config": r"(?i)proxy\s*:\s*\{[^}]{0,200}target\s*:\s*['\"][^'\"]{8,}['\"]",
}


# ─── Scanner ─────────────────────────────────────────────────────────────────

GOOGLE_MAPS_CONTEXT_RE = re.compile(
    r"(?i)(maps|places|geocod|directions|embed\.googleapis|maps\.googleapis)",
)

def _is_public_google_key(val: str, context: str) -> bool:
    return bool(GOOGLE_MAPS_CONTEXT_RE.search(context))


def _scan_patterns(lines: list, patterns: dict, flags=0, max_val=120) -> dict:
    results = defaultdict(list)
    seen = defaultdict(set)

    # URL patterns that indicate false positives
    _FP_URL_RE = re.compile(r"/jsd/|cdn-cgi|challenge-platform|\.cloudflare\.")

    for lineno, line in enumerate(lines, 1):
        for name, pat in patterns.items():
            for m in re.finditer(pat, line, flags):
                val = m.group()[:max_val].strip()
                if len(val) < 8 or val in seen[name]:
                    continue
                # Skip values found inside known CDN/challenge URLs
                if _FP_URL_RE.search(line):
                    continue
                seen[name].add(val)
                note = None
                if name == "Google API Key" and _is_public_google_key(val, line):
                    note = "public?"
                results[name].append({
                    "value":   val,
                    "line_no": lineno,
                    "context": line.strip()[:200],
                    "note":    note,
                })

    return dict(results)


def _maybe_beautify(text: str) -> list:
    lines = text.splitlines()
    if HAS_BEAUTIFIER and len(lines) <= 5 and len(text) > 500:
        try:
            text = _jsb.beautify(text, _BEAUTIFY_OPTS)
            lines = text.splitlines()
        except Exception:
            pass
    return lines


_SOURCE_EXTS = {".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".vue", ".svelte"}

# Files to skip entirely — known false positive sources
_FP_SKIP_FILES = re.compile(
    r"cdn-cgi[_/]challenge|challenge-platform[_/].*jsd|"
    r"_cf_chl|cloudflare-static",
    re.IGNORECASE
)

def scan_file(args: tuple) -> dict:
    filepath, domain_label, do_beautify = args
    filepath = Path(filepath)

    # Skip known Cloudflare challenge/CDN files — they generate false positives
    if _FP_SKIP_FILES.search(filepath.name):
        return {
            "file": str(filepath), "domain": domain_label,
            "size": 0, "beautified": False, "error": "skipped:fp",
            "secrets": {}, "apis": {}, "sensitive": {},
        }

    result = {
        "file":      str(filepath),
        "domain":    domain_label,
        "size":      0,
        "beautified": False,
        "error":     None,
        "secrets":   {},
        "apis":      {},
        "sensitive": {},
    }

    try:
        data = filepath.read_bytes()
        result["size"] = len(data)
        text = data.decode("utf-8", errors="replace")
        if len(text) < 50:
            return result

        raw_lines = text.splitlines()
        result["minified"] = len(raw_lines) <= 5 and len(text) > 500

        is_source = filepath.suffix.lower() in _SOURCE_EXTS or "sources" in filepath.parts
        lines = text.splitlines() if is_source else _maybe_beautify(text)

        result["secrets"]   = _scan_patterns(lines, SECRET_PATTERNS)
        result["apis"]      = _scan_patterns(lines, API_PATTERNS,       re.IGNORECASE)
        result["sensitive"] = _scan_patterns(lines, SENSITIVE_PATTERNS, re.IGNORECASE)

    except Exception as e:
        result["error"] = str(e)

    return result


# ─── Merge ───────────────────────────────────────────────────────────────────

def merge_results(results: list, output_root: Path) -> dict:
    summary = {
        "scan_time":      datetime.now().isoformat(),
        "total_files":    0,
        "minified_files": 0,
        "total_size_mb":  0.0,
        "domains":       defaultdict(lambda: {
            "files": 0, "size_mb": 0.0,
            "secrets":   defaultdict(list),
            "apis":      defaultdict(list),
            "sensitive": defaultdict(list),
        }),
        "all_secrets":   defaultdict(list),
        "all_apis":      defaultdict(list),
        "all_sensitive": defaultdict(list),
        "counts":        {"secrets": 0, "apis": 0, "sensitive": 0},
    }

    global_seen = {
        "secrets":   defaultdict(set),
        "apis":      defaultdict(set),
        "sensitive": defaultdict(set),
    }
    file_counts = {
        "secrets":   defaultdict(lambda: defaultdict(int)),
        "apis":      defaultdict(lambda: defaultdict(int)),
        "sensitive": defaultdict(lambda: defaultdict(int)),
    }

    for r in results:
        if r.get("error"):
            continue
        domain = r["domain"]
        summary["total_files"]   += 1
        summary["total_size_mb"] += r["size"] / (1024 * 1024)
        if r.get("minified"):
            summary["minified_files"] += 1
        d = summary["domains"][domain]
        d["files"]   += 1
        d["size_mb"] += r["size"] / (1024 * 1024)

        for cat_key in ("secrets", "apis", "sensitive"):
            for cat, matches in r[cat_key].items():
                for match in matches:
                    val = match["value"]
                    file_counts[cat_key][cat][val] += 1
                    if val in global_seen[cat_key][cat]:
                        continue
                    global_seen[cat_key][cat].add(val)
                    enriched = dict(match, file=r["file"], domain=domain)
                    d[cat_key][cat].append(enriched)
                    summary[f"all_{cat_key}"][cat].append(enriched)

    for cat_key in ("secrets", "apis", "sensitive"):
        for cat, matches in summary[f"all_{cat_key}"].items():
            for m in matches:
                m["file_count"] = file_counts[cat_key][cat].get(m["value"], 1)

    for key in ("secrets", "apis", "sensitive"):
        summary["counts"][key] = sum(len(v) for v in summary[f"all_{key}"].values())

    return summary


def collect_vite_info(output: Path) -> dict:
    """Collect vite_info.json from all domain directories."""
    vite_findings = {}
    for domain_dir in sorted(output.iterdir()):
        if not domain_dir.is_dir():
            continue
        vite_info_file = domain_dir / "vite_info.json"
        if not vite_info_file.exists():
            continue
        try:
            data = json.loads(vite_info_file.read_text(encoding="utf-8"))
            # Attach LFI file contents if any
            lfi_dir = domain_dir / "vite_lfi"
            lfi_contents = {}
            if lfi_dir.exists():
                for f in sorted(lfi_dir.iterdir()):
                    try:
                        lfi_contents[f.name] = f.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        pass
            data["lfi_contents"] = lfi_contents
            vite_findings[domain_dir.name] = data
        except Exception:
            continue
    return vite_findings


# ─── Report ──────────────────────────────────────────────────────────────────

def _section(title: str):
    print(f"\n{col(C.BOLD, '='*70)}")
    print(f"  {col(C.BOLD, title)}")
    print(col(C.BOLD, '='*70))


def _print_category(cat: str, matches: list, color: str, show_context: bool = True):
    print(f"\n  {col(color, f'[{cat}]')} {col(C.DIM, f'({len(matches)} unique)')}")
    domains = sorted({m["domain"] for m in matches})
    print(f"  {col(C.DIM, 'Domains: ' + ', '.join(domains))}")
    for m in matches[:5]:
        fname      = Path(m["file"]).name
        lineno     = f"L{m['line_no']:>5}"
        val        = m["value"][:100]
        fc         = m.get("file_count", 1)
        note       = m.get("note")
        note_str   = f" {col(C.DIM, f'[{note}]')}" if note else ""
        fc_str     = f" {col(C.DIM, f'in {fc} file(s)')}" if fc > 1 else ""
        print(f"    {col(C.DIM, lineno)}  {col(color, val)}{note_str}{fc_str}")
        if show_context and m["context"].strip() != m["value"].strip():
            print(f"           {col(C.DIM, m['context'][:130])}")
        print(f"           {col(C.DIM, fname)}")
    if len(matches) > 5:
        print(f"    {col(C.DIM, f'... and {len(matches)-5} more')}")


def print_report(summary: dict, severity: str):
    print(f"\n{col(C.BOLD, '#'*70)}")
    print(f"  {col(C.BOLD, 'JS ANALYSIS REPORT')}")
    print(f"  Scan time: {summary['scan_time']}")
    print(col(C.BOLD, '#'*70))
    print(f"\n  Files scanned : {summary['total_files']}  (minified: {summary.get('minified_files', 0)})")
    print(f"  Total size    : {summary['total_size_mb']:.2f} MB")
    print(f"  Domains       : {len(summary['domains'])}")
    print(f"  {col(C.RED,    'Secrets')}       : {summary['counts']['secrets']}")
    print(f"  {col(C.YELLOW, 'API refs')}      : {summary['counts']['apis']}")
    print(f"  {col(C.CYAN,   'Sensitive')}     : {summary['counts']['sensitive']}")

    _section("SECRETS & KEYS")
    if summary["all_secrets"]:
        for cat in sorted(summary["all_secrets"]):
            _print_category(cat, summary["all_secrets"][cat], C.RED, show_context=True)
    else:
        print(f"  {col(C.DIM, '(none found)')}")

    if severity == "secrets":
        print(f"\n{col(C.BOLD, '#'*70)}\n")


    _section("API ENDPOINTS")
    if summary["all_apis"]:
        for cat in sorted(summary["all_apis"]):
            _print_category(cat, summary["all_apis"][cat], C.YELLOW, show_context=False)
    else:
        print(f"  {col(C.DIM, '(none found)')}")

    _section("SENSITIVE PATHS")
    if summary["all_sensitive"]:
        for cat in sorted(summary["all_sensitive"]):
            _print_category(cat, summary["all_sensitive"][cat], C.CYAN, show_context=False)
    else:
        print(f"  {col(C.DIM, '(none found)')}")

    _section("PER-DOMAIN SUMMARY")
    for domain in sorted(summary["domains"]):
        d = summary["domains"][domain]
        s = sum(len(v) for v in d["secrets"].values())
        a = sum(len(v) for v in d["apis"].values())
        n = sum(len(v) for v in d["sensitive"].values())
        if s + a + n == 0:
            continue
        print(f"\n  {col(C.BOLD, domain)}")
        print(f"    Files: {d['files']}  Size: {d['size_mb']:.2f} MB")
        print(f"    {col(C.RED, f'Secrets: {s}')}  {col(C.YELLOW, f'API: {a}')}  {col(C.CYAN, f'Sensitive: {n}')}")
        for cat_key, color in (("secrets", C.RED), ("apis", C.YELLOW), ("sensitive", C.CYAN)):
            if d[cat_key]:
                top = sorted(d[cat_key], key=lambda k: len(d[cat_key][k]), reverse=True)[:3]
                parts = [f"{t}({len(d[cat_key][t])})" for t in top]
                print(f"    {col(color, cat_key.capitalize())}: {', '.join(parts)}")

    print(f"\n{col(C.BOLD, '#'*70)}\n")

def print_vite_summary(vite_data: dict):
    """Print Vite findings summary."""
    if not vite_data:
        return
    detected = [d for d, v in vite_data.items() if v.get("confirmed")]
    if not detected:
        return

    print(f"\n{col(C.BOLD, '='*70)}")
    print(f"  {col(C.BOLD, 'VITE CVE FINDINGS')}")
    print(col(C.BOLD, '='*70))

    for domain, info in vite_data.items():
        confirmed = info.get("confirmed", [])
        lfi_files = info.get("lfi_files", [])
        if not confirmed:
            continue
        print(f"\n  {col(C.BOLD, domain)}")
        print(f"    Root: {col(C.YELLOW, info.get('root_path', '/'))}")
        for cve in confirmed:
            print(f"    {col(C.RED + C.BOLD, '[CVE]')} {col(C.RED, cve)}")
        if lfi_files:
            print(f"    {col(C.RED, f'LFI files read: {len(lfi_files)}')}")
            for f in lfi_files[:5]:
                print(f"      {col(C.DIM, f)}")
            if len(lfi_files) > 5:
                print(f"      {col(C.DIM, f'... and {len(lfi_files)-5} more')}")

    print(f"\n{col(C.BOLD, '#'*70)}\n")



def save_txt_report(summary: dict, output: Path):
    lines = [
        "JS ANALYSIS REPORT",
        f"Scan time: {summary['scan_time']}",
        f"Files: {summary['total_files']}  Size: {summary['total_size_mb']:.2f} MB",
        f"Secrets: {summary['counts']['secrets']}  API: {summary['counts']['apis']}  Sensitive: {summary['counts']['sensitive']}",
        "",
    ]
    for section, key in (("SECRETS", "all_secrets"), ("API ENDPOINTS", "all_apis"), ("SENSITIVE PATHS", "all_sensitive")):
        lines += [f"{'='*60}", section, f"{'='*60}"]
        for cat, matches in sorted(summary[key].items()):
            lines.append(f"\n[{cat}] ({len(matches)} unique)")
            for m in matches:
                fc = m.get("file_count", 1)
                fc_tag = f"[{fc}f] " if fc > 1 else ""
                lines.append(f"  L{m['line_no']:>5}  {fc_tag}{m['value'][:120]}")
                lines.append(f"         {Path(m['file']).name}")
        lines.append("")

    out = output / "js_analysis_report.txt"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"[*] TXT report saved: {out}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    global USE_COLOR

    parser = argparse.ArgumentParser(description="JS grepper — secrets, APIs, sensitive paths")
    parser.add_argument("-o", "--output",   default="output",
                        help="Output dir with JS data (default: ./output)")
    parser.add_argument("-t", "--target",   action="append", default=None, metavar="PATH",
                        help="Arbitrary path to scan recursively (repeatable). Skips -o structure.")
    parser.add_argument("-d", "--domain",   default=None,
                        help="Scan only this domain (substring match, e.g. 'erp.quart.pro')")
    parser.add_argument("-j", "--jobs",     type=int, default=4,
                        help="Parallel workers (default: 4)")
    parser.add_argument("--json",           action="store_true", help="Save JSON report")
    parser.add_argument("--save-txt",       action="store_true", help="Save plain text report")
    parser.add_argument("--severity",       choices=["secrets", "all"], default="all",
                        help="'secrets' — only secrets section; 'all' — everything (default)")
    parser.add_argument("--no-color",       action="store_true", help="Disable ANSI colors")
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    js_files = []

    if args.target:
        # ── Arbitrary mode: scan any path, no domain structure expected ──
        root = Path(args.target[0])  # used as output root for report paths
        for t in args.target:
            p = Path(t)
            if not p.exists():
                print(f"[!] Path not found: {p}")
                continue
            found = list(p.rglob("*.js"))
            print(f"[*] {p} → {len(found)} JS file(s)")
            js_files.extend(found)
        output = root
    else:
        # ── Default mode: output/<domain>/js/ structure ──
        output = Path(args.output)
        if not output.is_dir():
            print(f"[!] Directory not found: {output}")
            sys.exit(1)
        for domain_dir in sorted(output.iterdir()):
            if not domain_dir.is_dir():
                continue
            if args.domain and args.domain.lower() not in domain_dir.name.lower():
                continue
            js_dir = domain_dir / "js"
            if js_dir.is_dir():
                js_files.extend(js_dir.rglob("*.js"))
            sources_dir = domain_dir / "sources"
            if sources_dir.is_dir():
                for ext in ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.vue", "*.svelte"):
                    js_files.extend(sources_dir.rglob(ext))

    print(f"[*] Total: {len(js_files)} file(s) to scan")
    if not js_files:
        print("[!] No files found.")
        sys.exit(1)

    do_beautify = not getattr(args, 'no_beautify', False)

    # Build (filepath, domain_label, do_beautify) tuples
    scan_args = []
    for f in js_files:
        f = Path(f)
        if args.target:
            # Arbitrary mode: use parent dir name as domain label
            # Walk up to find a meaningful name (skip generic names like 'js', 'jsfiles')
            SKIP = {'js', 'jsfiles', 'javascript', 'static', 'assets', 'dist', 'build'}
            label = f.parent.name
            for part in reversed(f.parts[:-1]):
                if part.lower() not in SKIP:
                    label = part
                    break
        else:
            # Default mode: first part relative to output is the domain dir
            try:
                label = f.relative_to(output).parts[0]
            except ValueError:
                label = f.parent.name
        scan_args.append((str(f), label, do_beautify))

    results = []
    with ProcessPoolExecutor(max_workers=args.jobs) as ex:
        futures = {ex.submit(scan_file, a): a for a in scan_args}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                results.append(fut.result())
            except Exception as e:
                print(f"  [!] {futures[fut][0][0]}: {e}")
            if i % 50 == 0:
                print(f"  Progress: {i}/{len(js_files)}")

    summary = merge_results(results, output)
    print_report(summary, args.severity)

    # Vite CVE summary
    if not args.target:
        vite_data = collect_vite_info(output)
        print_vite_summary(vite_data)

    if args.save_txt:
        save_txt_report(summary, output)

    if args.json:
        vite_data = {}
        if not args.target:
            vite_data = collect_vite_info(output)

        out = output / "js_analysis_report.json"
        out.write_text(json.dumps({
            "scan_time":     summary["scan_time"],
            "total_files":   summary["total_files"],
            "total_size_mb": round(summary["total_size_mb"], 2),
            "domains":       len(summary["domains"]),
            "counts":        summary["counts"],
            "secrets":       dict(summary["all_secrets"]),
            "apis":          dict(summary["all_apis"]),
            "sensitive":     dict(summary["all_sensitive"]),
            "vite":          vite_data,
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[*] JSON report saved: {out}")


if __name__ == "__main__":
    main()