#!/usr/bin/env python3
"""
js_recon.py — JS recon tool for external pentest
Usage: python3 js_recon.py -f subdomains.txt [-w wordlist.txt] [-t 10] [-o output]
"""

import asyncio
import argparse
import sys
import re
import json
import base64
import httpx
from pathlib import Path
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright

# ─── Default JS wordlist (filename brute) ────────────────────────────────────
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


# ─── Stage 1: Playwright JS collection ───────────────────────────────────────

async def collect_js_playwright(url: str, timeout: int = 20) -> list[str]:
    """Open URL in headless Chromium, intercept all .js requests."""
    js_urls: list[str] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = await browser.new_context(
            user_agent=UA,
            ignore_https_errors=True,      # self-signed certs
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        page = await ctx.new_page()

        def on_request(req):
            if req.resource_type == "script":
                u = req.url
                if u not in js_urls:
                    js_urls.append(u)

        page.on("request", on_request)

        try:
            resp = await page.goto(
                url,
                timeout=timeout * 1000,
                wait_until="networkidle",
            )
            # If https failed, retry http
            if resp is None or resp.status >= 400:
                if url.startswith("https://"):
                    fallback = url.replace("https://", "http://", 1)
                    await page.goto(
                        fallback,
                        timeout=timeout * 1000,
                        wait_until="networkidle",
                    )
            # Extra wait for lazy-loaded scripts
            await page.wait_for_timeout(2000)
        except Exception:
            # Try http fallback silently
            if url.startswith("https://"):
                try:
                    fallback = url.replace("https://", "http://", 1)
                    await page.goto(
                        fallback,
                        timeout=timeout * 1000,
                        wait_until="networkidle",
                    )
                    await page.wait_for_timeout(2000)
                except Exception:
                    pass
        finally:
            await browser.close()

    return js_urls


# ─── Stage 2: Brute-force sibling JS files ───────────────────────────────────

async def brute_js_names(
    base_dirs: list[str],
    wordlist: list[str],
    concurrency: int = 20,
) -> list[str]:
    """
    For each base directory, try wordlist filenames with .js extension.
    Return URLs that respond with status 200 and JS content-type.
    """
    found: list[str] = []
    sem = asyncio.Semaphore(concurrency)

    async def probe(client: httpx.AsyncClient, url: str):
        async with sem:
            try:
                r = await client.get(url, timeout=8, follow_redirects=True)
                ct = r.headers.get("content-type", "")
                if r.status_code == 200 and (
                    "javascript" in ct or url.endswith(".js")
                ):
                    found.append(url)
            except Exception:
                pass

    limits = httpx.Limits(max_connections=50, max_keepalive_connections=20)
    async with httpx.AsyncClient(
        verify=False,
        headers={"User-Agent": UA},
        limits=limits,
    ) as client:
        tasks = []
        seen = set()
        for base in base_dirs:
            for name in wordlist:
                candidate = f"{base}{name}.js"
                if candidate not in seen:
                    seen.add(candidate)
                    tasks.append(probe(client, candidate))
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


def extract_sourcemap_url(content: bytes) -> str | None:
    tail = content[-4096:]
    try:
        text = tail.decode("utf-8", errors="replace")
    except Exception:
        return None
    m = re.search(r"//[#@]\s*sourceMappingURL=([^\s]+)", text)
    return m.group(1).strip() if m else None


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


async def process_sourcemap(
    js_url: str,
    js_content: bytes,
    domain_dir: Path,
    client: httpx.AsyncClient,
):
    mapping_url = extract_sourcemap_url(js_content)
    if not mapping_url:
        return

    js_filename = urlparse(js_url).path.rsplit("/", 1)[-1]
    sourcemaps_dir = domain_dir / "sourcemaps"
    sources_dir = domain_dir / "sources"
    sourcemaps_dir.mkdir(parents=True, exist_ok=True)
    sources_dir.mkdir(parents=True, exist_ok=True)

    if mapping_url.startswith("data:"):
        map_data = extract_inline_map(mapping_url)
        if map_data:
            map_path = sourcemaps_dir / f"{js_filename}.map"
            map_path.write_text(json.dumps(map_data, ensure_ascii=False, indent=2))
            print(f"  [map] inline → {map_path}")
    else:
        resolved = resolve_map_url(js_url, mapping_url)
        if not resolved:
            return
        try:
            r = await client.get(resolved, timeout=15, follow_redirects=True)
            if r.status_code != 200:
                return
            map_raw = r.content
            map_path = sourcemaps_dir / f"{js_filename}.map"
            map_path.write_bytes(map_raw)
            print(f"  [map] {resolved} → {map_path}")
            try:
                map_data = json.loads(map_raw)
            except Exception:
                return
        except Exception:
            return

    sources = map_data.get("sources", [])
    contents = map_data.get("sourcesContent", [])

    saved = 0
    for i, src_path in enumerate(sources):
        if not src_path:
            continue
        src_path = re.sub(r"^(webpack://|webpack:///|\.\/)", "", src_path)
        content_str = contents[i] if i < len(contents) and contents[i] is not None else None
        if content_str is None:
            continue
        dest = safe_path(sources_dir, src_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content_str, encoding="utf-8")
        saved += 1

    if saved:
        print(f"  [src] Extracted {saved} source file(s) → {sources_dir}")


async def download_js_files(urls: list[str], domain_dir: Path):
    js_dir = domain_dir / "js"
    js_dir.mkdir(parents=True, exist_ok=True)

    downloaded: list[tuple[str, bytes]] = []

    async def fetch(client: httpx.AsyncClient, url: str):
        try:
            r = await client.get(url, timeout=15, follow_redirects=True)
            if r.status_code == 200:
                path = urlparse(url).path.lstrip("/").replace("/", "_")
                (js_dir / path).write_bytes(r.content)
                return url, r.content
        except Exception:
            pass
        return None, None

    async with httpx.AsyncClient(verify=False, headers={"User-Agent": UA}) as client:
        results = await asyncio.gather(*[fetch(client, u) for u in urls])
        ok = [(url, content) for url, content in results if url]
        print(f"  [+] Downloaded {len(ok)}/{len(urls)} JS file(s) → {js_dir}")

        for js_url, js_content in ok:
            await process_sourcemap(js_url, js_content, domain_dir, client)




async def process_subdomain(
    raw: str,
    output_dir: Path,
    wordlist: list[str],
    timeout: int,
    semaphore: asyncio.Semaphore,
    verbose: bool,
    download: bool,
):
    url = normalize(raw)
    if not url:
        return

    slug = domain_slug(url)
    async with semaphore:
        print(f"[*] {url}")

        # Stage 1 — collect JS via headless browser
        try:
            js_urls = await collect_js_playwright(url, timeout=timeout)
        except Exception as e:
            print(f"  [!] Playwright error: {e}", file=sys.stderr)
            js_urls = []

        if verbose:
            for u in js_urls:
                print(f"  [js] {u}")

        print(f"  [+] Found {len(js_urls)} JS file(s)")

        # Stage 2 — brute all dirs from target host only (skip CDNs)
        target_host = urlparse(url).netloc
        target_js = [u for u in js_urls if urlparse(u).netloc == target_host]
        base_dirs = list({base_dir_of(u) for u in target_js})

        bruted: list[str] = []
        if base_dirs:
            print(f"  [*] Bruting {len(wordlist)} names in {len(base_dirs)} dir(s)…")
            bruted = await brute_js_names(base_dirs, wordlist)
            # Exclude already-known URLs
            bruted = [u for u in bruted if u not in js_urls]
            if verbose:
                for u in bruted:
                    print(f"  [brute] {u}")
            print(f"  [+] Brute found {len(bruted)} new JS file(s)")

        # Save — only target-domain JS in js_files.txt
        js_f, br_f = save_results(output_dir, slug, target_js, bruted)
        print(f"  [>] {js_f}")
        print(f"  [>] {br_f}")

        # Download if requested
        if download:
            all_js = list(set(target_js + bruted))
            await download_js_files(all_js, output_dir / slug)


# ─── Entry point ─────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="JS recon: headless collection + filename brute"
    )
    parser.add_argument("-f", "--file", default=None, help="File with subdomains (one per line)")
    parser.add_argument("-u", "--url", default=None, help="Single subdomain/domain to scan")
    parser.add_argument("-w", "--wordlist", default=None, help="Custom JS wordlist (one name per line, no extension)")
    parser.add_argument("-t", "--timeout", type=int, default=20, help="Page load timeout in seconds (default: 20)")
    parser.add_argument("-c", "--concurrency", type=int, default=3, help="Max parallel subdomains (default: 3)")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: ./output)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every JS URL found")
    parser.add_argument("-d", "--download", action="store_true", help="Download all collected JS files")
    args = parser.parse_args()

    # Load target(s)
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

    sem = asyncio.Semaphore(args.concurrency)
    tasks = [
        process_subdomain(sub, output_dir, wordlist, args.timeout, sem, args.verbose, args.download)
        for sub in subdomains
    ]

    print(f"[*] Starting recon on {len(subdomains)} subdomain(s)\n")
    await asyncio.gather(*tasks)
    print("\n[✓] Done.")


if __name__ == "__main__":
    asyncio.run(main())