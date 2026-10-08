#!/usr/bin/env bash
# wcp-agent: cache-warmup
# wcp-agent-version: 1.0.0
# wcp-agent-description: Pre-warms the full-page cache for every site by crawling its sitemap.xml (falls back to the homepage)
#
# Run modes:
#   bash cache-warmup.sh                 - warm every site found under SITES_ROOT
#   bash cache-warmup.sh --domain <fqdn> - warm just one site (used after maintenance mode is disabled)

set -euo pipefail

WCP_DIR="${WCP_DIR:-/root/.wcp}"
SITES_ROOT="${SITES_ROOT:-/var/www}"
export WCP_DIR SITES_ROOT
trap 'ec=$?; mkdir -p "$WCP_DIR/agents"; echo "{\"ts\":$(date +%s),\"exit_code\":$ec}" > "$WCP_DIR/agents/cache-warmup.heartbeat"' EXIT

domain_arg=""
if [[ "${1:-}" == "--domain" ]]; then
  domain_arg="${2:-}"
fi
export DOMAIN_ARG="$domain_arg"

python3 - << 'PYEOF'
import glob, os, re, sys, time

WCP_DIR    = os.environ.get("WCP_DIR", "/root/.wcp")
SITES_ROOT = os.environ.get("SITES_ROOT", "/var/www")
DOMAIN_ARG = os.environ.get("DOMAIN_ARG", "")
LOG_FILE   = os.path.join(WCP_DIR, "logs", "cache-warmup.log")

MAX_URLS = 200
MAX_SUB_SITEMAPS = 20

sys.path.insert(0, os.path.join(WCP_DIR, "agents"))
from wcp_agent_lib import log_entry as _log_entry, run_argv

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def run_cmd(cmd, timeout=30):
    return run_argv(cmd, timeout=timeout)


def fetch(url):
    # Sitemap-derived URLs are untrusted (a compromised site's sitemap.xml
    # could contain a "-..." entry to smuggle curl flags); reject anything
    # that could be parsed as a flag and use "--" to end option parsing.
    if url.startswith("-"):
        return None
    r = run_cmd(["curl", "-s", "-m", "15", "--", url])
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return r.stdout


def warm(url):
    if url.startswith("-"):
        return False
    r = run_cmd(["curl", "-s", "-o", "/dev/null", "-m", "10", "-w", "%{http_code}", "--", url])
    try:
        return int(r.stdout.strip()) < 400
    except ValueError:
        return False


def log_entry(entry):
    _log_entry(LOG_FILE, entry)


def extract_locs(xml):
    return re.findall(r"<loc>(.*?)</loc>", xml)


def urls_for_domain(domain):
    """Returns (urls, source) where source is 'sitemap' or 'homepage'."""
    root_xml = fetch(f"https://{domain}/sitemap.xml")
    if not root_xml:
        return [f"https://{domain}/"], "homepage"

    locs = extract_locs(root_xml)
    if not locs:
        return [f"https://{domain}/"], "homepage"

    if "<sitemapindex" in root_xml:
        urls = []
        for sub_url in locs[:MAX_SUB_SITEMAPS]:
            sub_xml = fetch(sub_url)
            if sub_xml:
                urls.extend(extract_locs(sub_xml))
            if len(urls) >= MAX_URLS:
                break
        if not urls:
            return [f"https://{domain}/"], "homepage"
        return urls[:MAX_URLS], "sitemap"

    return locs[:MAX_URLS], "sitemap"


def warm_domain(domain):
    urls, source = urls_for_domain(domain)
    warmed = failed = 0
    for url in urls:
        if warm(url):
            warmed += 1
        else:
            failed += 1
    log_entry({
        "ts": int(time.time()),
        "domain": domain,
        "warmed": warmed,
        "failed": failed,
        "source": source,
    })


if DOMAIN_ARG:
    warm_domain(DOMAIN_ARG)
else:
    for public_dir in sorted(glob.glob(os.path.join(SITES_ROOT, "*", "public"))):
        domain = public_dir.split(os.sep)[-2]
        warm_domain(domain)
PYEOF
