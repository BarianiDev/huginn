# Huginn

Huginn is a passive OSINT / reconnaissance CLI tool for gathering publicly available information about a target domain — subdomains, DNS records, WHOIS data, exposed email addresses, detected technologies, and historical URLs from the Wayback Machine.

Named after Huginn, one of Odin's two ravens ("thought"), who flies across the world and returns with information.

## Why "passive"

Every collector in Huginn queries public third-party data sources (Certificate Transparency logs, DNS resolvers, WHOIS registries, archive.org) or fetches a single page the same way a browser would. Huginn never scans, brute-forces, or otherwise interacts intrusively with the target's own infrastructure — that's a deliberate design boundary, not a limitation. See [Legal & ethical use](#legal--ethical-use).

## Architecture

Huginn follows a Collector pattern:

- `Collector` (abstract base class) defines a single contract: `collect(target) -> list[Finding]`.
- Every data source (crt.sh, DNS, WHOIS, ...) is its own `Collector` subclass, fully isolated from the others.
- Every collector emits the same generic `Finding` model (`kind`, `value`, `source`, `metadata`), so the CLI — or any future consumer, like a web API or a storage layer — can treat every collector interchangeably.
- Dependencies point inward: `core/` (the `Collector` and `Finding` contracts) never imports from `collectors/`, `output/`, or the CLI. Collectors depend on `core/`, never the other way around.

This is what let the project grow from 1 collector to 6 without ever having to touch `core/`.

## Collectors

| Command | Source | What it finds |
|---|---|---|
| `subdomains` | crt.sh (Certificate Transparency) | Subdomains with issued TLS certificates |
| `dns` | Public DNS resolvers | A / AAAA / MX / NS / TXT records |
| `whois` | WHOIS registries | Registrar, registration/expiration dates, name servers, status |
| `emails` | Target's own homepage | Email addresses on the target's domain |
| `tech` | Target's own homepage (headers + HTML) | Detected technologies (WordPress, Cloudflare, Nginx, ...) |
| `wayback` | archive.org (Wayback Machine CDX API) | Historical URLs ever archived for the domain |
| `scan` | all of the above | Runs every collector in parallel and merges the results |

## Installation

```bash
git clone https://github.com/BarianiDev/huginn.git
cd huginn
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
pip install -e .
```

## Usage

```bash
huginn subdomains example.com
huginn dns example.com
huginn whois example.com
huginn emails example.com
huginn tech example.com
huginn wayback example.com

huginn scan example.com
huginn scan example.com --output results.json
```

## Testing

```bash
pytest
```

Every collector's parsing logic (`_parse`) is tested without hitting the network. Network calls (`_fetch`) are deliberately kept in a separate method so parsing can be verified offline, deterministically, and fast.

## Known limitations

- The Wayback Machine's public CDX API is known to be slow or unreliable at times. The `wayback` collector retries with backoff before giving up, but a persistent failure there is usually the API itself, not Huginn.
- WHOIS data is frequently redacted by registrars for privacy (GDPR and similar regulations), so contact fields are often empty — this is expected, not a bug.

## Legal & ethical use

Huginn only performs passive reconnaissance: it queries public third-party sources and the target's own public-facing homepage, the same way any browser or search engine crawler would. It does not port-scan, brute-force, or otherwise probe the target's infrastructure directly.

Even so, only use this tool against domains you own or are explicitly authorized to test.

## Roadmap

- ASN / IP block ownership lookup (RDAP)
- Persistent storage (SQLite) to track what changed between scans over time
- FastAPI + React interface reusing the same core

---

Part of a two-project security portfolio: Huginn (offensive/recon) pairs with [NeonGrid](https://github.com/BarianiDev/Neongrid) (defensive SIEM) to form a purple-team narrative — recon builds the picture of what's exposed, detection watches for what happens next.
