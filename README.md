# Shield Check

Compare how well filtering DNS services block fresh phishing and malware domains, including CIRA Canadian Shield. Published at **https://coolcode.ca/shieldcheck/**.

Every six hours a GitHub Actions job takes the newest domains from two public threat feeds and resolves each one through every filtering service and through the same operator's unfiltered service. A domain counts as **blocked** when the filtered service refuses it (NXDOMAIN, an empty answer, or an Extended DNS Error such as "Blocked" or "Filtered") or answers with a block page or null address while the unfiltered service resolves it normally.

| Operator | Unfiltered (baseline) | Filtered |
|---|---|---|
| CIRA Canadian Shield | Private | Protected (malware and phishing), Family |
| Cloudflare | 1.1.1.1 | 1.1.1.2 Malware, 1.1.1.3 Family |
| Quad9 | 9.9.9.10 | 9.9.9.9 Threat blocking |

Threat feeds: [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch, online malware URLs) and the [OpenPhish](https://openphish.com/) community feed. A control list of well-known legitimate sites catches false positives.

## Reading the results

<!-- coolcode:guide -->
The scoreboard's block rate counts only domains that still resolved on the operator's unfiltered service, so dead domains don't count against anyone. "Unique" means no other security filter blocked that domain in the same capture. A control-list block is a false positive worth reporting to the provider. "How quickly" tracks domains that first appear in a feed after tracking began and shows how many hours passed before each filter blocked them. Use "Check your own list" to test a suspicious link before you share it. That check runs from your browser, and services that don't accept browser requests show "!".
<!-- /coolcode:guide -->

- **Sinkholes:** CIRA answers blocked HTTP names with the address of its block page instead of refusing them. Any address that a filtered service returns instead of the baseline answer for several different domains in one capture (`sinkhole_min_domains`, default 3) is treated as a block page. `0.0.0.0`, `::` and private addresses always count as blocks.
- **Shared platforms** such as Google Docs, GitHub Pages or Cloudflare Pages are skipped, because no DNS filter can block one user's page without blocking everyone's (`skip_suffixes`).
- Each capture is one DNS lookup per domain per service, made from GitHub's servers. It's a snapshot rather than a benchmark. Providers may answer differently in other regions or as their lists change.
- Feed domains are shown as plain text, never as links.

## Expand or customize

Everything is in **`web/config.json`**:

| Key | Meaning |
|---|---|
| `resolvers` | Each DNS-over-HTTPS service: `id`, `name`, `short` (column label), `operator`, `url`, and either `"role": "baseline"` or `"baseline": "<id of its unfiltered sibling>"` with `"level": "security"` or `"family"`. |
| `feeds` | Threat feeds: `id`, `name`, `url` (one URL or host per line), `kind`, `max_domains` per capture. |
| `controls` | Legitimate domains that should never be blocked. |
| `skip_suffixes` | Shared platforms to leave out. |
| `sinkhole_min_domains`, `concurrency`, `timeout_ms` | Detection threshold and query limits. |
| `keep_captures` (default 120 = 30 days), `history_days` | Retention. |
| `min_live_domains` | A capture with fewer live feed domains than this is rejected and not published. |
| `live_max_domains` | Cap on the in-browser check. |

To add a service, append it to `resolvers` and point `baseline` at an unfiltered sibling (add one if needed). For example:

```json
{ "id": "adguard", "name": "AdGuard DNS · Default", "short": "AdGuard", "operator": "AdGuard",
  "url": "https://dns.adguard-dns.com/dns-query", "baseline": "adguard-unfiltered", "level": "security" }
```

No code changes are needed (`tests/model.test.mjs` covers an extra resolver). Configuration changes apply from the next capture. Earlier captures keep the services and feeds they were taken with.

**Refresh and publish:** a push to `main` runs the tests, takes a capture and deploys. Scheduled runs repeat every six hours. To capture without pushing, use **Actions → Browser tool · Check and publish → Run workflow**. If no feed domains resolve, or every unfiltered service fails, the run stops and the last good deployment stays live. Captures and the block-time history persist in the Actions cache.

## Develop and test

```sh
node --test tests/*.test.mjs
python3 -m unittest discover -s tests -v
node scripts/capture.mjs --fixtures tests/fixtures/sim --now 2026-11-23T18:00:00Z   # offline capture
python3 scripts/build.py
python3 -m http.server 8000 --directory dist
```

`tests/fixtures/sim/` holds feed text and simulated resolver answers for each service's blocking style. `tests/browser_smoke.py` serves the build at `/shieldcheck/` and simulates the DNS services, including CIRA refusing browser requests.

## Publish

Settings → Pages → Source → **GitHub Actions**. GitHub pauses schedules in public repositories after 60 days without activity; run the workflow by hand to resume.
