# jsdrift

**Watch a target's JavaScript over time and get alerted when new attack surface appears:
new endpoints, hidden parameters, leaked keys, exposed sourcemaps, new cloud hosts.**

Most JS recon tools are one-shot scanners: you run them, get 4,000 lines, and half are noise.
jsdrift is built around two ideas instead:

1. **Drift, not snapshots.** It remembers what every scan saw and reports only what *changed*.
   A new endpoint shipped on Tuesday is a lead while nobody else has noticed it.
2. **False positives are the enemy.** Every candidate goes through validators, filters and a
   0-99 confidence score that can explain itself, and you can teach it what to ignore.

Pure Python 3.11+, **zero dependencies**, one SQLite file, a CLI and a local web dashboard.

> **Only use this on assets you are authorised to test** (a bug bounty program's scope or written
> permission). jsdrift enforces a scope guard, but you are responsible for what you point it at.

## Try it in 30 seconds (no internet, no target needed)

```bash
python -m jsdrift demo            # fake app on 127.0.0.1: scan v1, "deploy" v2, show the drift
python -m jsdrift demo --serve    # ...then open the dashboard on the demo data
```

The demo app is stuffed with false-positive bait (placeholders, doc-example keys, UI labels, MIME
types, a header-only PEM constant) and then ships a "release" with a hidden admin endpoint, new
parameters, an AWS key pair, a GitHub token, a Supabase `service_role` JWT, an exposed sourcemap and
a lazy-loaded admin chunk. Every file name hash changes between the two versions. jsdrift reports
the real drift and nothing else.

## Install and run

```bash
pip install .                     # or just run `python -m jsdrift` from this folder
jsdrift init                      # writes jsdrift.toml
$EDITOR jsdrift.toml              # seeds + scope (required)
jsdrift scan                      # first run = baseline (nothing is "new")
jsdrift scan                      # later runs report drift
jsdrift serve --open              # dashboard
```

Quick ad-hoc scan without a config (scope defaults to the seed host *only*):

```bash
jsdrift scan --url https://app.example.com/ --scope app.example.com --scope '*.api.example.com' \
             --header 'X-Bug-Bounty: yourhandle' --proxy http://127.0.0.1:8080
```

Run it on a schedule: `jsdrift watch --interval 3600`, or cron with `--exit-code`
(exit 2 = new alertable findings) and a webhook (`[notify]` in the config, or the
`JSDRIFT_DISCORD_WEBHOOK` / `JSDRIFT_SLACK_WEBHOOK` / `JSDRIFT_WEBHOOK` env vars).

## What it finds

| kind | examples |
|---|---|
| `endpoint` | `/api/v2/admin/users/{param}/impersonate`, absolute API URLs, WebSocket URLs, with method when visible |
| `param` | query-string params, `URLSearchParams`, request-body keys, tagged: open-redirect, SSRF, LFI, IDOR, privilege, debug/feature-flag, injection |
| `secret` | 34 provider formats (AWS, GitHub, GitLab, Slack, Stripe, Google, SendGrid, npm, OpenAI/Anthropic, private keys, DB URLs, JWTs...) plus key-name-driven generic credentials |
| `host` | new hostnames in JS, with a hint for S3/GCS/Azure/Firebase hosts (takeover / public-access leads) |
| `graphql` | operation names (`mutation PurgeAccount`) |
| `sourcemap` / `sourcefile` | exposed `.map` files; **original sources are downloaded and analysed too**, and the file paths themselves are tracked (a new `src/admin/...` module means a new feature shipped) |
| `route` | client-side routes |

Beyond `<script src>`: inline scripts and JSON blobs, `modulepreload`, import maps, webpack runtime
chunk maps, `import("...")` lazy chunks, and `SourceMap` headers.

## How false positives are kept down

Every finding carries a confidence score (0-99) and a list of *reasons* (`-v` shows them).
Alerts only include findings at or above `min_alert_confidence` (default 60) and
`min_alert_severity`; everything is still stored and visible in the dashboard.

| technique | what it removes |
|---|---|
| Provider-specific formats + **structural validators** | AWS IDs must base32-decode to a real account id; GitHub tokens are CRC32-checked; JWTs must parse (header + payload JSON); PEM headers need actual key material after them (crypto libraries ship the bare header as a constant) |
| Context-aware severity | expired JWTs are demoted; Supabase `role: anon` is `info`, `service_role` is `critical`; Stripe publishable / Sentry DSN / Mapbox `pk.` / Google OAuth client ids are marked public-by-design |
| Placeholder / doc-example filter | `YOUR_API_KEY`, `changeme`, `xxxx`, `<secret>`, `${...}`, `AKIAIOSFODNN7EXAMPLE`, the jwt.io sample token, repeated or sequential characters |
| Generic-secret rules | key *name* must imply a credential, label/UI names (`passwordLabel`, `forgot_password`) are skipped, CSRF/nonce/site-key names are skipped, values that look like identifiers / i18n keys / dotted paths / URLs / plain words are skipped, entropy and length gates |
| Real JS lexing | strings come from a lexer that understands comments, regex literals, template literals and concatenation (`"/api/u/"+id+"/edit"` becomes one endpoint) instead of regex-matching minified text |
| Endpoint noise filters | static assets, MIME types, date formats, `node_modules`, W3C/CDN/doc hosts, regex-looking strings, SPA-fallback HTML served as a "script" |
| Vendor-file down-weighting | findings inside `vendor.js`, jQuery, polyfills... are scored lower, not dropped |
| Stable file identity | `main.5f3e2a1b.js` -> `main.9c8d7e6f.js` is one file with a new version, so a redeploy does not look like "everything is new" |
| **You** | `jsdrift triage <target> <fingerprint> false_positive`, the dashboard button, or `[targets.x.ignore]` (hosts, path regexes, values, params, whole rules) |

See *why* something was rejected: `jsdrift analyze suspicious.js --explain`.

## Drift semantics (why alerts are trustworthy)

A finding's identity is a content fingerprint, independent of which file carried it. After each scan:

* **new**: fingerprint never seen for this target
* **removed**: active finding that no file contains any more
* **reappeared**: was removed earlier, present again
* **unchanged files are not re-analysed** (content hash match), and their findings are carried forward
* **a failed or partial scan never invents removals.** If a download fails, that file keeps its previous findings and the run is marked `partial`
* the first scan is a **baseline**: it is stored and summarised, never alerted
* `jsdrift diff-file <target> main` shows a line diff between stored versions of a bundle (a small beautifier makes minified diffs readable)

## Scope guard

Required, not optional. A target without `in_scope` will not run.

* every request **and every redirect hop** is checked before it is sent; `out_of_scope` always wins
* wildcard patterns need at least two fixed labels (`*.com` is rejected)
* plain `http`, credentials in URLs, private/loopback/link-local addresses and cloud metadata
  addresses (`169.254.169.254`...) are blocked by default; metadata is blocked even with `allow_private_ips`
* third-party script URLs (analytics, CDNs) are listed as skipped and **never requested**
* `jsdrift scope-check <target> <url>...` dry-runs URLs against your rules
* politeness: global rate limit with jitter, bounded retries, backs off and aborts if the server keeps answering 429/503,
  response size cap applied after decompression, optional `X-Bug-Bounty`-style identification header

jsdrift **never uses a credential it finds** (no "is this key live?" checks). Verifying a key against a
third-party service is usually out of scope and sometimes illegal; some findings carry a note on how to
triage them manually and within the program's rules.

## Dashboard

`jsdrift serve` starts a local-only UI: Changes (per-run drift), Findings (filter by kind / severity /
confidence / text), Files (stored versions + line diff between any two), Runs. One click to mark
Confirmed / Reported / False positive; secrets are masked until you press Reveal.

Because the database holds attacker-controlled strings and real secrets, the server is hardened:
loopback-only bind, random per-launch token (in the URL fragment, never logged), `Host` validation against DNS rebinding,
same-origin checks, strict CSP, and a frontend that never parses markup from strings.

## Configuration reference

```toml
db = "jsdrift.db"
[defaults]            # any per-target key can be set here
delay = 0.5           # seconds between requests
threads = 4
max_depth = 3         # reference-following depth (page -> script -> chunk -> chunk)
max_files = 300
max_file_mb = 8
sourcemaps = true     # fetch exposed .map files and analyse the original sources
min_alert_confidence = 60
min_alert_severity = "low"
reveal_secrets = false          # alerts mask secrets unless true
headers = { "X-Bug-Bounty" = "handle" }   # also use for Cookie/Authorization when testing logged-in areas
[targets.acme]
seeds = ["https://app.acme.com/"]
extra_js = ["https://app.acme.com/static/js/legacy-admin.js"]
[targets.acme.scope]
in_scope = ["app.acme.com", "*.api.acme.com"]
out_of_scope = ["blog.acme.com"]
[targets.acme.ignore]
hosts = ["cdn.analytics-vendor.com"]
paths = ["^/cdn-cgi/"]
values = []
params = ["utm_source"]
rules = []            # e.g. ["generic_assignment"] to switch a rule off for this target
```

## Commands

`init` `scan` `watch` `analyze` `findings` `report` `triage` `runs` `diff-file` `scope-check` `serve` `demo`
(`jsdrift <command> -h` for options). Reports render as text, Markdown (`--format md`, paste into a bug report)
or JSON (`--format json`, pipe into other tooling).

## Known limitations (be aware)

* Static analysis only. Endpoints assembled at runtime from data, or JS served only after login/interaction,
  are not found. Use `headers` for authenticated sessions and add more `seeds` / `extra_js` for other apps on the domain.
* Webpack chunk-map resolution covers the common `__webpack_require__.u` shapes; unusual loaders may be missed.
* Providers rotate formats. The GitHub CRC32 check is best-effort: a mismatch lowers confidence (-30), it never hides a token.
* Scope checks resolve DNS before connecting; a hostile DNS server could in theory answer differently on the second lookup.
  Hosts must already be in your scope for this to matter.
* The database and the diff view contain **raw secret values** (the file is created `0600`). Treat it as sensitive and don't share it.
* Single process, SQLite: one scheduler per database.

## Development

```bash
python -m unittest discover -s tests -t .     # 40+ tests: detection corpora, scope/redirect safety, drift semantics, dashboard security
```

Layout: `tokenizer` (JS lexer) -> `extract`/`secrets` (detection + scoring) -> `crawler` (discovery) -> `engine`
(scan + drift reconcile) -> `store` (SQLite) -> `report`/`notify`/`web`/`cli`. Add a provider rule in
`secrets.RULES` (pattern, severity, confidence, optional validator) and bump `ANALYZER_VERSION` so unchanged files get re-analysed.
