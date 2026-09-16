<div align="center">

```
 ____________ _____   ____  _    _          _____ _  __
|___  /  ____|  __ \ / __ \| |  | |   /\   / ____| |/ /
   / /| |__  | |__) | |  | | |__| |  /  \ | |    | ' / 
  / / |  __| |  _  /| |  | |  __  | / /\ \| |    |  <  
 / /__| |____| | \ \| |__| | |  | |/ ____ \ |____| . \ 
/_____|______|_|  \_\____/|_|  |_/_/    \_\_____|_|\_\

              Fortifying the Digital Frontier
```

# @zerohack/log-analyzer · `zh-log`

**Streaming parser + statistics for nginx/apache/syslog logs with attack heuristics**

[![License](https://img.shields.io/badge/license-Apache--2.0-00B0BD?style=for-the-badge)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6?style=for-the-badge&logo=typescript&logoColor=white)](tsconfig.json)
[![Zero Budget](https://img.shields.io/badge/cost-%240-00b894?style=for-the-badge)](https://zerohack.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-00B0BD?style=for-the-badge)](CONTRIBUTING.md)

**Part of the [ZeroHack](https://zerohack.org) Geek Tools ecosystem**
Category: `forensics` · `logs` · `analytics` · `siem`

</div>

---

> **⚡ Zero Budget. Zero Cloud Dependencies. Pure Local Power.**

---

## What It Does

In-memory parser + statistics for nginx/apache (combined log format),
JSONL, BSD/ISO syslog, and firewall `BLOCK`/`DROP` lines. Returns traffic
stats and heuristic attack flags over a file or stdin.

---

## Quick Start

### Standalone

```bash
git clone https://github.com/ZeroHackOrg/zerohack-log-analyzer.git
cd zerohack-log-analyzer && npm install
cat access.log | npx tsx src/bin.ts analyze - --json
```

### Standalone Resolution

```bash
git clone https://github.com/ZeroHackOrg/zerohack-shared.git
cd zerohack-shared && npm install && npm link
cd ../zerohack-log-analyzer && npm link @zerohack/shared
```

---

## Commands

| command | description |
| --- | --- |
| `analyze <file\|-> [--json] [--top N]` | totals, unique IPs, top IPs, status histogram, user-agents, methods, slowest (by `ms`) |
| `detect <file\|-> [--json]` | heuristic flags: `sqli`, `auth-failure`, `sensitive-path`, `admin-scan` |

`-` reads stdin. Every tabular command accepts `-j, --json`.

---

## Library API

```ts
import { parseLine, analyze, detect } from "@zerohack/log-analyzer";

const p = parseLine('10.0.0.1 - - [01/Jan/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 42 "-" "curl/8.0"');
// { kind: "clf", src: "10.0.0.1", method: "GET", path: "/", status: 200, size: 42, ... }

const stats = analyze(lines); // total, uniqIps, topIps, topUas, statusHist, slowest, methods, kinds
const flags = detect(lines);  // { flags: [{ kind, count, sample[] }] }
```

Line kinds: `clf` | `json` | `syslog` | `drop` (blank + firewall) | `unknown`.

`slowest` is ranked by the `ms` field found in JSON lines
(`ms` / `duration_ms` / `response_ms`).

---

## Env

None — all tools are zero-dependency, zero-config, and run offline.

---

## Tests

```bash
npm run typecheck --workspace @zerohack/log-analyzer
npm run test    --workspace @zerohack/log-analyzer
```

Pure functions: `parseLine`, `analyze`, `detect` take strings/iterables;
file + stdin handling lives only in `bin.ts`. Deterministic ordering
(count desc, then lexicographic / input order).

---

## Architecture

```
zerohack-log-analyzer/
├── src/
│   ├── bin.ts          # CLI entrypoint (commander)
│   ├── index.ts        # Re-exports
│   ├── types.ts        # LogLine, Stats, Flag types
│   ├── parsers.ts      # CLF / JSONL / syslog / drop parsers
│   ├── analyze.ts      # Aggregate statistics
│   └── detect.ts       # Heuristic attack flags
├── test/
│   ├── analyze.test.ts
│   ├── detect.test.ts
│   └── parsers.test.ts
├── package.json
├── tsconfig.json
├── README.md
├── LICENSE             # Apache-2.0
├── SECURITY.md
├── CONTRIBUTING.md
└── CODE_OF_CONDUCT.md
```

**Design principles:**
- Pure functions, no I/O in the core.
- Deterministic ordering everywhere.
- Frameworks used from `@zerohack/shared`: `table` + `truncate`.

---

## Security

Read-only analysis of log files you provide. Does not send logs anywhere.
Flags are heuristic — always review flagged samples before acting.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

---

## Related Packages

| Package | Binary | What It Does |
|---|---|---|
| [@zerohack/shared](https://github.com/ZeroHackOrg/zerohack-shared) | — | Types, schemas, catalog |
| [@zerohack/cli](https://github.com/ZeroHackOrg/zerohack-cli) | `zh` | Unified CLI |
| [@zerohack/supalite-api](https://github.com/ZeroHackOrg/zerohack-supalite-api) | `zh-api` | PostgREST API |
| [@zerohack/pal](https://github.com/ZeroHackOrg/zerohack-pal) | `zh-pal` | Local AI assistant |
| [@zerohack/honeypot](https://github.com/ZeroHackOrg/zerohack-honeypot) | `zh-honeypot` | Honeypot |
| [@zerohack/osint-cli](https://github.com/ZeroHackOrg/zerohack-osint-cli) | `zh-osint` | OSINT tools |
| [@zerohack/ssh-hardener](https://github.com/ZeroHackOrg/zerohack-ssh-hardener) | `zh-ssh` | SSH auditor |
| [@zerohack/secret-scanner](https://github.com/ZeroHackOrg/zerohack-secret-scanner) | `zh-secret` | Secret scanner |
| [@zerohack/recon-bot](https://github.com/ZeroHackOrg/zerohack-recon-bot) | `zh-recon` | Recon automation |
| [@zerohack/ctf-lab](https://github.com/ZeroHackOrg/zerohack-ctf-lab) | `zh-lab` | CTF lab runner |
| [@zerohack/ctf-automation](https://github.com/ZeroHackOrg/zerohack-ctf-automation) | `zh-ctf` | CTF solver |
---

## Community

- **Issues:** [GitHub Issues](https://github.com/ZeroHackOrg/zerohack-log-analyzer/issues)
- **PRs:** [Pull Requests](https://github.com/ZeroHackOrg/zerohack-log-analyzer/pulls)
- **Security:** [SECURITY.md](SECURITY.md)
- **Platform:** [zerohack.org](https://zerohack.org)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Read our [Code of Conduct](CODE_OF_CONDUCT.md) first.

## License

[Apache-2.0](LICENSE) — Copyright 2026 ZeroHack Security