<!--
©AngelaMos | 2026
README.md
-->

# Credential Rotation Enforcer (`cre`)

> A Crystal daemon that tracks credentials, enforces rotation policies as code, and executes the four-step rotation contract against AWS Secrets Manager, HashiCorp Vault, GitHub fine-grained PATs, and local `.env` files. Single binary. Live TUI. Tamper-evident audit log. Bidirectional Telegram bot. Signed compliance evidence export.

[![Crystal](https://img.shields.io/badge/crystal-1.20+-black?logo=crystal)](https://crystal-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-200+-brightgreen)](spec/)

---

## What this is

A senior+ portfolio implementation of an enterprise credential rotation enforcer, built end-to-end in Crystal. The code is the lesson - every architectural choice (event bus, plugin macros, AEAD envelope, hash-chained audit log, three demo tiers) is intentional and explained in `learn/`.

This is **not** a wrapper around HashiCorp Vault or AWS Secrets Manager. It is its own coherent enforcer that talks *to* those systems via their HTTP APIs (real SigV4, real bearer auth, real lease tokens).

## What it does

1. **Tracks** credentials in an inventory (PostgreSQL or SQLite).
2. **Evaluates** Crystal-DSL policies that compile-time-check for typos, missing fields, and bad enum values.
3. **Rotates** credentials using AWS Secrets Manager's four-step contract (`generate -> apply -> verify -> commit`) with dual-version safety so concurrent consumers never crash mid-rotation.
4. **Records** every event in a tamper-evident audit log: SHA-256 hash chain + ratcheting HMAC-SHA256 + Ed25519-signed Merkle batches.
5. **Encrypts** stored credentials at rest with AES-256-GCM AEAD, per-row DEKs wrapped by a KEK, AAD-bound to credential identity.
6. **Notifies** via structured logs and a bidirectional Telegram bot supporting `/status`, `/rotate <id>`, `/snooze`, `/history`, `/queue`.
7. **Exports** signed compliance evidence bundles mapping audit events to SOC 2 / PCI-DSS / ISO 27001 / HIPAA controls.
8. **Renders** a hand-rolled live TUI (no `crysterm` dependency) showing active rotations, recent events, and KEK version, repainted at most every 200ms.

## Quick start

### Tier 1 - Zero-deps demo (under 30 seconds)

```bash
git clone <repo> && cd PROJECTS/intermediate/credential-rotation-enforcer
shards install && shards build cre
./bin/cre demo
```

You'll see live narration of an in-memory SQLite + tempfile rotation, with audit-chain verification at the end.

### Tier 2 - Full mocked stack (under 2 minutes)

```bash
make demo-full
```

Brings up Docker Compose with PostgreSQL 16, LocalStack (AWS Secrets Manager), HashiCorp Vault dev mode, and a fake-GitHub Flask service. CRE talks to all four with real network calls.

### Tier 3 - Real cloud

Edit `config/demo-full.cr.example` and set env vars to point at your real AWS account / Vault server / GitHub Apps token. Then `cre run --db=postgres://...`.

## Subcommands

| Command | Purpose |
|---|---|
| `cre run` | Headless daemon (production / systemd) |
| `cre watch` | Engine + live TUI in same process |
| `cre check` | One-shot policy evaluation; exit code reflects violations |
| `cre rotate <id>` | Manually rotate a single credential |
| `cre policy list / show <name>` | Inspect compiled-in policies |
| `cre export --framework=soc2` | Generate signed compliance evidence ZIP |
| `cre audit verify` | Verify hash chain + HMAC ratchet + Merkle batch signatures |
| `cre demo` | Tier 1 zero-deps demo |
| `cre version` | Print version |

## The flagship rotators

| Rotator | What it talks to | Auth |
|---|---|---|
| AWS Secrets Manager | `secretsmanager.us-east-1.amazonaws.com` | SigV4 (rolled from scratch in `src/cre/aws/signer.cr`) |
| HashiCorp Vault | `vault read database/creds/<role>` + lease revoke | `X-Vault-Token` |
| GitHub fine-grained PATs | `POST/DELETE /user/personal-access-tokens` | `Bearer ghp_...` |
| Local `.env` file | atomic temp+rename | n/a |

Adding a fifth rotator means dropping a single file in `src/cre/rotators/`. The `register_as :kind` macro hooks it into the registry at compile time.

## Architecture at a glance

```
                       ┌──────────────────────────────────────┐
                       │       cre  (single Crystal binary)   │
                       │                                      │
   ┌────────────┐      │  ┌──────────────────────────────┐    │
   │ Scheduler  │─────►│  │       Typed Event Bus        │    │
   │ (fiber)    │      │  └──┬─────┬─────┬─────┬─────┬───┘    │
   └────────────┘      │     │     │     │     │     │        │
                       │  ┌──▼──┐ ┌▼────┐ ┌▼──┐ ┌▼──┐ ┌▼───┐  │
                       │  │Rot. │ │Audit│ │TUI│ │Tg │ │Pol.│  │
                       │  │Reg. │ │Log  │ │   │ │Bot│ │Eval│  │
                       │  └──┬──┘ └──┬──┘ └───┘ └───┘ └────┘  │
                       │     └──────┴──────────────┐          │
                       │                           │          │
                       │              ┌────────────▼────────┐ │
                       │              │  Persistence        │ │
                       │              │  (PG / SQLite)      │ │
                       │              └─────────────────────┘ │
                       └──────────────────────────────────────┘
```

All components are fibers in one OS process. The bus is in-process - Crystal channels are nanosecond-scale.

## Project layout

```
credential-rotation-enforcer/
├── shard.yml          Crystal manifest (1.20+)
├── Makefile           build / test / demo / lint targets
├── policies/          USER policy files (compiled in)
├── src/cre/
│   ├── cli/           subcommand dispatch + 9 commands
│   ├── tui/           ANSI primitives + 4-panel live monitor
│   ├── engine/        scheduler, event bus, lifecycle, orchestrator
│   ├── events/        typed event hierarchy
│   ├── rotators/      registry + 4 flagship rotators
│   ├── policy/        macro DSL + evaluation engine
│   ├── audit/         hash chain + HMAC ratchet + Merkle + Ed25519
│   ├── crypto/        AES-256-GCM envelope, KEK/DEK
│   ├── persistence/   PG + SQLite adapters (same interface)
│   ├── notifiers/     structured log + Telegram bidirectional bot
│   ├── compliance/    SOC2/PCI/ISO/HIPAA control mapping + bundle export
│   ├── aws/           SigV4 signer + Secrets Manager client
│   ├── vault/         dynamic-secrets HTTP client
│   ├── github/        fine-grained PAT API client
│   └── demo/          Tier 1 demo
├── docker/            Tier 2 docker-compose stack (PG + LocalStack + Vault + fake-GH)
├── spec/              200+ unit + integration tests
└── learn/             walkthrough docs (this is the teaching folder)
```

## Read the walkthrough

- [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) - quick start, prerequisites, three-tier demo path
- [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) - rotation theory, real breaches that motivated the design, framework controls
- [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) - bus + plugin design, persistence layers, crypto stack
- [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) - code-level walkthrough; where to look in the source for each concept
- [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) - 10 extension challenges (beginner -> advanced)

## Running the test suite

```bash
crystal spec                     # all 200+ tests
crystal spec spec/unit            # unit only (no DB required)
DATABASE_URL=postgres://cre_test:cre_test@localhost:5432/cre_test \
  crystal spec spec/integration   # integration with real PG
make check                        # format + lint + unit
```

## License

MIT - see [LICENSE](LICENSE).

## Credits

Built as part of the [Cybersecurity Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects) portfolio - 60+ enterprise-grade cybersecurity projects designed as senior-level learning resources.
