<!--
©AngelaMos | 2026
00-OVERVIEW.md
-->

# Credential Rotation Enforcer - Overview

A Crystal daemon that **tracks** credentials, **enforces** rotation policies as code, and **executes** the four-step rotation contract against AWS Secrets Manager, HashiCorp Vault, GitHub fine-grained PATs, and local `.env` files. Single binary. Live TUI. Bidirectional Telegram bot. Tamper-evident audit log. Signed compliance evidence export.

## What This Project Demonstrates

| Concept | What you'll see in the code |
|---|---|
| Compile-time-checked policy DSL | `policies/*.cr` evaluated by the Crystal compiler; typo'd action symbols, missing fields, or bad credential property references all fail `crystal build` |
| Bus + plugin architecture | Typed events fan out across Crystal channels; subscribers (audit, TUI, Telegram, log) react independently; rotators register at compile time via `register_as :kind` macro |
| 4-step rotation contract | `generate -> apply -> verify -> commit`, dual-version safe (AWSCURRENT / AWSPENDING analog), with rollback on failure between apply and commit |
| Tamper-evident audit log | SHA-256 hash chain + ratcheting HMAC-SHA256 + Ed25519-signed Merkle batches (3 independent layers of integrity) |
| AEAD envelope encryption | AES-256-GCM with per-row DEKs wrapped by a KEK; AAD-bound to `tenant_id || credential_id || version_id`; reserved `algorithm_id` byte for crypto agility |
| Hand-rolled live TUI | ANSI escapes only (no `crysterm` dependency); event-driven repaints coalesced to a tick interval; works against any IO so it's testable |

## Prerequisites

- Crystal **1.20.0+** (see `https://crystal-lang.org/install/`)
- For Tier 1 demo: nothing else
- For Tier 2 demo: Docker + Docker Compose
- For Tier 3 (real cloud): AWS account, Vault server, GitHub Apps token

## Three-Tier Demo Path

Each tier teaches a different lesson. Run them in order to see the system evolve.

### Tier 1 - Zero Deps

```
$ git clone <repo> && cd credential-rotation-enforcer
$ shards install && shards build cre
$ ./bin/cre demo
```

What you'll see:
- A temp `.env` file with `API_KEY=oldvalue-aaa`
- A simulated 60-day-old credential triggering policy violation
- Live narration of all 4 rotation steps
- The same `.env` file with a fresh random `API_KEY=...` value
- Audit chain verification confirming integrity

Runtime: under 1 second.

### Tier 2 - Docker Compose

```
$ make demo-full
```

Brings up: PostgreSQL 16, LocalStack (AWS Secrets Manager), HashiCorp Vault dev mode, a fake-GitHub Flask service. CRE connects to all four and rotates one credential through each rotator. Demonstrates real network calls, real auth (SigV4 to LocalStack, token to Vault, bearer to fake-GitHub), real persistence to Postgres, real append-only audit triggers.

Setup time: ~2 minutes (mostly image pulls).

### Tier 3 - Real Cloud

Copy `config/demo-full.cr.example` and edit env vars to point at your real AWS account / Vault server / GitHub. Run `cre run` headless or `cre watch` for the live TUI.

## Subcommand Cheat Sheet

| Command | Purpose |
|---|---|
| `cre run` | Headless daemon (production / systemd) |
| `cre watch` | Engine + live TUI in one process |
| `cre check` | One-shot policy eval, exit code by violations (CI-friendly) |
| `cre rotate <id>` | Manual rotation of a single credential |
| `cre policy list` | List compiled-in policies |
| `cre policy show <name>` | Inspect one policy in detail |
| `cre export --framework=soc2` | Generate signed compliance evidence ZIP |
| `cre audit verify` | Verify hash chain + HMAC + Merkle batch signatures |
| `cre demo` | Tier 1 zero-deps demo |
| `cre version` | Print version |

## Where to Read Next

- **Architecture** -> `02-ARCHITECTURE.md` (event bus, persistence, crypto layers)
- **Concepts** -> `01-CONCEPTS.md` (rotation theory, NIST/SOC2 framework controls, real breaches)
- **Code walkthrough** -> `03-IMPLEMENTATION.md` (key functions, where to make changes)
- **Extension ideas** -> `04-CHALLENGES.md` (add a 5th rotator, ML-KEM hybrid wrap, web UI)
