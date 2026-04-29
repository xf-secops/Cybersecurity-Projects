<!--
©AngelaMos | 2026
02-ARCHITECTURE.md
-->

# Architecture

## System overview

```
┌─────────────────────────────────────────────────────────────┐
│                       cre  (single Crystal binary)          │
│                                                             │
│   ┌──────────────────────────────────────────────────────┐  │
│   │                   Event Bus                          │  │
│   │             (typed Crystal channels)                 │  │
│   └────┬─────┬─────┬─────┬─────┬─────┬─────┬────────────┘  │
│        │     │     │     │     │     │     │               │
│   ┌────▼─┐ ┌─▼──┐ ┌▼───┐ ┌▼──┐ ┌▼────┐ ┌──▼──┐ ┌──────┐    │
│   │Sched │ │Rot.│ │Pol.│ │TUI│ │Tele.│ │Audit│ │Notify│    │
│   │ulers │ │Reg │ │Eval│ │   │ │Bot  │ │Log  │ │      │    │
│   └──┬───┘ └─┬──┘ └─┬──┘ └───┘ └─────┘ └──┬──┘ └──────┘    │
│      │       │      │                     │                 │
│      └───────┴──────┴─────────────────────┘                 │
│                       │                                     │
│              ┌────────▼─────────┐                           │
│              │  Persistence     │ ◄── SQLite (Tier 1)       │
│              │  (PG / SQLite)   │ ◄── PostgreSQL (T2/T3)    │
│              └──────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

All long-lived components are **fibers in one OS process**. The bus is in-process - Crystal channels are nanosecond-scale, so the architectural overhead is essentially free.

## Components

### Event Bus (`src/cre/engine/event_bus.cr`)

Fanout dispatch via Crystal channels. Each subscriber gets its own bounded channel and chooses an overflow policy:

| Subscriber | Overflow | Reason |
|---|---|---|
| `AuditSubscriber` | `Block` | Never drop audit events; compliance requirement |
| `TuiSubscriber` | `Drop` | Stale UI is fine; can't block engine |
| `MetricsSubscriber` | `Drop` | Best-effort metrics |
| `TelegramSubscriber` | `Drop` (large buffer) | Network-flaky anyway |
| `RotationOrchestrator` | `Block` | Must process scheduled rotations |

The dispatcher is a single fiber reading from the inbox channel and writing to all subscriber channels in order. A slow subscriber configured `Block` causes the dispatcher to block on that subscriber's `send` - which is exactly what you want for audit (better to backpressure than to lose).

### Rotators (`src/cre/rotators/`)

The abstract `Rotator` class exposes the four lifecycle methods plus `rollback_apply`. Concrete rotators self-register at compile time:

```crystal
class AwsSecretsRotator < Rotator
  register_as :aws_secretsmgr
  ...
end
```

Adding a fifth rotator means dropping a single file in `src/cre/rotators/`. The macro hooks it into the registry at compile time. No central wiring to update.

Rotators receive their cloud client through their constructor (DI). The CLI `run` command wires the right client based on env vars / config.

### Persistence (`src/cre/persistence/`)

Two adapters behind one interface:
- `Sqlite::SqlitePersistence` - WAL mode, single connection (avoids `:memory:` per-connection split), application-level mutex for advisory lock simulation. Used for Tier 1 demo.
- `Postgres::PostgresPersistence` - JSONB tags, BIGSERIAL audit, append-only triggers refusing UPDATE/DELETE/TRUNCATE on `audit_events`, `pg_advisory_xact_lock` for cross-process row locking. Used for Tier 2/3.

Same repo contracts (`CredentialsRepo`, `VersionsRepo`, `RotationsRepo`, `AuditRepo`) for both. The `Persistence` superclass exposes `transaction(&)` and `with_advisory_lock(key, &)` so the rest of the system is backend-agnostic.

### Crypto layers (`src/cre/crypto/`, `src/cre/audit/`)

```
+--------------------+
|   Plaintext        |
+--------------------+
          |
          | AES-256-GCM(plain, DEK, AAD = tenant||cred||version, nonce 96b)
          v
+--------------------+
|  ciphertext + tag  | -> credential_versions.ciphertext
+--------------------+

+----+
| DEK| (32 random bytes per row)
+----+
   |
   | KEK_v.wrap(DEK)  (envelope encryption)
   v
+--------------------+
|   wrapped DEK       | -> credential_versions.dek_wrapped + kek_version
+--------------------+

KEK source (per tier):
  Tier 1: env var CRE_KEK_HEX (64-hex chars = 32 bytes)
  Tier 2: AWS KMS via LocalStack
  Tier 3: real AWS KMS or HSM
```

Per-row DEKs collapse the AES-GCM nonce-reuse birthday concern (each row's DEK encrypts exactly one message). AAD-binding prevents ciphertext-swap attacks where an attacker with DB write tries to swap a low-privilege row's ciphertext into a high-privilege row.

`algorithm_id` is reserved for crypto agility:
- `0x01` = AES-256-GCM (today)
- `0x02` = XChaCha20-Poly1305 (long nonce, simpler)
- `0x03` = ML-KEM hybrid wrap (post-quantum forward secrecy)

### Audit log integrity stack

Three layers, increasingly hard to bypass:

```
+-------------------------------------------------+
|  Layer 3: Ed25519-signed Merkle batches         |
|    audit_batches table, hourly seal, signed     |
|    over (start_seq, end_seq, root)              |
|    Auditor verifies with public key only.       |
+-------------------------------------------------+
                    |
                    | leaves: content_hash[]
                    v
+-------------------------------------------------+
|  Layer 2: HMAC ratchet                          |
|    K_v signs each row's content_hash; every     |
|    1024 rows -> K_{v+1} = HKDF(K_v, "ratchet"); |
|    K_v zeroized in memory                       |
+-------------------------------------------------+
                    |
                    v
+-------------------------------------------------+
|  Layer 1: Hash chain                            |
|    content_hash = SHA256(prev_hash ||           |
|                          canonical_payload)     |
|    rendering single-row tampering visible       |
+-------------------------------------------------+
                    |
                    v
+-------------------------------------------------+
|  PostgreSQL audit_events table                  |
|    - INSERT-only role grant                     |
|    - UPDATE/DELETE/TRUNCATE trigger refuses     |
+-------------------------------------------------+
```

The PG triggers are not strictly necessary (the chain catches tampering anyway), but they fail loud at write-time which is much friendlier for operators. SQLite tier 1 documents the relaxed guarantee.

## Concurrency

| Scope | Bound | Mechanism |
|---|---|---|
| Per-credential | 1 active rotation | PG advisory lock keyed on `credential_id` (or per-process Mutex on SQLite) |
| Per-rotator-kind | configurable | `Channel(Nil).new(capacity: N)` semaphore |
| Global | 20 (default) | Global rotation worker pool |

Crystal fibers + bounded channels = clean rate limiting without threads or locks.

## Lifecycle (cre run)

```
1. Load config (env + flags)
2. Open persistence (PG or SQLite); migrate!
3. Initialize crypto (load KEK from env or KMS)
4. Load + validate compiled-in policies (REGISTRY)
5. Start EventBus.run (dispatcher fiber)
6. Start subscribers: audit, log, telegram, metrics
7. Start Scheduler (publishes SchedulerTick on tick)
8. Start PolicyEvaluator (subscribes to ticks + credential events)
9. Optionally start TUI (cre watch)
10. Block on signal: SIGTERM/SIGINT triggers graceful drain
```

Graceful shutdown: `engine.stop` publishes `ShutdownRequested`, gives subscribers ~50ms to flush, then closes the bus inbox and joins each subscriber fiber.
