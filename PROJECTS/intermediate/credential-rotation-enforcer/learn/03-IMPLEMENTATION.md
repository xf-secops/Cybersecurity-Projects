<!--
©AngelaMos | 2026
03-IMPLEMENTATION.md
-->

# Implementation Walkthrough

This document points you at the most important code paths. Read it with `tree src/` open in another window.

## The Policy DSL (compile-time validation)

`src/cre/policy/dsl.cr` defines a top-level `policy` method that uses Crystal's `with builder yield` so every Builder method is callable receiver-less inside the block:

```crystal
def policy(name : String, &block)
  builder = CRE::Policy::Builder.new(name)
  with builder yield
  CRE::Policy::REGISTRY << builder.build
end
```

The Builder methods (in `src/cre/policy/builder.cr`) take typed enum parameters - so `enforce :rotate_immediately` autocasts the symbol to `Action::RotateImmediately` at compile time. Typo'd `:rotate_immediatly` fails the build with `expected Action, got :rotate_immediatly`. The `match {}` block is a real `Proc(Credential, Bool)` so `c.kund` (typo) breaks compilation pointing at the policy file.

`Builder#build` validates required fields (`matcher`, `max_age`, `enforce_action`) and raises `BuilderError` if any are missing. This makes a policy literally unable to ship to production in a misformed state.

## The Event Bus (fanout via Crystal channels)

`src/cre/engine/event_bus.cr` exposes `subscribe(buffer:, overflow:)` returning a `Channel(Event)`. The `run` method spawns a single dispatcher fiber that reads from `@inbox` and forwards to each subscriber's channel. Per-subscriber overflow policy (`Block` or `Drop`) drives whether a slow consumer pauses the dispatcher or quietly loses events.

The `dispatch` method uses Crystal's `select` to attempt a non-blocking send for `Drop` subscribers and logs a warning when full. `Block` subscribers get `send` directly.

## The Rotator Plugin Registration

`src/cre/rotators/rotator.cr` declares an abstract base with a class-level `REGISTRY = {} of Symbol => Rotator.class`. The macro `register_as` populates this at compile time:

```crystal
abstract class Rotator
  REGISTRY = {} of Symbol => Rotator.class

  macro register_as(kind)
    ::CRE::Rotators::Rotator::REGISTRY[{{ kind }}] = self
  end
end
```

When a file like `src/cre/rotators/aws_secrets.cr` is required, the `register_as :aws_secretsmgr` line runs at *compile time* and the class shows up in `Rotator::REGISTRY[:aws_secretsmgr]`. No central list to maintain.

## The 4-step Orchestrator

`src/cre/engine/rotation_orchestrator.cr` runs the contract:

```
generate -> persist pending version
apply    -> rotator-specific (often no-op for cloud rotators where generate already exposed)
verify   -> read back, byte-equal check
commit   -> promote new -> AWSCURRENT, demote old -> AWSPREVIOUS
```

Each step publishes `RotationStepStarted` and either `RotationStepCompleted` or `RotationStepFailed` to the bus. On any exception during apply/verify, `rollback_apply` is invoked and `RotationFailed` is published. `RotationCompleted` is the success terminal.

The orchestrator never directly calls audit. Audit happens automatically because `AuditSubscriber` is on the bus listening for these exact event types - the orchestrator can't forget to log.

## SigV4 Signer (the AWS-flavored work)

`src/cre/aws/signer.cr` implements RFC-style AWS SigV4:

```
canonical_request = method + canonical_uri + canonical_query +
                    canonical_headers + signed_headers + payload_hash
string_to_sign    = "AWS4-HMAC-SHA256\n" + amz_date + "\n" +
                    credential_scope + "\n" + sha256(canonical_request)
signing_key       = HMAC chain (kSecret -> kDate -> kRegion -> kService -> kSigning)
signature         = HMAC(signing_key, string_to_sign)
```

The `Authorization` header is built from `algorithm + Credential=... + SignedHeaders=... + Signature=...`. Includes `X-Amz-Security-Token` when an STS session token is supplied.

Tested against AWS canonical examples in `spec/unit/aws/signer_spec.cr` for idempotence and format conformance.

## Audit Log Integrity (three-layer)

`src/cre/audit/audit_log.cr` orchestrates Layer 1 + 2:
- `latest_hash` from the DB (genesis = 32 zero bytes for an empty log)
- `content_hash = HashChain.next_hash(prev_hash, canonical_payload)`
- `hmac = HmacRatchet#sign(content_hash)`; ratchet rolls every 1024 rows

`src/cre/audit/batch_sealer.cr` builds Layer 3:
- Walk new audit_events since `last_sealed_seq`
- Build a Merkle tree (`Merkle.root`) over each row's `content_hash`
- Sign `(start_seq, end_seq, root)` with Ed25519 via `Signing::Ed25519Signer`
- Store the signed batch in `audit_batches`

Crystal's stdlib OpenSSL doesn't expose Ed25519 high-level wrappers, so `src/cre/audit/signing.cr` reaches into LibCrypto via FFI: `EVP_PKEY_new_raw_private_key`, `EVP_DigestSign`, etc. Public-key verification is symmetrical: `Ed25519Verifier#verify(message, signature)`.

## AEAD Envelope Encryption

`src/cre/crypto/aead.cr` does AES-256-GCM via LibCrypto FFI (stdlib `OpenSSL::Cipher` doesn't expose `auth_data=` / `auth_tag` for GCM). The envelope (`src/cre/crypto/envelope.cr`) generates a 32-byte DEK per row, encrypts plaintext with AES-256-GCM(plaintext, DEK, AAD), then wraps the DEK with KEK using a separate AEAD (with its own AAD `kek-wrap|v<version>`). Both ciphertexts are `nonce(12) || tag(16) || body`.

Decrypting requires the KEK to unwrap the DEK, then the DEK + AAD to decrypt the payload. AAD mismatch fails tag verification at the inner layer; KEK version mismatch fails at unwrap.

## TUI

`src/cre/tui/state.cr` holds a rolling view of active rotations + recent events. `apply(ev)` is the single entry point that mutates state; pure update logic, easy to test.

`src/cre/tui/renderer.cr` paints the four panels to any IO. ANSI escapes via `src/cre/tui/ansi.cr` (stdlib only). The renderer's `pad` helper accounts for ANSI escape widths so column alignment is correct under colors.

`src/cre/tui/tui.cr` ties it together: subscribes to the bus (Drop overflow), spawns a tick fiber + an event fiber, both calling `maybe_render` which throttles to `refresh_interval`.

## Telegram Bot

`src/cre/notifiers/telegram.cr` is a thin HTTP::Client wrapper for the Telegram Bot API (no tourmaline dependency for the notification path).

`src/cre/notifiers/telegram_bot.cr` does long-poll `getUpdates` and dispatches commands. Auth is by chat-ID allowlist; viewer tier vs operator tier separates `/status` from `/rotate`. `/rotate` publishes `RotationScheduled` to the bus, where the orchestrator picks it up.

## Persistence Layer Shape

`src/cre/persistence/repos.cr` declares the abstract repos (`CredentialsRepo`, `VersionsRepo`, `RotationsRepo`, `AuditRepo`) and the record types (`RotationRecord`, `AuditEntry`, `AuditBatch`, plus the `RotatorKind` and `RotationState` enums).

`src/cre/persistence/sqlite/` and `src/cre/persistence/postgres/` mirror each other under the same interface. PG uses `$1, $2` placeholders, BYTEA + JSONB native types, BIGSERIAL audit; SQLite uses `?` placeholders, BLOB + TEXT (with JSON helpers).

`audit_events` is the most carefully guarded table in the schema - PG triggers refuse `UPDATE`, `DELETE`, `TRUNCATE` and the application role doesn't have those grants either. Two independent locks; both must be subverted to forge history.
