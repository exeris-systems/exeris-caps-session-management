---
title: "exeris-caps-session-management roadmap"
type: roadmap
visibility: public
owning-repo: exeris-caps-session-management
status: active
last-verified: 2026-10-15
---

# `exeris-caps-session-management` roadmap

This repository is a proof of concept: sign-in sessions and single-use refresh tokens on PostgreSQL, built against the kernel 0.13 line, with no published artefact. This file records what it does not cover. Read it together with the code; the pull request that closes a gap removes or rewrites its entry.

Milestones are versions, not dates.

A gap that must close before the first release has a tracking issue in the `0.1.0` milestone, linked from its entry. Everything else is listed under Later and has no issue until it is scheduled.

## Before 0.1.0

### A composed module has no store

The composition conductor builds the module through its no-arg constructor, which leaves both services null, and `initialize()` then refuses to start (`src/main/java/eu/exeris/caps/sessionmanagement/SessionManagementModule.java`, the no-arg constructor and `requireWired()`). The `TransactionalExecutor`, `SessionPolicy`, `AccessTokenIssuer` and `AuditLogSink` are constructor arguments that nothing in the composition supplies, so only a hand-built instance serves requests. The failure is closed, but the Identity SKU cannot compose a working capability today. The kernel 0.13 line publishes `KernelProviders.TRANSACTIONAL_EXECUTOR`, so the executor can be taken in `initialize()`. The `@Requires` on `TransactionalExecutor` stays `optional = true` because tooling reports a requirement on a kernel SPI type as EXT-PLUG-2201 (exeris-tooling#409). Tracked in [#11](https://github.com/exeris-systems/exeris-caps-session-management/issues/11).

## Later

### Access token issuer is a local copy

`spi.AccessTokenIssuer` and `api.IssuedAccessToken` are this capability's own types (`src/main/java/eu/exeris/caps/sessionmanagement/spi/AccessTokenIssuer.java`). `exeris-caps-token-issuer` provides its own `AccessTokenIssuer` and `IssuedAccessToken` in another package, so the two cannot be composed without an adapter, and until one exists rotation returns no access token. The capability should take a `@Requires` on the token-issuer contract and drop the copy. This waits on a decision about which side owns the contract type, and on the token-issuer capability's 0.1.0 contract.

### Consumers of the capability are not yet adapted

The refresh and sign-out routes of the Identity SKU must pass a `SessionPrincipal`, map the `sid` claim into a `SessionBoundPrincipal` through a `ClaimsMapper`, handle `RotationOutcome`, and apply `SessionManagementModule.MIGRATIONS`. None of this is in this repository. It waits on `exeris-sku-identity`.

### Rows are never deleted

Expired, revoked and consumed sessions and refresh tokens stay in `sessions` and `refresh_tokens` indefinitely. Nothing in `PostgresSessionRepository` deletes a row, and the schema has no retention column or partitioning (`src/main/resources/db/migration/exeris-caps-session-management/V1__session_management.sql`). Every row also keeps the recorded user agent and IP address. A deployment grows without bound and holds personal data past the life of the session. A purge needs a rule on how long a consumed token must remain readable, because reuse detection depends on it, and a scheduler to run it. It waits on that rule.

### An access token outlives its session

The capability exposes no way to ask whether a session is still live: `SessionStore` has no lookup, and revoking a session changes only the stored rows. An access token already issued for a revoked session stays valid at the kernel's security edge until it expires. Closing this needs either a short access-token lifetime fixed by the issuer or a liveness check at the edge. It waits on a design decision that spans the token issuer and the Identity SKU.

### Audit and issuer are silently optional

A module wired without an `AuditLogSink` emits no `TOKEN_REPLAY_DETECTED`, `SESSION_REVOKED` or `TOKEN_ROTATED` event, and one wired without an `AccessTokenIssuer` returns rotations with no access token. Neither fails at start (`SessionManagementModule.java`, the wired constructors). A deployment that needs the audit trail cannot make the capability insist on it. It waits on a rule for which optional edges an SKU may require at boot.

### No rate limit on refresh attempts

`rotate` and `revoke` accept any number of attempts with unknown tokens and do no work to slow guessing (`src/main/java/eu/exeris/caps/sessionmanagement/internal/DefaultRefreshTokenRotation.java`). The 128-bit token space makes guessing impractical, but each attempt costs a database round trip. Throttling is a route concern that belongs to the Identity SKU or a rate-limiting capability, and waits on one of them.
