# exeris-caps-session-management

Sign-in sessions and refresh tokens as an Exeris capability. It provides `SessionStore` (create a session; list, revoke one, revoke all and log out, each for the authenticated caller only) and `RefreshTokenRotation` (opaque single-use refresh tokens stored hashed, rotated on every use; presenting a consumed token to a live session revokes the whole session).

Status: proof of concept, built against `exeris-kernel` 0.13.0-SNAPSHOT. The API is not stable and no artefact has been published.

## Where it sits

- **Layer:** Layer 5 — Domain primitive (identity), in the Tier 2 capability map of [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md) §3.2.
- **Depends on:** `exeris-kernel-spi`, `exeris-sdk-composition-lifecycle` and `exeris-caps-audit-trail`.
- **Provides** (`@Provides`, all version 0.1.0): `SessionStore`, `RefreshTokenRotation`.
- **Requires** (`@Requires`, each declared `optional = true`): `eu.exeris.kernel.spi.persistence.TransactionalExecutor`, `eu.exeris.caps.audittrail.api.AuditLogSink`, `eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer`.
- **Wall (ADR-055):** `eu.exeris.caps.sessionmanagement.api` is the cross-cap surface; `eu.exeris.caps.sessionmanagement.internal` is private, and a sibling cap reaching into it fails the build. No Spring, servlet, Netty or reactive type may appear (ADR-006).

Behaviour worth knowing before composing it:

- **Refresh tokens are strictly single-use.** `rotate` consumes the presented token with one conditional `UPDATE ... WHERE consumed_at IS NULL` under a lock on the session row, so of any number of concurrent presentations exactly one returns `RotationOutcome.Rotated`. While the session is live, the first presentation of a consumed token returns `RotationOutcome.ReuseDetected` and revokes the session and every refresh token issued for it (ADR-099 obligation 9); later presentations return `RotationOutcome.Rejected(SESSION_REVOKED)`. A consumed token presented to a session that has already expired or gone idle returns `RotationOutcome.Rejected(SESSION_EXPIRED)` or `Rejected(SESSION_IDLE)`, is audited as `TOKEN_REPLAY_DETECTED` and revokes nothing, because the session no longer accepts any token. No interval exists in which a consumed token is accepted again; a client that refreshes from several tabs must serialise its refreshes.
- **Sessions end on an absolute lifetime and an idle timeout** (`SessionPolicy`; defaults 7 days and 12 hours). Activity is a successful rotation. A refresh token never outlives the session's idle window or its absolute expiry, and a revoked, expired or idle session refuses refresh without consuming the token.
- **Subject-scoped operations take a `SessionPrincipal`**, which only `SessionPrincipal.current()` produces, from the principal the kernel's security edge bound after verifying the access token. No constructor or factory accepts a subject identifier, so a route cannot act on a `subjectId` from a request body or query. `logout` needs the session identifier as well: the composition's `ClaimsMapper` returns a `SessionBoundPrincipal` carrying the token's `sid` claim. `createSession` and `revokeAllForSubject` take a bare subject because the sign-in and credential-change flows verify the subject themselves.
- **Storage is PostgreSQL through the kernel `TransactionalExecutor`, and nothing else.** A module built without one has no services and refuses to initialize. The schema is `SessionManagementModule.MIGRATIONS`, classpath resources under `db/migration/exeris-caps-session-management/` (idempotent DDL, namespaced by artifactId); the composing SKU applies them, the capability does not.
- **No tenant column and no row-level security.** ADR-099 obligation 10 keys session records by subject, and subjects are per deployment; tenant membership belongs to `multi-tenancy` and `rbac-policy`. Neither sign-in nor refresh carries a verified tenant to scope rows by. The tables belong in the identity deployment's own schema or database.
- Issuing an access token on rotation goes through an interface this cap declares itself (`spi.AccessTokenIssuer`). With none wired, rotation returns no access token.

## Build & test

Requires JDK 25 and Maven 3.9+.

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — the processor writes capability metadata
mvn verify                               # pass 2 — generate cap-manifest.json, validate the graph, scan the Wall
```

The PostgreSQL integration test (`PostgresSessionManagementIT`) starts `postgres:16` through Testcontainers and is skipped when no Docker daemon is reachable.

Both passes are needed after a `clean`: `exeris:generate` runs before `compile`, and `compile` is when the processor writes the metadata it reads. `src/main/generated/java/cap-manifest.json` is committed, so a clean `git status` after `mvn verify` shows the manifest matches the declaration.

`exeris-sdk` 0.12.0 and `exeris-tooling` 0.10.0 resolve from Maven Central, and `exeris-kernel` 0.13.0-SNAPSHOT is resolved from GitHub Packages, which needs a token with `read:packages`; the sibling `exeris-caps-service-boundary-core` and `exeris-caps-audit-trail` are built from source first. [`.github/workflows/build.yml`](.github/workflows/build.yml) is the exact sequence, and [`.github/maven-settings.xml`](.github/maven-settings.xml) the repository configuration it uses.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [Capability Author Guide](https://github.com/exeris-systems/exeris-docs/blob/main/cap-author-guide.md) — how a cap declares `@CapabilityModule`, `@Provides`, `@Requires` and `@CapabilityLifecycle`.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-055](https://github.com/exeris-systems/exeris-tooling/blob/main/docs/adr/ADR-055-cap-tier-wall-guard.md) — cap-tier Wall guard.
- [ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md) — signed licence manifest.
- [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md) — capability entitlement enforcement.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — the Identity SKU, which lists this cap.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-caps-session-management` is a `commercial` capability under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

The cap enforces that at boot. It registers a kernel `EntitlementRequirement` whose capability id is `exeris-caps-session-management`, and in a production-class environment the kernel's contract gate refuses to start unless a signed licence manifest lists that id among its entitlements ([ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md), [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md)).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
