package eu.exeris.caps.sessionmanagement.internal;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionInfo;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.caps.sessionmanagement.api.SessionStore;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.repository.RevocationReason;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Default {@link SessionStore}. Every subject-scoped operation passes the principal's subject to the
 * repository, which puts it in the statement's {@code WHERE} clause.
 *
 * @since 0.1.0
 */
public final class DefaultSessionStore implements SessionStore {

    private final SessionRepository repository;
    private final SessionPolicy policy;
    private final SessionAuditBridge auditBridge;
    private final Clock clock;

    public DefaultSessionStore(SessionRepository repository, SessionPolicy policy, SessionAuditBridge auditBridge, Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.auditBridge = auditBridge;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public Session createSession(UUID subjectId, ClientMetadata metadata) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        ClientMetadata meta = metadata != null ? metadata : ClientMetadata.empty();
        Instant now = clock.instant();

        SessionRecord record = new SessionRecord(
                UUID.randomUUID(),
                subjectId,
                now,
                now.plus(policy.absoluteLifetime()),
                now,
                null,
                meta.userAgent(),
                meta.ipAddress()
        );
        List<UUID> evicted = repository.createSession(record, policy.maxActiveSessionsPerSubject(), policy.idleTimeout());

        if (auditBridge != null) {
            for (UUID victim : evicted) {
                auditBridge.emitSessionRevoked(victim, subjectId, RevocationReason.EVICTED);
            }
            auditBridge.emitSessionCreated(record.id(), subjectId, meta, record.expiresAt());
        }
        return record.toDomain();
    }

    @Override
    public List<SessionInfo> listSessions(SessionPrincipal principal) {
        Objects.requireNonNull(principal, "principal must not be null");
        UUID current = principal.sessionId().orElse(null);
        return repository.findActiveSessions(principal.subjectId(), clock.instant(), policy.idleTimeout()).stream()
                .map(r -> SessionInfo.from(r.toDomain(), policy, r.id().equals(current)))
                .toList();
    }

    @Override
    public boolean revokeSession(SessionPrincipal principal, UUID sessionId) {
        Objects.requireNonNull(principal, "principal must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        return revokeOwned(principal.subjectId(), sessionId, RevocationReason.REVOKED_BY_SUBJECT);
    }

    @Override
    public int revokeAllSessions(SessionPrincipal principal) {
        Objects.requireNonNull(principal, "principal must not be null");
        return revokeAll(principal.subjectId(), RevocationReason.REVOKED_ALL_BY_SUBJECT);
    }

    @Override
    public boolean logout(SessionPrincipal principal) {
        Objects.requireNonNull(principal, "principal must not be null");
        UUID sessionId = principal.sessionId().orElseThrow(() -> new IllegalStateException(
                "the authenticated principal carries no session identifier; logout needs a SessionBoundPrincipal"));
        return revokeOwned(principal.subjectId(), sessionId, RevocationReason.LOGOUT);
    }

    @Override
    public int revokeAllForSubject(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return revokeAll(subjectId, RevocationReason.CREDENTIAL_CHANGED);
    }

    private boolean revokeOwned(UUID subjectId, UUID sessionId, RevocationReason reason) {
        boolean revoked = repository.revokeSession(subjectId, sessionId, clock.instant(), reason);
        if (revoked && auditBridge != null) {
            auditBridge.emitSessionRevoked(sessionId, subjectId, reason);
        }
        return revoked;
    }

    private int revokeAll(UUID subjectId, RevocationReason reason) {
        int count = repository.revokeAllSessions(subjectId, clock.instant(), reason);
        if (count > 0 && auditBridge != null) {
            auditBridge.emitSessionsRevokedAll(subjectId, count, reason);
        }
        return count;
    }
}
