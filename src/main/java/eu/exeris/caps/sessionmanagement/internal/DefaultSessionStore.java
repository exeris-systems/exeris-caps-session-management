package eu.exeris.caps.sessionmanagement.internal;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionInfo;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.SessionStore;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link SessionStore}.
 *
 * @since 0.1.0
 */
public final class DefaultSessionStore implements SessionStore {

    private final SessionRepository repository;
    private final SessionPolicy policy;
    private final SessionAuditBridge auditBridge;

    public DefaultSessionStore(SessionRepository repository, SessionPolicy policy, SessionAuditBridge auditBridge) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.auditBridge = auditBridge;
    }

    @Override
    public Session createSession(UUID subjectId, ClientMetadata metadata) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        ClientMetadata meta = metadata != null ? metadata : ClientMetadata.empty();
        Instant now = Instant.now();

        // Evict oldest sessions if active limit reached
        List<SessionRecord> active = repository.findActiveSessions(subjectId, now);
        if (active.size() >= policy.maxActiveSessionsPerSubject()) {
            List<SessionRecord> sorted = active.stream()
                    .sorted(Comparator.comparing(SessionRecord::createdAt).thenComparing(SessionRecord::id))
                    .toList();
            int toEvict = active.size() - policy.maxActiveSessionsPerSubject() + 1;
            for (int i = 0; i < toEvict && i < sorted.size(); i++) {
                SessionRecord oldest = sorted.get(i);
                repository.revokeSession(oldest.id(), now);
                if (auditBridge != null) {
                    auditBridge.emitSessionRevoked(oldest.id(), subjectId);
                }
            }
        }

        UUID sessionId = UUID.randomUUID();
        Instant expiresAt = now.plus(policy.sessionTtl());
        SessionRecord sessionRecord = new SessionRecord(
                sessionId,
                subjectId,
                now,
                expiresAt,
                now,
                null,
                meta.userAgent(),
                meta.ipAddress()
        );
        repository.saveSession(sessionRecord);

        if (auditBridge != null) {
            auditBridge.emitSessionCreated(sessionId, subjectId, meta, expiresAt);
        }

        return toDomain(sessionRecord);
    }

    @Override
    public List<SessionInfo> listActiveSessions(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Instant now = Instant.now();
        return repository.findActiveSessions(subjectId, now).stream()
                .map(r -> new SessionInfo(
                        r.id(),
                        r.createdAt(),
                        r.expiresAt(),
                        r.lastActiveAt(),
                        r.userAgent(),
                        r.ipAddress(),
                        false
                ))
                .toList();
    }

    @Override
    public Optional<SessionInfo> findSession(UUID sessionId) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        return repository.findSession(sessionId)
                .map(r -> new SessionInfo(
                        r.id(),
                        r.createdAt(),
                        r.expiresAt(),
                        r.lastActiveAt(),
                        r.userAgent(),
                        r.ipAddress(),
                        false
                ));
    }

    @Override
    public boolean revokeSession(UUID subjectId, UUID sessionId) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Instant now = Instant.now();
        UUID effectiveSubjectId = subjectId;
        if (effectiveSubjectId == null) {
            effectiveSubjectId = repository.findSession(sessionId).map(SessionRecord::subjectId).orElse(null);
        }
        boolean revoked = repository.revokeSession(subjectId, sessionId, now);
        if (revoked && auditBridge != null) {
            auditBridge.emitSessionRevoked(sessionId, effectiveSubjectId);
        }
        return revoked;
    }

    @Override
    public int revokeAllForSubject(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Instant now = Instant.now();
        int count = repository.revokeAllSessionsForSubject(subjectId, now);
        if (count > 0 && auditBridge != null) {
            auditBridge.emitSessionsRevokedAll(subjectId, count);
        }
        return count;
    }

    private static Session toDomain(SessionRecord record) {
        return new Session(
                record.id(),
                record.subjectId(),
                record.createdAt(),
                record.expiresAt(),
                record.lastActiveAt(),
                record.revokedAt(),
                record.userAgent(),
                record.ipAddress()
        );
    }
}
