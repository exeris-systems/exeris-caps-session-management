package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome.Reason;
import eu.exeris.caps.sessionmanagement.internal.repository.FamilyRevocation;
import eu.exeris.caps.sessionmanagement.internal.repository.IssueResult;
import eu.exeris.caps.sessionmanagement.internal.repository.RefreshTokenRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.RevocationReason;
import eu.exeris.caps.sessionmanagement.internal.repository.RotationExecutionResult;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Test double for {@link SessionRepository} with the PostgreSQL implementation's semantics; every method
 * holds the monitor for its whole body, standing in for one transaction.
 */
final class InMemorySessionRepository implements SessionRepository {

    private final Map<UUID, SessionRecord> sessions = new HashMap<>();
    private final Map<String, RefreshTokenRecord> tokensByHash = new HashMap<>();

    @Override
    public synchronized List<UUID> createSession(SessionRecord session, int maxActive, Duration idleTimeout) {
        Instant now = session.createdAt();
        List<SessionRecord> active = active(session.subjectId(), now, idleTimeout).stream()
                .sorted(Comparator.comparing(SessionRecord::createdAt).thenComparing(SessionRecord::id).reversed())
                .toList();
        List<UUID> evicted = new ArrayList<>();
        for (int i = maxActive - 1; i < active.size(); i++) {
            revokeFamily(active.get(i).id(), now);
            evicted.add(active.get(i).id());
        }
        sessions.put(session.id(), session);
        return evicted;
    }

    @Override
    public synchronized List<SessionRecord> findActiveSessions(UUID subjectId, Instant now, Duration idleTimeout) {
        return active(subjectId, now, idleTimeout);
    }

    @Override
    public synchronized boolean revokeSession(UUID subjectId, UUID sessionId, Instant now, RevocationReason reason) {
        SessionRecord s = sessions.get(sessionId);
        if (s == null || !s.subjectId().equals(subjectId) || s.isRevoked()) {
            return false;
        }
        revokeFamily(sessionId, now);
        return true;
    }

    @Override
    public synchronized int revokeAllSessions(UUID subjectId, Instant now, RevocationReason reason) {
        int count = 0;
        for (SessionRecord s : List.copyOf(sessions.values())) {
            if (s.subjectId().equals(subjectId) && !s.isRevoked()) {
                revokeFamily(s.id(), now);
                count++;
            }
        }
        return count;
    }

    @Override
    public synchronized IssueResult issueFirstToken(UUID subjectId, RefreshTokenRecord token, Instant now, Duration idleTimeout) {
        SessionRecord s = sessions.get(token.sessionId());
        if (s == null || !s.subjectId().equals(subjectId)) {
            return IssueResult.refused(IssueResult.Status.SESSION_NOT_FOUND);
        }
        if (s.isRevoked()) {
            return IssueResult.refused(IssueResult.Status.SESSION_REVOKED);
        }
        if (s.isExpired(now) || s.isIdle(now.minus(idleTimeout))) {
            return IssueResult.refused(IssueResult.Status.SESSION_EXPIRED);
        }
        if (tokensByHash.values().stream().anyMatch(t -> t.sessionId().equals(s.id()))) {
            return IssueResult.refused(IssueResult.Status.ALREADY_ISSUED);
        }
        Instant expiresAt = s.tokenExpiry(now, idleTimeout);
        tokensByHash.put(token.tokenHash(), new RefreshTokenRecord(
                token.id(), s.id(), token.tokenHash(), now, expiresAt, null, null));
        return IssueResult.issued(expiresAt);
    }

    @Override
    public synchronized RotationExecutionResult rotate(
            String presentedHash, UUID newTokenId, String newTokenHash, ClientMetadata metadata, Instant now, Duration idleTimeout) {
        RefreshTokenRecord token = tokensByHash.get(presentedHash);
        if (token == null) {
            return new RotationExecutionResult.Rejected(Reason.UNKNOWN_TOKEN);
        }
        SessionRecord s = sessions.get(token.sessionId());
        if (s.isRevoked()) {
            return new RotationExecutionResult.Rejected(Reason.SESSION_REVOKED);
        }
        if (s.isExpired(now)) {
            return new RotationExecutionResult.Rejected(Reason.SESSION_EXPIRED);
        }
        if (s.isIdle(now.minus(idleTimeout))) {
            return new RotationExecutionResult.Rejected(Reason.SESSION_IDLE);
        }
        if (token.isConsumed()) {
            revokeFamily(s.id(), now);
            return new RotationExecutionResult.ReuseDetected(s.id(), s.subjectId());
        }
        if (token.isRevoked()) {
            return new RotationExecutionResult.Rejected(Reason.TOKEN_REVOKED);
        }
        if (token.isExpired(now)) {
            return new RotationExecutionResult.Rejected(Reason.TOKEN_EXPIRED);
        }
        tokensByHash.put(presentedHash, new RefreshTokenRecord(
                token.id(), token.sessionId(), token.tokenHash(), token.createdAt(), token.expiresAt(), now, null));
        tokensByHash.put(newTokenHash, new RefreshTokenRecord(
                newTokenId, s.id(), newTokenHash, now, s.tokenExpiry(now, idleTimeout), null, null));
        String ua = metadata != null && metadata.userAgent() != null ? metadata.userAgent() : s.userAgent();
        String ip = metadata != null && metadata.ipAddress() != null ? metadata.ipAddress() : s.ipAddress();
        SessionRecord updated = new SessionRecord(s.id(), s.subjectId(), s.createdAt(), s.expiresAt(), now, null, ua, ip);
        sessions.put(s.id(), updated);
        return new RotationExecutionResult.Rotated(updated);
    }

    @Override
    public synchronized Optional<FamilyRevocation> revokeFamilyByTokenHash(String tokenHash, Instant now, RevocationReason reason) {
        RefreshTokenRecord token = tokensByHash.get(tokenHash);
        if (token == null) {
            return Optional.empty();
        }
        SessionRecord s = sessions.get(token.sessionId());
        if (s.isRevoked()) {
            return Optional.empty();
        }
        revokeFamily(s.id(), now);
        return Optional.of(new FamilyRevocation(s.id(), s.subjectId()));
    }

    private List<SessionRecord> active(UUID subjectId, Instant now, Duration idleTimeout) {
        Instant idleCutoff = now.minus(idleTimeout);
        return sessions.values().stream()
                .filter(s -> s.subjectId().equals(subjectId))
                .filter(s -> !s.isRevoked() && !s.isExpired(now) && !s.isIdle(idleCutoff))
                .sorted(Comparator.comparing(SessionRecord::createdAt).thenComparing(SessionRecord::id))
                .toList();
    }

    private void revokeFamily(UUID sessionId, Instant now) {
        SessionRecord s = sessions.get(sessionId);
        if (!s.isRevoked()) {
            sessions.put(sessionId, new SessionRecord(
                    s.id(), s.subjectId(), s.createdAt(), s.expiresAt(), s.lastActiveAt(), now, s.userAgent(), s.ipAddress()));
        }
        tokensByHash.replaceAll((hash, t) -> t.sessionId().equals(sessionId) && !t.isRevoked()
                ? new RefreshTokenRecord(t.id(), t.sessionId(), t.tokenHash(), t.createdAt(), t.expiresAt(), t.consumedAt(), now)
                : t);
    }
}
