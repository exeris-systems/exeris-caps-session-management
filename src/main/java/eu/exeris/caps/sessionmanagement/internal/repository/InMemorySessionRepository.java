package eu.exeris.caps.sessionmanagement.internal.repository;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link SessionRepository}.
 *
 * @since 0.1.0
 */
public final class InMemorySessionRepository implements SessionRepository {

    private final Map<UUID, SessionRecord> sessions = new ConcurrentHashMap<>();
    private final Map<String, RefreshTokenRecord> tokensByHash = new ConcurrentHashMap<>();
    private final java.time.Duration transitionGraceWindow;

    public InMemorySessionRepository() {
        this(java.time.Duration.ZERO);
    }

    public InMemorySessionRepository(java.time.Duration transitionGraceWindow) {
        this.transitionGraceWindow = Objects.requireNonNull(transitionGraceWindow, "transitionGraceWindow must not be null");
    }

    @Override
    public synchronized void saveSession(SessionRecord session) {
        Objects.requireNonNull(session, "session must not be null");
        sessions.put(session.id(), session);
    }

    @Override
    public Optional<SessionRecord> findSession(UUID sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.get(sessionId));
    }

    @Override
    public synchronized List<SessionRecord> findActiveSessions(UUID subjectId, Instant now) {
        if (subjectId == null) {
            return List.of();
        }
        return sessions.values().stream()
                .filter(s -> s.subjectId().equals(subjectId))
                .filter(s -> s.isActive(now))
                .sorted(Comparator.comparing(SessionRecord::createdAt).thenComparing(SessionRecord::id))
                .toList();
    }

    @Override
    public synchronized boolean revokeSession(UUID sessionId, Instant revokedAt) {
        if (sessionId == null) {
            return false;
        }
        SessionRecord existing = sessions.get(sessionId);
        if (existing == null || existing.isRevoked()) {
            return false;
        }
        SessionRecord updated = new SessionRecord(
                existing.id(),
                existing.subjectId(),
                existing.createdAt(),
                existing.expiresAt(),
                existing.lastActiveAt(),
                revokedAt,
                existing.userAgent(),
                existing.ipAddress()
        );
        sessions.put(sessionId, updated);
        revokeAllRefreshTokensForSession(sessionId, revokedAt);
        return true;
    }

    @Override
    public synchronized boolean revokeSession(UUID subjectId, UUID sessionId, Instant revokedAt) {
        if (sessionId == null) {
            return false;
        }
        SessionRecord existing = sessions.get(sessionId);
        if (existing == null || existing.isRevoked()) {
            return false;
        }
        if (subjectId != null && !existing.subjectId().equals(subjectId)) {
            return false;
        }
        return revokeSession(sessionId, revokedAt);
    }

    @Override
    public synchronized int revokeAllSessionsForSubject(UUID subjectId, Instant revokedAt) {
        if (subjectId == null) {
            return 0;
        }
        int count = 0;
        for (SessionRecord session : sessions.values()) {
            if (session.subjectId().equals(subjectId) && !session.isRevoked()) {
                revokeSession(session.id(), revokedAt);
                count++;
            }
        }
        return count;
    }

    @Override
    public synchronized void updateSessionActivity(UUID sessionId, Instant lastActiveAt, String userAgent, String ipAddress) {
        SessionRecord existing = sessions.get(sessionId);
        if (existing != null) {
            String ua = userAgent != null ? userAgent : existing.userAgent();
            String ip = ipAddress != null ? ipAddress : existing.ipAddress();
            SessionRecord updated = new SessionRecord(
                    existing.id(),
                    existing.subjectId(),
                    existing.createdAt(),
                    existing.expiresAt(),
                    lastActiveAt,
                    existing.revokedAt(),
                    ua,
                    ip
            );
            sessions.put(sessionId, updated);
        }
    }

    @Override
    public synchronized void saveRefreshToken(RefreshTokenRecord token) {
        Objects.requireNonNull(token, "token must not be null");
        tokensByHash.put(token.tokenHash(), token);
    }

    @Override
    public Optional<RefreshTokenRecord> findRefreshTokenByHash(String tokenHash) {
        if (tokenHash == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(tokensByHash.get(tokenHash));
    }

    @Override
    public synchronized boolean revokeRefreshToken(String tokenHash, Instant revokedAt) {
        if (tokenHash == null) {
            return false;
        }
        RefreshTokenRecord existing = tokensByHash.get(tokenHash);
        if (existing == null || existing.isRevoked()) {
            return false;
        }
        RefreshTokenRecord updated = new RefreshTokenRecord(
                existing.id(),
                existing.sessionId(),
                existing.tokenHash(),
                existing.createdAt(),
                existing.expiresAt(),
                existing.consumedAt(),
                revokedAt
        );
        tokensByHash.put(tokenHash, updated);
        return true;
    }

    @Override
    public synchronized void revokeAllRefreshTokensForSession(UUID sessionId, Instant revokedAt) {
        if (sessionId == null) {
            return;
        }
        for (Map.Entry<String, RefreshTokenRecord> entry : tokensByHash.entrySet()) {
            RefreshTokenRecord token = entry.getValue();
            if (token.sessionId().equals(sessionId) && !token.isRevoked()) {
                tokensByHash.put(entry.getKey(), new RefreshTokenRecord(
                        token.id(),
                        token.sessionId(),
                        token.tokenHash(),
                        token.createdAt(),
                        token.expiresAt(),
                        token.consumedAt(),
                        revokedAt
                ));
            }
        }
    }

    @Override
    public synchronized RotationExecutionResult executeRotation(
            String oldTokenHash,
            UUID newTokenId,
            String newTokenHash,
            Instant newExpiresAt,
            ClientMetadata metadata,
            Instant now
    ) {
        RefreshTokenRecord token = tokensByHash.get(oldTokenHash);
        if (token == null) {
            return new RotationExecutionResult.TokenNotFound();
        }
        SessionRecord session = sessions.get(token.sessionId());
        if (session == null) {
            return new RotationExecutionResult.SessionNotFound(token.sessionId());
        }

        if (token.isConsumed()) {
            Instant effectiveGrace = token.transitionUntil() != null
                    ? token.transitionUntil()
                    : (token.consumedAt() != null && !transitionGraceWindow.isZero()
                        ? token.consumedAt().plus(transitionGraceWindow)
                        : null);

            if (effectiveGrace != null && now.isBefore(effectiveGrace) && session.isActive(now)) {
                return new RotationExecutionResult.GraceWindow(session);
            }

            // Replay attack detected! Revoke session and all its tokens.
            revokeSession(session.id(), now);
            revokeAllRefreshTokensForSession(session.id(), now);
            return new RotationExecutionResult.ReplayDetected(session.id(), session.subjectId());
        }

        if (session.isRevoked()) {
            return new RotationExecutionResult.SessionRevoked(session.id());
        }

        if (token.isRevoked()) {
            return new RotationExecutionResult.TokenRevoked(session.id());
        }

        if (session.isExpired(now)) {
            return new RotationExecutionResult.SessionExpired(session.id());
        }

        if (token.isExpired(now)) {
            return new RotationExecutionResult.TokenExpired(session.id());
        }

        Instant graceUntil = !transitionGraceWindow.isZero() ? now.plus(transitionGraceWindow) : null;

        // Consume old token
        RefreshTokenRecord consumed = new RefreshTokenRecord(
                token.id(),
                token.sessionId(),
                token.tokenHash(),
                token.createdAt(),
                token.expiresAt(),
                now,
                token.revokedAt(),
                graceUntil
        );
        tokensByHash.put(oldTokenHash, consumed);

        // Save fresh token
        RefreshTokenRecord newToken = new RefreshTokenRecord(
                newTokenId,
                token.sessionId(),
                newTokenHash,
                now,
                newExpiresAt,
                null,
                null,
                null
        );
        tokensByHash.put(newTokenHash, newToken);

        // Update session lastActiveAt and metadata
        String ua = metadata != null && metadata.userAgent() != null ? metadata.userAgent() : session.userAgent();
        String ip = metadata != null && metadata.ipAddress() != null ? metadata.ipAddress() : session.ipAddress();
        SessionRecord updatedSession = new SessionRecord(
                session.id(),
                session.subjectId(),
                session.createdAt(),
                session.expiresAt(),
                now,
                null,
                ua,
                ip,
                graceUntil
        );
        sessions.put(session.id(), updatedSession);

        return new RotationExecutionResult.Success(updatedSession, newToken);
    }
}
