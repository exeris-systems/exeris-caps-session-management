package eu.exeris.caps.sessionmanagement.internal.repository;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence contract for sessions and refresh tokens.
 *
 * @since 0.1.0
 */
public interface SessionRepository {

    /**
     * Inserts a new session record.
     */
    void saveSession(SessionRecord session);

    /**
     * Finds a session by its unique identifier.
     */
    Optional<SessionRecord> findSession(UUID sessionId);

    /**
     * Finds all active (non-revoked, non-expired) sessions for a subject, ordered by creation time ascending.
     */
    List<SessionRecord> findActiveSessions(UUID subjectId, Instant now);

    /**
     * Explicitly revokes a session by session ID.
     */
    boolean revokeSession(UUID sessionId, Instant revokedAt);

    /**
     * Explicitly revokes a session by session ID and subject ID.
     */
    boolean revokeSession(UUID subjectId, UUID sessionId, Instant revokedAt);

    /**
     * Revokes all active sessions for a subject, returning the count of revoked sessions.
     */
    int revokeAllSessionsForSubject(UUID subjectId, Instant revokedAt);

    /**
     * Updates session last active timestamp and optionally client metadata.
     */
    void updateSessionActivity(UUID sessionId, Instant lastActiveAt, String userAgent, String ipAddress);

    /**
     * Saves a refresh token record.
     */
    void saveRefreshToken(RefreshTokenRecord token);

    /**
     * Finds a refresh token record by its SHA-256 hash.
     */
    Optional<RefreshTokenRecord> findRefreshTokenByHash(String tokenHash);

    /**
     * Explicitly revokes a refresh token by its hash.
     */
    boolean revokeRefreshToken(String tokenHash, Instant revokedAt);

    /**
     * Revokes all active refresh tokens for a session.
     */
    void revokeAllRefreshTokensForSession(UUID sessionId, Instant revokedAt);

    /**
     * Atomically executes refresh token rotation with single-use verification and replay detection.
     *
     * <p>In relational implementations, this executes inside a transaction with {@code SELECT FOR UPDATE}
     * row locking to ensure strict serializability and immediate replay detection.
     *
     * @param oldTokenHash  hash of the token presented for rotation
     * @param newTokenId    ID for the newly generated token
     * @param newTokenHash  hash of the newly generated token
     * @param newExpiresAt  expiry instant for the new token
     * @param metadata      updated client metadata
     * @param now           current transaction instant
     * @return outcome of the rotation attempt
     */
    RotationExecutionResult executeRotation(
            String oldTokenHash,
            UUID newTokenId,
            String newTokenHash,
            Instant newExpiresAt,
            ClientMetadata metadata,
            Instant now
    );
}
