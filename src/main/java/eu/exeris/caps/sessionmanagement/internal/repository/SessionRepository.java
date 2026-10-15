package eu.exeris.caps.sessionmanagement.internal.repository;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence contract for sessions and their refresh-token families.
 *
 * <p>Every method is one transaction. Implementations take the session row before any of its refresh
 * tokens, in every method, so that rotation and revocation of one family serialise instead of
 * deadlocking. "Active" means not revoked, {@code expires_at > now} and
 * {@code last_active_at > now - idleTimeout}.
 *
 * @since 0.1.0
 */
public interface SessionRepository {

    /**
     * Inserts a session, first revoking the subject's oldest active sessions so that at most
     * {@code maxActive} are active afterwards.
     *
     * @return identifiers of the sessions revoked to make room
     */
    List<UUID> createSession(SessionRecord session, int maxActive, Duration idleTimeout);

    /**
     * The subject's active sessions, oldest first.
     */
    List<SessionRecord> findActiveSessions(UUID subjectId, Instant now, Duration idleTimeout);

    /**
     * Revokes one session of a subject and its refresh tokens.
     *
     * @return {@code false} if no unrevoked session with that identifier belongs to that subject
     */
    boolean revokeSession(UUID subjectId, UUID sessionId, Instant now, RevocationReason reason);

    /**
     * Revokes every unrevoked session of a subject and their refresh tokens.
     *
     * @return number of sessions revoked
     */
    int revokeAllSessions(UUID subjectId, Instant now, RevocationReason reason);

    /**
     * Stores the first refresh token of an active session of {@code subjectId}. The token's expiry is
     * set to {@code min(now + idleTimeout, session.expires_at)}; {@code token.expiresAt()} is ignored.
     */
    IssueResult issueFirstToken(UUID subjectId, RefreshTokenRecord token, Instant now, Duration idleTimeout);

    /**
     * Rotates the refresh token whose hash is {@code presentedHash}.
     *
     * <p>Consumption is one conditional {@code UPDATE ... WHERE consumed_at IS NULL}, under a lock on
     * the session row, so at most one transaction consumes a given token. A presented token that is
     * already consumed revokes the session and all its tokens, and that revocation is committed. The
     * session's revoked, absolute and idle state is checked before consumption, so a token of a session
     * that has already ended is refused and consumes nothing.
     *
     * @param newTokenId   identifier of the successor token
     * @param newTokenHash hash of the successor token
     */
    RotationExecutionResult rotate(
            String presentedHash,
            UUID newTokenId,
            String newTokenHash,
            ClientMetadata metadata,
            Instant now,
            Duration idleTimeout
    );

    /**
     * Revokes the session that the token with this hash belongs to, and all its tokens.
     *
     * @return the revoked family, or empty if the token is unknown or its session was already revoked
     */
    Optional<FamilyRevocation> revokeFamilyByTokenHash(String tokenHash, Instant now, RevocationReason reason);
}
