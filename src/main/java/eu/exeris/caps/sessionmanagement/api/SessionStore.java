package eu.exeris.caps.sessionmanagement.api;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Layer 5 Domain Primitive contract for managing authenticated sessions.
 *
 * <p>Specified in ADR-099 for the Identity SKU ({@code exeris-sku-identity}).
 *
 * @since 0.1.0
 */
public interface SessionStore {

    /**
     * Creates and persists a new authenticated session for the specified subject.
     *
     * <p>If the subject has reached {@link SessionPolicy#maxActiveSessionsPerSubject()},
     * the oldest active session is automatically evicted and revoked.
     *
     * @param subjectId identity subject identifier
     * @param metadata  client environment attributes (user-agent, IP)
     * @return newly established session
     */
    Session createSession(UUID subjectId, ClientMetadata metadata);

    /**
     * Lists all non-expired, non-revoked sessions for the given subject.
     *
     * @param subjectId identity subject identifier
     * @return list of active session info views
     */
    List<SessionInfo> listActiveSessions(UUID subjectId);

    /**
     * Lists active sessions for the subject, marking the current session.
     *
     * @param subjectId        identity subject identifier
     * @param currentSessionId current caller session identifier
     * @return list of active session info views
     */
    default List<SessionInfo> listActiveSessions(UUID subjectId, UUID currentSessionId) {
        return listActiveSessions(subjectId).stream()
                .map(s -> new SessionInfo(
                        s.id(),
                        s.createdAt(),
                        s.expiresAt(),
                        s.lastActiveAt(),
                        s.userAgent(),
                        s.ipAddress(),
                        s.id().equals(currentSessionId)
                ))
                .toList();
    }

    /**
     * Finds session view info by session identifier.
     *
     * @param sessionId session identifier
     * @return session info if found
     */
    Optional<SessionInfo> findSession(UUID sessionId);

    /**
     * Revokes a specific session belonging to the subject.
     *
     * @param subjectId identity subject identifier
     * @param sessionId session identifier
     * @return true if session was revoked, false if not found or already revoked
     */
    boolean revokeSession(UUID subjectId, UUID sessionId);

    /**
     * Revokes a specific session by its identifier.
     *
     * @param sessionId session identifier
     * @return true if session was revoked, false if not found or already revoked
     */
    default boolean revokeSession(UUID sessionId) {
        return revokeSession(null, sessionId);
    }

    /**
     * Revokes all active sessions for the specified subject.
     *
     * <p>Typically invoked on password change or password reset (ADR-099 Obligation 9).
     *
     * @param subjectId identity subject identifier
     * @return count of revoked sessions
     */
    int revokeAllForSubject(UUID subjectId);
}
