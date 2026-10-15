package eu.exeris.caps.sessionmanagement.api;

import java.util.List;
import java.util.UUID;

/**
 * Sessions of a subject: one per sign-in (ADR-099).
 *
 * <p>Operations a signed-in user performs on their own sessions take a {@link SessionPrincipal}, which
 * only the kernel's verified principal can produce, and act on that principal's subject alone. The two
 * operations that take a bare subject identifier, {@link #createSession} and {@link #revokeAllForSubject},
 * serve flows that have verified the subject by other means (a password, a reset token) and must never be
 * fed an identifier taken from a request.
 *
 * <p>A session is active while it is not revoked, not past its absolute lifetime, and not idle under the
 * {@link SessionPolicy}. Listings return active sessions only.
 *
 * @since 0.1.0
 */
public interface SessionStore {

    /**
     * Creates a session for a subject whose credentials the caller has just verified.
     *
     * <p>If the subject already holds {@link SessionPolicy#maxActiveSessionsPerSubject()} active sessions,
     * the oldest are revoked so that the new one fits.
     *
     * @param subjectId subject whose sign-in succeeded
     * @param metadata  client environment attributes (user agent, IP)
     * @return the new session
     */
    Session createSession(UUID subjectId, ClientMetadata metadata);

    /**
     * Lists the caller's active sessions, marking the one the caller authenticated with.
     *
     * @param principal the authenticated caller
     * @return active sessions, oldest first
     */
    List<SessionInfo> listSessions(SessionPrincipal principal);

    /**
     * Revokes one of the caller's sessions and every refresh token issued for it.
     *
     * @param principal the authenticated caller
     * @param sessionId session to revoke
     * @return {@code true} if it was revoked; {@code false} if it does not exist, belongs to another
     *         subject, or was already revoked — the three are indistinguishable to the caller
     */
    boolean revokeSession(SessionPrincipal principal, UUID sessionId);

    /**
     * Revokes every session of the caller, the current one included.
     *
     * @param principal the authenticated caller
     * @return number of sessions revoked
     */
    int revokeAllSessions(SessionPrincipal principal);

    /**
     * Revokes the session the caller authenticated with and every refresh token issued for it.
     *
     * @param principal the authenticated caller
     * @return {@code true} if it was revoked, {@code false} if it was already revoked
     * @throws IllegalStateException if the principal carries no session identifier
     *         (see {@link SessionBoundPrincipal})
     */
    boolean logout(SessionPrincipal principal);

    /**
     * Revokes every session of a subject after a completed password change or reset (ADR-099
     * obligation 9).
     *
     * @param subjectId subject whose credential changed, as verified by the credential flow
     * @return number of sessions revoked
     */
    int revokeAllForSubject(UUID subjectId);
}
