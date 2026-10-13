package eu.exeris.caps.sessionmanagement.api;

import java.util.UUID;

/**
 * Opaque, single-use refresh tokens bound to a session (ADR-099 obligation 9).
 *
 * <p>Tokens are persisted as SHA-256 hashes only; the raw value is returned once. Each rotation consumes
 * the presented token and issues its successor in the same transaction, and consumption is a single
 * conditional write, so of any number of concurrent presentations of one token exactly one succeeds.
 * A second presentation of a consumed token, however soon after the first, revokes the session and
 * every token issued for it.
 *
 * @since 0.1.0
 */
public interface RefreshTokenRotation {

    /**
     * Issues the first refresh token of a session that was just created.
     *
     * @param sessionId session returned by {@link SessionStore#createSession}
     * @param subjectId subject the session was created for
     * @return the refresh token, with its raw value
     * @throws eu.exeris.caps.sessionmanagement.api.exception.SessionNotFoundException if the session does not
     *         exist or belongs to another subject
     * @throws eu.exeris.caps.sessionmanagement.api.exception.SessionRevokedException if the session is revoked
     * @throws eu.exeris.caps.sessionmanagement.api.exception.SessionExpiredException if the session is past its
     *         absolute lifetime or idle
     * @throws eu.exeris.caps.sessionmanagement.api.exception.SessionException if a refresh token was already
     *         issued for the session; later tokens come from {@link #rotate} only
     */
    IssuedRefreshToken issue(UUID sessionId, UUID subjectId);

    /**
     * Consumes a refresh token and issues its successor.
     *
     * @param rawRefreshToken raw refresh token presented by the client
     * @param metadata        client environment attributes recorded on the session
     * @return the outcome; never {@code null}
     */
    RotationOutcome rotate(String rawRefreshToken, ClientMetadata metadata);

    /**
     * Revokes the session a presented refresh token belongs to, with every token issued for it. Holding
     * a token of the family is the authority to end it.
     *
     * @param rawRefreshToken raw refresh token
     * @return {@code true} if a session was revoked, {@code false} if the token is unknown or its session
     *         was already revoked
     */
    boolean revoke(String rawRefreshToken);
}
