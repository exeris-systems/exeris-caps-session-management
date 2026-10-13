package eu.exeris.caps.sessionmanagement.api;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Outcome of presenting a refresh token to {@link RefreshTokenRotation#rotate}.
 *
 * <p>Exactly one presentation of a refresh token yields {@link Rotated}. Every later presentation of the
 * same token yields {@link ReuseDetected}, and by then the session and every refresh token issued for it
 * are revoked. There is no interval in which a consumed token is accepted again.
 *
 * @since 0.1.0
 */
public sealed interface RotationOutcome {

    /**
     * The token was live and is now consumed; the client must use the new refresh token from here on.
     *
     * @param subjectId    subject the session belongs to
     * @param sessionId    the session
     * @param refreshToken the successor refresh token
     * @param accessToken  a fresh access token, or {@code null} when no {@code AccessTokenIssuer} is wired
     *                     or the issuer failed after the rotation committed. A missing access token never
     *                     undoes the rotation: the client keeps {@code refreshToken} and refreshes again
     *                     with it to obtain an access token.
     */
    record Rotated(
            UUID subjectId,
            UUID sessionId,
            IssuedRefreshToken refreshToken,
            IssuedAccessToken accessToken
    ) implements RotationOutcome {

        public Rotated {
            Objects.requireNonNull(subjectId, "subjectId must not be null");
            Objects.requireNonNull(sessionId, "sessionId must not be null");
            Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        }

        public Optional<IssuedAccessToken> findAccessToken() {
            return Optional.ofNullable(accessToken);
        }
    }

    /**
     * The token had already been consumed. The session and its whole refresh-token family are revoked,
     * so whichever party holds the successor token is signed out as well.
     *
     * @param sessionId the revoked session
     */
    record ReuseDetected(UUID sessionId) implements RotationOutcome {

        public ReuseDetected {
            Objects.requireNonNull(sessionId, "sessionId must not be null");
        }
    }

    /**
     * The token was refused without being consumed.
     *
     * @param reason why it was refused
     */
    record Rejected(Reason reason) implements RotationOutcome {

        public Rejected {
            Objects.requireNonNull(reason, "reason must not be null");
        }
    }

    /**
     * Why a presented token was refused. None of these reveals whether a token exists to a client that
     * is not entitled to know; a boundary may collapse them into one response.
     */
    enum Reason {
        /** No refresh token with this value exists, or the value is blank. */
        UNKNOWN_TOKEN,
        /** The token was revoked without having been consumed. */
        TOKEN_REVOKED,
        /** The token is past its own expiry. */
        TOKEN_EXPIRED,
        /** The session was revoked. */
        SESSION_REVOKED,
        /** The session is past its absolute lifetime. */
        SESSION_EXPIRED,
        /** The session was not refreshed within the idle timeout. */
        SESSION_IDLE
    }
}
