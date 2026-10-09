package eu.exeris.caps.sessionmanagement.api;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Newly issued single-use refresh token holding the raw plaintext token to be returned to the client.
 *
 * <p>The plaintext token is never stored; only its SHA-256 hash is persisted.
 *
 * @param rawToken  unhashed opaque token string (32 hex characters)
 * @param expiresAt token expiration timestamp
 * @param sessionId session identifier bound to this refresh token
 * @since 0.1.0
 */
public record IssuedRefreshToken(
        String rawToken,
        Instant expiresAt,
        UUID sessionId
) {

    public IssuedRefreshToken {
        Objects.requireNonNull(rawToken, "rawToken must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
    }
}
