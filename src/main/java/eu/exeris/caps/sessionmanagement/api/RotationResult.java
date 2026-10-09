package eu.exeris.caps.sessionmanagement.api;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Result of a successful refresh token rotation.
 *
 * @param subjectId    identity subject identifier
 * @param sessionId    session identifier bound to the rotated token
 * @param refreshToken fresh single-use refresh token
 * @param accessToken  optional newly issued access token (if an AccessTokenIssuer SPI was configured)
 * @since 0.1.0
 */
public record RotationResult(
        UUID subjectId,
        UUID sessionId,
        IssuedRefreshToken refreshToken,
        IssuedAccessToken accessToken
) {

    public RotationResult {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
    }

    public Optional<IssuedAccessToken> findAccessToken() {
        return Optional.ofNullable(accessToken);
    }

    public Optional<IssuedRefreshToken> findRefreshToken() {
        return Optional.ofNullable(refreshToken);
    }
}
