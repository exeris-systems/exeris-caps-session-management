package eu.exeris.caps.sessionmanagement.api;

import java.util.UUID;

/**
 * Layer 5 Domain Primitive contract for single-use opaque refresh token issuance and rotation.
 *
 * <p>Tokens are persisted as SHA-256 hashes only. On each rotation, the presented token is consumed
 * and replaced with a fresh token. If an already-consumed token is presented (replay attack), the session
 * is immediately revoked.
 *
 * @since 0.1.0
 */
public interface RefreshTokenRotation {

    /**
     * Issues an initial single-use refresh token for an active session.
     *
     * @param sessionId session identifier
     * @param subjectId identity subject identifier
     * @return newly issued refresh token containing unhashed token value
     */
    IssuedRefreshToken issue(UUID sessionId, UUID subjectId);

    /**
     * Rotates a single-use refresh token, issuing a new refresh token and an optional fresh access token.
     *
     * <p>Enforces atomic replay detection. If the token was already consumed, a
     * {@link eu.exeris.caps.sessionmanagement.api.exception.RefreshTokenReplayedException} is thrown and
     * the underlying session is revoked.
     *
     * @param rawRefreshToken plaintext opaque refresh token presented by client
     * @param metadata        client environment metadata
     * @return rotation result with new tokens
     */
    RotationResult rotate(String rawRefreshToken, ClientMetadata metadata);

    /**
     * Explicitly revokes a refresh token by its raw value.
     *
     * @param rawRefreshToken plaintext opaque refresh token
     */
    void revoke(String rawRefreshToken);
}
