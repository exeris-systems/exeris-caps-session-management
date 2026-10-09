package eu.exeris.caps.sessionmanagement.spi;

import eu.exeris.caps.sessionmanagement.api.IssuedAccessToken;

import java.util.UUID;

/**
 * Capability SPI contract for issuing short-lived access JWT tokens upon refresh token rotation.
 *
 * <p>Implemented by {@code exeris-caps-token-issuer} when composed into the Identity SKU.
 *
 * @since 0.1.0
 */
public interface AccessTokenIssuer {

    /**
     * Generates a signed access token for the given subject and session.
     *
     * @param subjectId identity subject identifier
     * @param sessionId session identifier
     * @return newly issued access token
     */
    IssuedAccessToken issueAccessToken(UUID subjectId, UUID sessionId);
}
