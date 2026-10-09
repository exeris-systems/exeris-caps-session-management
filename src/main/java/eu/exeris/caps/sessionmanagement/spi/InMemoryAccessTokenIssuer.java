package eu.exeris.caps.sessionmanagement.spi;

import eu.exeris.caps.sessionmanagement.api.IssuedAccessToken;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * In-memory test double implementation of {@link AccessTokenIssuer}.
 *
 * @since 0.1.0
 */
public final class InMemoryAccessTokenIssuer implements AccessTokenIssuer {

    private final Duration validity;

    public InMemoryAccessTokenIssuer() {
        this(Duration.ofMinutes(15));
    }

    public InMemoryAccessTokenIssuer(Duration validity) {
        this.validity = Objects.requireNonNull(validity, "validity must not be null");
    }

    @Override
    public IssuedAccessToken issueAccessToken(UUID subjectId, UUID sessionId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        String dummyJwt = "eyTestHeader.eyPayload." + subjectId + "." + sessionId + "." + UUID.randomUUID();
        return new IssuedAccessToken(dummyJwt, Instant.now().plus(validity), "Bearer");
    }
}
