package eu.exeris.caps.sessionmanagement.internal.repository;

import java.util.Objects;
import java.util.UUID;

/**
 * A session revoked together with every refresh token issued for it.
 *
 * @since 0.1.0
 */
public record FamilyRevocation(UUID sessionId, UUID subjectId) {
    public FamilyRevocation {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
    }
}
