package eu.exeris.caps.sessionmanagement.internal.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * Internal entity record representing a row in the {@code refresh_tokens} table.
 *
 * @since 0.1.0
 */
public record RefreshTokenRecord(
        UUID id,
        UUID sessionId,
        String tokenHash,
        Instant createdAt,
        Instant expiresAt,
        Instant consumedAt,
        Instant revokedAt,
        Instant transitionUntil
) {

    public RefreshTokenRecord(
            UUID id,
            UUID sessionId,
            String tokenHash,
            Instant createdAt,
            Instant expiresAt,
            Instant consumedAt,
            Instant revokedAt
    ) {
        this(id, sessionId, tokenHash, createdAt, expiresAt, consumedAt, revokedAt, null);
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public boolean isValid(Instant now) {
        return !isConsumed() && !isRevoked() && !isExpired(now);
    }
}
