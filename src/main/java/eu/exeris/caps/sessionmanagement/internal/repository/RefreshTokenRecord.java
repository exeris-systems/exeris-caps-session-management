package eu.exeris.caps.sessionmanagement.internal.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * A row of the {@code refresh_tokens} table. Only the SHA-256 hash of the raw token is held.
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
        Instant revokedAt
) {

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }
}
