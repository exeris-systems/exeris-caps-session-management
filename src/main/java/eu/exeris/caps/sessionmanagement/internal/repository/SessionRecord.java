package eu.exeris.caps.sessionmanagement.internal.repository;

import java.time.Instant;
import java.util.UUID;

/**
 * Internal entity record representing a row in the {@code sessions} table.
 *
 * @since 0.1.0
 */
public record SessionRecord(
        UUID id,
        UUID subjectId,
        Instant createdAt,
        Instant expiresAt,
        Instant lastActiveAt,
        Instant revokedAt,
        String userAgent,
        String ipAddress,
        Instant transitionUntil
) {

    public SessionRecord(
            UUID id,
            UUID subjectId,
            Instant createdAt,
            Instant expiresAt,
            Instant lastActiveAt,
            Instant revokedAt,
            String userAgent,
            String ipAddress
    ) {
        this(id, subjectId, createdAt, expiresAt, lastActiveAt, revokedAt, userAgent, ipAddress, null);
    }

    public boolean isActive(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now);
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }
}
