package eu.exeris.caps.sessionmanagement.internal.repository;

import eu.exeris.caps.sessionmanagement.api.Session;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * A row of the {@code sessions} table.
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
        String ipAddress
) {

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public boolean isIdle(Instant idleCutoff) {
        return !lastActiveAt.isAfter(idleCutoff);
    }

    /** Expiry of a refresh token issued at {@code now}: never past the idle window or the absolute lifetime. */
    public Instant tokenExpiry(Instant now, Duration idleTimeout) {
        Instant idle = now.plus(idleTimeout);
        return idle.isBefore(expiresAt) ? idle : expiresAt;
    }

    public Session toDomain() {
        return new Session(id, subjectId, createdAt, expiresAt, lastActiveAt, revokedAt, userAgent, ipAddress);
    }
}
