package eu.exeris.caps.sessionmanagement.api;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Domain representation of an authenticated user session.
 *
 * @param id           unique session identifier
 * @param subjectId    identity subject identifier
 * @param createdAt    session creation timestamp
 * @param expiresAt    session expiration timestamp
 * @param lastActiveAt timestamp of most recent activity or token rotation
 * @param revokedAt    explicit revocation timestamp, or null if active
 * @param userAgent    user agent string recorded at session creation
 * @param ipAddress    IP address recorded at session creation
 * @since 0.1.0
 */
public record Session(
        UUID id,
        UUID subjectId,
        Instant createdAt,
        Instant expiresAt,
        Instant lastActiveAt,
        Instant revokedAt,
        String userAgent,
        String ipAddress
) {

    public Session {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(lastActiveAt, "lastActiveAt must not be null");
    }

    /**
     * Checks whether the session is currently active (not revoked and not expired).
     *
     * @param now reference instant
     * @return true if session is valid and active
     */
    public boolean isActive(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now);
    }

    /**
     * Checks whether the session has been explicitly revoked.
     */
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /**
     * Checks whether the session has expired relative to the given timestamp.
     */
    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }
}
