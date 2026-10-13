package eu.exeris.caps.sessionmanagement.api;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One sign-in of a subject. The session is the refresh-token family: every refresh token issued for
 * it descends from the first by rotation, and revoking the session revokes all of them.
 *
 * @param id           unique session identifier
 * @param subjectId    identity subject identifier
 * @param createdAt    session creation timestamp
 * @param expiresAt    end of the absolute lifetime
 * @param lastActiveAt timestamp of the most recent refresh-token rotation, or of creation
 * @param revokedAt    revocation timestamp, or {@code null} while not revoked
 * @param userAgent    user agent recorded at creation or at the last rotation
 * @param ipAddress    IP address recorded at creation or at the last rotation
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
     * Whether the session is neither revoked, past its absolute lifetime, nor idle at {@code now}.
     */
    public boolean isActive(Instant now, SessionPolicy policy) {
        return revokedAt == null && expiresAt.isAfter(now) && lastActiveAt.isAfter(policy.idleCutoff(now));
    }

    /**
     * Whether the session has been revoked.
     */
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /**
     * The instant the session becomes idle unless its refresh token is rotated first, capped at the
     * absolute expiry.
     */
    public Instant idleExpiresAt(SessionPolicy policy) {
        Instant idle = lastActiveAt.plus(policy.idleTimeout());
        return idle.isBefore(expiresAt) ? idle : expiresAt;
    }
}
