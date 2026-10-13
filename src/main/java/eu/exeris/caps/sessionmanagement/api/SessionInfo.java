package eu.exeris.caps.sessionmanagement.api;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * View of one of the caller's own sessions, for an active-sessions listing.
 *
 * @param id            session identifier
 * @param createdAt     session creation timestamp
 * @param expiresAt     end of the absolute lifetime
 * @param idleExpiresAt instant the session becomes idle unless refreshed, never after {@code expiresAt}
 * @param lastActiveAt  timestamp of most recent activity
 * @param userAgent     recorded user agent string
 * @param ipAddress     recorded client IP address
 * @param isCurrent     whether this is the session the caller authenticated with
 * @since 0.1.0
 */
public record SessionInfo(
        UUID id,
        Instant createdAt,
        Instant expiresAt,
        Instant idleExpiresAt,
        Instant lastActiveAt,
        String userAgent,
        String ipAddress,
        boolean isCurrent
) {

    public SessionInfo {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(idleExpiresAt, "idleExpiresAt must not be null");
        Objects.requireNonNull(lastActiveAt, "lastActiveAt must not be null");
    }

    public static SessionInfo from(Session session, SessionPolicy policy, boolean isCurrent) {
        Objects.requireNonNull(session, "session must not be null");
        Objects.requireNonNull(policy, "policy must not be null");
        return new SessionInfo(
                session.id(),
                session.createdAt(),
                session.expiresAt(),
                session.idleExpiresAt(policy),
                session.lastActiveAt(),
                session.userAgent(),
                session.ipAddress(),
                isCurrent
        );
    }
}
