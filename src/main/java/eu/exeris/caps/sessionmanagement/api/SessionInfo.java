package eu.exeris.caps.sessionmanagement.api;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Public view DTO of a session for user-facing active session listings.
 *
 * @param id           session identifier
 * @param createdAt    session creation timestamp
 * @param expiresAt    session expiration timestamp
 * @param lastActiveAt timestamp of most recent activity
 * @param userAgent    recorded user agent string
 * @param ipAddress    recorded client IP address
 * @param isCurrent    whether this session matches the caller's current session
 * @since 0.1.0
 */
public record SessionInfo(
        UUID id,
        Instant createdAt,
        Instant expiresAt,
        Instant lastActiveAt,
        String userAgent,
        String ipAddress,
        boolean isCurrent
) {

    public SessionInfo {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(lastActiveAt, "lastActiveAt must not be null");
    }

    public static SessionInfo from(Session session, boolean isCurrent) {
        Objects.requireNonNull(session, "session must not be null");
        return new SessionInfo(
                session.id(),
                session.createdAt(),
                session.expiresAt(),
                session.lastActiveAt(),
                session.userAgent(),
                session.ipAddress(),
                isCurrent
        );
    }
}
