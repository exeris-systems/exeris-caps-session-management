package eu.exeris.caps.sessionmanagement.api;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Lifetime and concurrency limits applied to every session.
 *
 * <p>A session ends at whichever comes first: {@code createdAt + absoluteLifetime}, or
 * {@code lastActiveAt + idleTimeout}. Activity is a successful refresh-token rotation, so an idle
 * session is one whose refresh token has not been presented within the idle timeout. Neither limit
 * can be extended by rotating: the absolute lifetime is fixed when the session is created, and every
 * refresh token issued for a session expires no later than the session itself.
 *
 * @param absoluteLifetime            maximum age of a session, regardless of activity
 * @param idleTimeout                 maximum time between two rotations of the session's refresh token
 * @param maxActiveSessionsPerSubject active sessions a subject may hold; creating one more revokes the oldest
 * @since 0.1.0
 */
public record SessionPolicy(
        Duration absoluteLifetime,
        Duration idleTimeout,
        int maxActiveSessionsPerSubject
) {

    /** Default absolute lifetime: 7 days. */
    public static final Duration DEFAULT_ABSOLUTE_LIFETIME = Duration.ofDays(7);

    /** Default idle timeout: 12 hours. */
    public static final Duration DEFAULT_IDLE_TIMEOUT = Duration.ofHours(12);

    /** Default limit of active sessions per subject. */
    public static final int DEFAULT_MAX_ACTIVE_SESSIONS = 10;

    public SessionPolicy {
        Objects.requireNonNull(absoluteLifetime, "absoluteLifetime must not be null");
        Objects.requireNonNull(idleTimeout, "idleTimeout must not be null");
        if (absoluteLifetime.isNegative() || absoluteLifetime.isZero()) {
            throw new IllegalArgumentException("absoluteLifetime must be positive");
        }
        if (idleTimeout.isNegative() || idleTimeout.isZero()) {
            throw new IllegalArgumentException("idleTimeout must be positive");
        }
        if (idleTimeout.compareTo(absoluteLifetime) > 0) {
            throw new IllegalArgumentException("idleTimeout must not exceed absoluteLifetime");
        }
        if (maxActiveSessionsPerSubject <= 0) {
            throw new IllegalArgumentException("maxActiveSessionsPerSubject must be positive");
        }
    }

    /**
     * Default policy: 7-day absolute lifetime, 12-hour idle timeout, 10 active sessions per subject.
     */
    public static SessionPolicy defaults() {
        return new SessionPolicy(DEFAULT_ABSOLUTE_LIFETIME, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_ACTIVE_SESSIONS);
    }

    /**
     * The earliest {@code lastActiveAt} a session may have and still be active at {@code now}.
     *
     * @param now reference instant
     * @return idle cut-off; a session last active at or before it is idle
     */
    public Instant idleCutoff(Instant now) {
        return now.minus(idleTimeout);
    }
}
