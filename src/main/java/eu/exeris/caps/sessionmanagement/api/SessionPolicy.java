package eu.exeris.caps.sessionmanagement.api;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration policy defining session lifetimes and concurrency limits.
 *
 * @param sessionTtl                duration after which an inactive session expires
 * @param refreshTokenTtl           validity period of an issued single-use refresh token
 * @param maxActiveSessionsPerSubject maximum active sessions allowed per subject before evicting the oldest
 * @since 0.1.0
 */
public record SessionPolicy(
        Duration sessionTtl,
        Duration refreshTokenTtl,
        int maxActiveSessionsPerSubject
) {

    public SessionPolicy {
        Objects.requireNonNull(sessionTtl, "sessionTtl must not be null");
        Objects.requireNonNull(refreshTokenTtl, "refreshTokenTtl must not be null");
        if (maxActiveSessionsPerSubject <= 0) {
            throw new IllegalArgumentException("maxActiveSessionsPerSubject must be positive");
        }
    }

    /**
     * Default policy with 30-day session TTL, 30-day refresh token TTL, and 10 max active sessions per subject.
     */
    public static SessionPolicy defaults() {
        return new SessionPolicy(
                Duration.ofDays(30),
                Duration.ofDays(30),
                10
        );
    }
}
