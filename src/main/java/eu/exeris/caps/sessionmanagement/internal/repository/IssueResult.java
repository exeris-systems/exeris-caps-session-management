package eu.exeris.caps.sessionmanagement.internal.repository;

import java.time.Instant;
import java.util.Objects;

/**
 * What issuing the first refresh token of a session did.
 *
 * @param status    the outcome
 * @param expiresAt expiry stored for the token when {@code status} is {@link Status#ISSUED}, else {@code null}
 * @since 0.1.0
 */
public record IssueResult(Status status, Instant expiresAt) {

    public IssueResult {
        Objects.requireNonNull(status, "status must not be null");
        if ((status == Status.ISSUED) != (expiresAt != null)) {
            throw new IllegalArgumentException("expiresAt is present exactly when the token was issued");
        }
    }

    public static IssueResult issued(Instant expiresAt) {
        return new IssueResult(Status.ISSUED, Objects.requireNonNull(expiresAt, "expiresAt must not be null"));
    }

    public static IssueResult refused(Status status) {
        return new IssueResult(status, null);
    }

    /** Outcome of the issue attempt. */
    public enum Status {
        /** The token was stored. */
        ISSUED,
        /** No session with that identifier belongs to that subject. */
        SESSION_NOT_FOUND,
        /** The session is revoked. */
        SESSION_REVOKED,
        /** The session is past its absolute lifetime or idle. */
        SESSION_EXPIRED,
        /** The session already has a refresh token; successors come from rotation only. */
        ALREADY_ISSUED
    }
}
