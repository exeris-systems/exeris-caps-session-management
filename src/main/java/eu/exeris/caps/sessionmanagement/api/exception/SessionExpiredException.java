package eu.exeris.caps.sessionmanagement.api.exception;

import java.util.UUID;

/**
 * Thrown when an operation is attempted on an expired session or with an expired refresh token.
 *
 * @since 0.1.0
 */
public class SessionExpiredException extends SessionException {

    private final UUID sessionId;

    public SessionExpiredException(String message, UUID sessionId) {
        super(message);
        this.sessionId = sessionId;
    }

    public SessionExpiredException(UUID sessionId) {
        this("Session has expired: " + sessionId, sessionId);
    }

    public SessionExpiredException(String message) {
        this(message, null);
    }

    public UUID sessionId() {
        return sessionId;
    }
}
