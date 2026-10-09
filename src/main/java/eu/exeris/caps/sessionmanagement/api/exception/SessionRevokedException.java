package eu.exeris.caps.sessionmanagement.api.exception;

import java.util.UUID;

/**
 * Thrown when an operation is attempted on an explicitly revoked session.
 *
 * @since 0.1.0
 */
public class SessionRevokedException extends SessionException {

    private final UUID sessionId;

    public SessionRevokedException(String message, UUID sessionId) {
        super(message);
        this.sessionId = sessionId;
    }

    public SessionRevokedException(UUID sessionId) {
        this("Session has been revoked: " + sessionId, sessionId);
    }

    public SessionRevokedException(String message) {
        this(message, null);
    }

    public UUID sessionId() {
        return sessionId;
    }
}
