package eu.exeris.caps.sessionmanagement.api.exception;

import java.util.UUID;

/**
 * Thrown when a specified session does not exist.
 *
 * @since 0.1.0
 */
public class SessionNotFoundException extends SessionException {

    private final UUID sessionId;

    public SessionNotFoundException(UUID sessionId) {
        super("Session not found: " + sessionId);
        this.sessionId = sessionId;
    }

    public SessionNotFoundException(String message) {
        super(message);
        this.sessionId = null;
    }

    public UUID sessionId() {
        return sessionId;
    }
}
