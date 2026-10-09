package eu.exeris.caps.sessionmanagement.api.exception;

/**
 * Base exception for session management and refresh token failures.
 *
 * @since 0.1.0
 */
public class SessionException extends RuntimeException {

    public SessionException(String message) {
        super(message);
    }

    public SessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
