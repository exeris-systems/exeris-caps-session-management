package eu.exeris.caps.sessionmanagement.api.exception;

/**
 * Thrown when a refresh token cannot be found, has an invalid format, or has already been revoked.
 *
 * @since 0.1.0
 */
public class InvalidRefreshTokenException extends SessionException {

    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}
