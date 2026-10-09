package eu.exeris.caps.sessionmanagement.api.exception;

import java.util.UUID;

/**
 * Thrown when an already-consumed refresh token is presented again (replay attack detection).
 *
 * <p>Per ADR-099 Obligation 9, replay detection triggers immediate revocation of the associated session
 * and all its active refresh tokens.
 *
 * @since 0.1.0
 */
public class RefreshTokenReplayedException extends SessionException {

    private final UUID sessionId;

    public RefreshTokenReplayedException(String message, UUID sessionId) {
        super(message);
        this.sessionId = sessionId;
    }

    public RefreshTokenReplayedException(String message) {
        this(message, null);
    }

    public UUID sessionId() {
        return sessionId;
    }
}
