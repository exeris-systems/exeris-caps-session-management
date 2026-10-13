package eu.exeris.caps.sessionmanagement.internal.repository;

import eu.exeris.caps.sessionmanagement.api.RotationOutcome;

import java.util.Objects;
import java.util.UUID;

/**
 * What one rotation transaction did.
 *
 * @since 0.1.0
 */
public sealed interface RotationExecutionResult {

    /** The presented token was consumed and its successor stored; {@code session} is the updated row. */
    record Rotated(SessionRecord session) implements RotationExecutionResult {
        public Rotated {
            Objects.requireNonNull(session, "session must not be null");
        }
    }

    /** The presented token was already consumed; the session and its tokens are now revoked. */
    record ReuseDetected(UUID sessionId, UUID subjectId) implements RotationExecutionResult {
        public ReuseDetected {
            Objects.requireNonNull(sessionId, "sessionId must not be null");
            Objects.requireNonNull(subjectId, "subjectId must not be null");
        }
    }

    /** The presented token was refused and nothing was written. */
    record Rejected(RotationOutcome.Reason reason) implements RotationExecutionResult {
        public Rejected {
            Objects.requireNonNull(reason, "reason must not be null");
        }
    }
}
