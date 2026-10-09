package eu.exeris.caps.sessionmanagement.internal.repository;

import java.util.UUID;

/**
 * Result outcome of an atomic refresh token rotation transaction.
 *
 * @since 0.1.0
 */
public sealed interface RotationExecutionResult {

    record Success(SessionRecord session, RefreshTokenRecord newRefreshToken) implements RotationExecutionResult {}

    record ReplayDetected(UUID sessionId, UUID subjectId) implements RotationExecutionResult {}

    record TokenNotFound() implements RotationExecutionResult {}

    record TokenRevoked(UUID sessionId) implements RotationExecutionResult {}

    record TokenExpired(UUID sessionId) implements RotationExecutionResult {}

    record SessionNotFound(UUID sessionId) implements RotationExecutionResult {}

    record SessionRevoked(UUID sessionId) implements RotationExecutionResult {}

    record SessionExpired(UUID sessionId) implements RotationExecutionResult {}

    record GraceWindow(SessionRecord session) implements RotationExecutionResult {}
}
