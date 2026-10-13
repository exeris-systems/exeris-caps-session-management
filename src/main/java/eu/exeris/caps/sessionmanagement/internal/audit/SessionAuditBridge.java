package eu.exeris.caps.sessionmanagement.internal.audit;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.internal.repository.RevocationReason;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Bridge for emitting security and compliance events to {@link AuditLogSink} when present.
 *
 * <p>Emits actions:
 * <ul>
 *   <li>{@code SESSION_CREATED}</li>
 *   <li>{@code SESSION_REVOKED}</li>
 *   <li>{@code SESSIONS_REVOKED_ALL}</li>
 *   <li>{@code TOKEN_ROTATED}</li>
 *   <li>{@code TOKEN_REPLAY_DETECTED}</li>
 * </ul>
 *
 * @since 0.1.0
 */
public final class SessionAuditBridge {

    private final AuditLogSink sink;

    public SessionAuditBridge(AuditLogSink sink) {
        this.sink = sink;
    }

    public void emitSessionCreated(UUID sessionId, UUID subjectId, ClientMetadata metadata, Instant expiresAt) {
        if (sink == null) return;
        Map<String, Object> details = new HashMap<>();
        if (sessionId != null) details.put("sessionId", sessionId.toString());
        if (expiresAt != null) details.put("expiresAt", expiresAt.toString());
        if (metadata != null) {
            if (metadata.userAgent() != null) details.put("userAgent", metadata.userAgent());
            if (metadata.ipAddress() != null) details.put("ipAddress", metadata.ipAddress());
        }
        emit("SESSION_CREATED", sessionId, subjectId, details);
    }

    public void emitSessionRevoked(UUID sessionId, UUID subjectId, RevocationReason reason) {
        if (sink == null) return;
        Map<String, Object> details = new HashMap<>();
        if (sessionId != null) details.put("sessionId", sessionId.toString());
        if (reason != null) details.put("reason", reason.name());
        emit("SESSION_REVOKED", sessionId, subjectId, details);
    }

    public void emitSessionsRevokedAll(UUID subjectId, int count, RevocationReason reason) {
        if (sink == null) return;
        Map<String, Object> details = new HashMap<>();
        details.put("revokedCount", count);
        if (reason != null) details.put("reason", reason.name());
        emit("SESSIONS_REVOKED_ALL", null, subjectId, details);
    }

    public void emitTokenRotated(UUID sessionId, UUID subjectId, ClientMetadata metadata) {
        if (sink == null) return;
        Map<String, Object> details = new HashMap<>();
        if (sessionId != null) details.put("sessionId", sessionId.toString());
        if (metadata != null) {
            if (metadata.userAgent() != null) details.put("userAgent", metadata.userAgent());
            if (metadata.ipAddress() != null) details.put("ipAddress", metadata.ipAddress());
        }
        emit("TOKEN_ROTATED", sessionId, subjectId, details);
    }

    public void emitTokenReplayDetected(UUID sessionId, UUID subjectId, String tokenHash) {
        if (sink == null) return;
        Map<String, Object> details = new HashMap<>();
        if (sessionId != null) details.put("sessionId", sessionId.toString());
        details.put("tokenHashPrefix", tokenHash != null && tokenHash.length() >= 8
                ? tokenHash.substring(0, 8) + "..."
                : "unknown");
        emit("TOKEN_REPLAY_DETECTED", sessionId, subjectId, details);
    }

    private void emit(String action, UUID sessionId, UUID subjectId, Map<String, Object> details) {
        String resId = sessionId != null ? sessionId.toString() : (subjectId != null ? subjectId.toString() : "");
        String actorId = subjectId != null ? subjectId.toString() : "system";
        sink.emit(AuditEvent.builder()
                .action(action)
                .resourceType("session")
                .resourceId(resId)
                .actorId(actorId)
                .timestamp(Instant.now())
                .details(details)
                .build());
    }
}
