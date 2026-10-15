package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.audittrail.api.AuditQuery;
import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@DisplayName("A failing audit sink never breaks the operation it records")
class SessionAuditBridgeTest {

    private static final AuditLogSink THROWING = new AuditLogSink() {
        @Override public void emit(AuditEvent event) { throw new IllegalStateException("sink down"); }
        @Override public List<AuditEvent> query(AuditQuery query) { return List.of(); }
        @Override public long count(AuditQuery query) { return 0; }
    };

    @Test
    @DisplayName("every emit method swallows a sink failure")
    void bridgeSwallowsSinkFailure() {
        SessionAuditBridge bridge = new SessionAuditBridge(THROWING);
        UUID id = UUID.randomUUID();

        assertThatCode(() -> {
            bridge.emitSessionCreated(id, id, ClientMetadata.empty(), Instant.now());
            bridge.emitSessionRevoked(id, id, null);
            bridge.emitSessionsRevokedAll(id, 1, null);
            bridge.emitTokenRotated(id, id, ClientMetadata.empty());
            bridge.emitTokenReplayDetected(id, id, "0123456789abcdef");
        }).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a rotation still hands the caller its successor when the sink throws")
    void rotationSurvivesSinkFailure() {
        SessionManagementModule module = new SessionManagementModule(
                new InMemorySessionRepository(), SessionPolicy.defaults(), new InMemoryAccessTokenIssuer(),
                new SessionAuditBridge(THROWING), new MutableClock(Instant.parse("2026-10-13T08:00:00Z")));
        UUID subject = UUID.randomUUID();
        Session session = module.sessionStore().createSession(subject, ClientMetadata.empty());
        IssuedRefreshToken token = module.refreshTokenRotation().issue(session.id(), subject);

        RotationOutcome outcome = module.refreshTokenRotation().rotate(token.rawToken(), ClientMetadata.empty());

        assertThat(outcome).isInstanceOf(RotationOutcome.Rotated.class);
    }
}
