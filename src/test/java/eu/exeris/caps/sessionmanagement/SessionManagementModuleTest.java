package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.audittrail.api.AuditQuery;
import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.RotationResult;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.SessionStore;
import eu.exeris.caps.sessionmanagement.spi.InMemoryAccessTokenIssuer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SessionManagementModule Lifecycle and Wiring Tests")
class SessionManagementModuleTest {

    @Test
    @DisplayName("no-arg constructor instantiates valid defaults and provides services")
    void noArgConstructorInstantiatesDefaults() {
        SessionManagementModule module = new SessionManagementModule();

        assertThat(module.sessionStore()).isNotNull();
        assertThat(module.refreshTokenRotation()).isNotNull();
        assertThat(module.isInitialized()).isFalse();
        assertThat(module.isReady()).isFalse();
    }

    @Test
    @DisplayName("lifecycle transitions through initialize, ready, drain, and terminate")
    void lifecycleTransitions() throws Exception {
        SessionManagementModule module = new SessionManagementModule();

        module.initialize();
        assertThat(module.isInitialized()).isTrue();
        assertThat(module.isReady()).isFalse();

        module.ready();
        assertThat(module.isReady()).isTrue();

        module.drain(Duration.ofSeconds(10));
        assertThat(module.isReady()).isFalse();
        assertThat(module.isInitialized()).isTrue();

        module.terminate();
        assertThat(module.isReady()).isFalse();
        assertThat(module.isInitialized()).isFalse();
    }

    @Test
    @DisplayName("module wires with custom policy, token issuer, and audit sink")
    void moduleWiringWithCustomDependencies() {
        List<AuditEvent> emittedEvents = new ArrayList<>();
        AuditLogSink auditSink = new AuditLogSink() {
            @Override public void emit(AuditEvent event) { emittedEvents.add(event); }
            @Override public List<AuditEvent> query(AuditQuery query) { return emittedEvents; }
            @Override public long count(AuditQuery query) { return emittedEvents.size(); }
        };

        SessionPolicy customPolicy = new SessionPolicy(Duration.ofHours(2), Duration.ofDays(1), 3);
        InMemoryAccessTokenIssuer tokenIssuer = new InMemoryAccessTokenIssuer();

        SessionManagementModule module = new SessionManagementModule(
                (eu.exeris.kernel.spi.persistence.TransactionalExecutor) null,
                customPolicy,
                tokenIssuer,
                auditSink
        );

        SessionStore store = module.sessionStore();
        UUID subjectId = UUID.randomUUID();
        Session session = store.createSession(subjectId, ClientMetadata.of("Mozilla/5.0", "127.0.0.1"));
        assertThat(session).isNotNull();

        // Audit event emitted
        assertThat(emittedEvents).hasSize(1);
        assertThat(emittedEvents.get(0).action()).isEqualTo("SESSION_CREATED");

        // Refresh token rotation with access token issuance
        IssuedRefreshToken issued = module.refreshTokenRotation().issue(session.id(), subjectId);
        RotationResult rotated = module.refreshTokenRotation().rotate(issued.rawToken(), ClientMetadata.empty());

        assertThat(rotated.findAccessToken()).isPresent();
        assertThat(rotated.accessToken().token()).contains("eyTestHeader");
        assertThat(emittedEvents).hasSize(2);
        assertThat(emittedEvents.get(1).action()).isEqualTo("TOKEN_ROTATED");
    }

    @Test
    @DisplayName("module wires with convenience constructor using default policy")
    void moduleWiringWithConvenienceConstructor() {
        SessionManagementModule module = new SessionManagementModule(
                (eu.exeris.kernel.spi.persistence.TransactionalExecutor) null,
                new InMemoryAccessTokenIssuer(),
                null
        );

        assertThat(module.sessionStore()).isNotNull();
        assertThat(module.refreshTokenRotation()).isNotNull();
    }
}
