package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SessionManagementModule lifecycle and wiring")
class SessionManagementModuleTest {

    @Test
    @DisplayName("without persistence the module exposes no services and refuses to initialize")
    void unwiredModuleFailsClosed() {
        SessionManagementModule module = new SessionManagementModule();

        assertThat(module.isWired()).isFalse();
        assertThatThrownBy(module::sessionStore).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::refreshTokenRotation).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::initialize).isInstanceOf(IllegalStateException.class);
        assertThat(module.isInitialized()).isFalse();
    }

    @Test
    @DisplayName("a TransactionalExecutor is required by the public constructors")
    void transactionalExecutorIsRequired() {
        assertThatThrownBy(() -> new SessionManagementModule(null, SessionPolicy.defaults(), null, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("lifecycle transitions through initialize, ready, drain and terminate")
    void lifecycleTransitions() throws Exception {
        SessionManagementModule module = wired();

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
    @DisplayName("rotation issues an access token when an AccessTokenIssuer is wired")
    void rotationIssuesAccessToken() {
        SessionManagementModule module = wired();
        UUID subject = UUID.randomUUID();
        Session session = module.sessionStore().createSession(subject, ClientMetadata.empty());
        IssuedRefreshToken issued = module.refreshTokenRotation().issue(session.id(), subject);

        RotationOutcome outcome = module.refreshTokenRotation().rotate(issued.rawToken(), ClientMetadata.empty());

        assertThat(outcome).isInstanceOfSatisfying(RotationOutcome.Rotated.class,
                r -> assertThat(r.findAccessToken()).isPresent());
    }

    @Test
    @DisplayName("default policy has an idle timeout shorter than the absolute lifetime")
    void defaultPolicy() {
        SessionPolicy policy = SessionPolicy.defaults();
        assertThat(policy.idleTimeout()).isEqualTo(Duration.ofHours(12));
        assertThat(policy.absoluteLifetime()).isEqualTo(Duration.ofDays(7));
        assertThatThrownBy(() -> new SessionPolicy(Duration.ofHours(1), Duration.ofHours(2), 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SessionPolicy(Duration.ofHours(1), Duration.ZERO, 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static SessionManagementModule wired() {
        return new SessionManagementModule(
                new InMemorySessionRepository(), SessionPolicy.defaults(), new InMemoryAccessTokenIssuer(), null,
                Clock.systemUTC());
    }
}
