package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.sessionmanagement.api.RefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.SessionStore;
import eu.exeris.caps.sessionmanagement.internal.DefaultRefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.internal.DefaultSessionStore;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.repository.InMemorySessionRepository;
import eu.exeris.caps.sessionmanagement.internal.repository.PostgresSessionRepository;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;
import eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-session-management}.
 *
 * <p>Provides Layer 5 Domain Primitives:
 * <ul>
 *   <li>{@link SessionStore} (one session per sign-in: list active sessions, revoke one, revoke all for subject, create session)</li>
 *   <li>{@link RefreshTokenRotation} (opaque single-use refresh tokens stored hashed, rotated on every use, atomic replay detection)</li>
 * </ul>
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = SessionStore.class, version = "1.0.0")
@Provides(service = RefreshTokenRotation.class, version = "1.0.0")
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[1.0.0,2.0.0)", optional = true)
@Requires(service = AccessTokenIssuer.class, versionRange = "[1.0.0,2.0.0)", optional = true)
public final class SessionManagementModule implements CapabilityLifecycleHooks {

    private final SessionStore sessionStore;
    private final RefreshTokenRotation refreshTokenRotation;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Public no-arg constructor for reflective instantiation by the composition conductor.
     */
    public SessionManagementModule() {
        this(
                new InMemorySessionRepository(),
                SessionPolicy.defaults(),
                null,
                null
        );
    }

    /**
     * Constructor wiring with a PostgreSQL {@link TransactionalExecutor}.
     */
    public SessionManagementModule(
            TransactionalExecutor tx,
            SessionPolicy policy,
            AccessTokenIssuer accessTokenIssuer,
            AuditLogSink auditLogSink
    ) {
        this(
                tx != null ? new PostgresSessionRepository(tx) : new InMemorySessionRepository(),
                policy != null ? policy : SessionPolicy.defaults(),
                accessTokenIssuer,
                auditLogSink != null ? new SessionAuditBridge(auditLogSink) : null
        );
    }

    /**
     * Constructor wiring with required and optional capability services using default policy.
     */
    public SessionManagementModule(
            TransactionalExecutor tx,
            AccessTokenIssuer accessTokenIssuer,
            AuditLogSink auditLogSink
    ) {
        this(tx, SessionPolicy.defaults(), accessTokenIssuer, auditLogSink);
    }

    /**
     * Constructor wiring with custom repository and dependencies.
     */
    public SessionManagementModule(
            SessionRepository repository,
            SessionPolicy policy,
            AccessTokenIssuer accessTokenIssuer,
            SessionAuditBridge auditBridge
    ) {
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(policy, "policy must not be null");

        this.sessionStore = new DefaultSessionStore(repository, policy, auditBridge);
        this.refreshTokenRotation = new DefaultRefreshTokenRotation(repository, policy, accessTokenIssuer, auditBridge);
    }

    public SessionStore sessionStore() {
        return sessionStore;
    }

    public RefreshTokenRotation refreshTokenRotation() {
        return refreshTokenRotation;
    }

    @Override
    public void initialize() throws Exception {
        initialized.set(true);
    }

    @Override
    public void ready() throws Exception {
        ready.set(true);
    }

    @Override
    public void drain(Duration remaining) throws Exception {
        ready.set(false);
    }

    @Override
    public void terminate() {
        ready.set(false);
        initialized.set(false);
    }

    public boolean isReady() {
        return ready.get();
    }

    public boolean isInitialized() {
        return initialized.get();
    }
}
