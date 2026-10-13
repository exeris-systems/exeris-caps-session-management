package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.sessionmanagement.api.RefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.SessionStore;
import eu.exeris.caps.sessionmanagement.internal.DefaultRefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.internal.DefaultSessionStore;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.repository.PostgresSessionRepository;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;
import eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-session-management}.
 *
 * <p>Provides Layer 5 Domain Primitives:
 * <ul>
 *   <li>{@link SessionStore}: one session per sign-in; list, revoke one, revoke all and log out, each
 *       scoped to the authenticated {@link eu.exeris.caps.sessionmanagement.api.SessionPrincipal}</li>
 *   <li>{@link RefreshTokenRotation}: opaque single-use refresh tokens stored hashed, rotated on every
 *       use; a reused token revokes its whole family</li>
 * </ul>
 *
 * <p>Sessions are persisted in PostgreSQL through the kernel {@link TransactionalExecutor}; there is no
 * other store, and its schema is {@link #MIGRATIONS}. A module built without an executor has no services,
 * and {@link #initialize()} refuses to start it.
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = SessionStore.class, version = "2.0.0")
@Provides(service = RefreshTokenRotation.class, version = "2.0.0")
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[1.0.0,2.0.0)", optional = true)
@Requires(service = AccessTokenIssuer.class, versionRange = "[1.0.0,2.0.0)", optional = true)
public final class SessionManagementModule implements CapabilityLifecycleHooks {

    /**
     * The schema migrations of this capability, in the order they apply, as classpath resource paths.
     * The capability does not apply them itself; the composing SKU does, before the first service call.
     */
    public static final List<String> MIGRATIONS = List.of(
            "db/migration/exeris-caps-session-management/V1__session_management.sql");

    private final SessionStore sessionStore;
    private final RefreshTokenRotation refreshTokenRotation;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Public no-arg constructor for reflective instantiation by the composition conductor. The module it
     * builds has no persistence, so it exposes no services and refuses to initialize.
     */
    public SessionManagementModule() {
        this.sessionStore = null;
        this.refreshTokenRotation = null;
    }

    /**
     * Wires the module over PostgreSQL with the system clock.
     *
     * @param tx                kernel transactional executor; required
     * @param policy            session policy, or {@code null} for {@link SessionPolicy#defaults()}
     * @param accessTokenIssuer issues an access token on each rotation, or {@code null} for none
     * @param auditLogSink      receives security events, or {@code null} for none
     */
    public SessionManagementModule(
            TransactionalExecutor tx,
            SessionPolicy policy,
            AccessTokenIssuer accessTokenIssuer,
            AuditLogSink auditLogSink
    ) {
        this(tx, policy, accessTokenIssuer, auditLogSink, Clock.systemUTC());
    }

    /**
     * Wires the module over PostgreSQL with an explicit clock, which decides every expiry and idle check.
     *
     * @param tx                kernel transactional executor; required
     * @param policy            session policy, or {@code null} for {@link SessionPolicy#defaults()}
     * @param accessTokenIssuer issues an access token on each rotation, or {@code null} for none
     * @param auditLogSink      receives security events, or {@code null} for none
     * @param clock             time source; required
     */
    public SessionManagementModule(
            TransactionalExecutor tx,
            SessionPolicy policy,
            AccessTokenIssuer accessTokenIssuer,
            AuditLogSink auditLogSink,
            Clock clock
    ) {
        this(
                new PostgresSessionRepository(Objects.requireNonNull(tx, "tx must not be null")),
                policy != null ? policy : SessionPolicy.defaults(),
                accessTokenIssuer,
                auditLogSink != null ? new SessionAuditBridge(auditLogSink) : null,
                clock
        );
    }

    SessionManagementModule(
            SessionRepository repository,
            SessionPolicy policy,
            AccessTokenIssuer accessTokenIssuer,
            SessionAuditBridge auditBridge,
            Clock clock
    ) {
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(policy, "policy must not be null");
        Objects.requireNonNull(clock, "clock must not be null");

        this.sessionStore = new DefaultSessionStore(repository, policy, auditBridge, clock);
        this.refreshTokenRotation = new DefaultRefreshTokenRotation(repository, policy, accessTokenIssuer, auditBridge, clock);
    }

    /**
     * @throws IllegalStateException if the module was built without persistence
     */
    public SessionStore sessionStore() {
        requireWired();
        return sessionStore;
    }

    /**
     * @throws IllegalStateException if the module was built without persistence
     */
    public RefreshTokenRotation refreshTokenRotation() {
        requireWired();
        return refreshTokenRotation;
    }

    /**
     * Whether the module was built with persistence and exposes its services.
     */
    public boolean isWired() {
        return sessionStore != null;
    }

    @Override
    public void initialize() throws Exception {
        requireWired();
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

    private void requireWired() {
        if (!isWired()) {
            throw new IllegalStateException(
                    "exeris-caps-session-management has no TransactionalExecutor wired; it has no store without one");
        }
    }
}
