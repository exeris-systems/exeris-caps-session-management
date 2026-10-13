package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.audittrail.api.AuditQuery;
import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.RefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome.Reason;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionInfo;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.caps.sessionmanagement.api.SessionStore;
import eu.exeris.caps.sessionmanagement.api.exception.SessionException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionExpiredException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionNotFoundException;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;
import eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The behaviour every {@link SessionRepository} must give the capability, run through the public API.
 * Bound once against a test double and once against live PostgreSQL.
 */
abstract class AbstractSessionManagementContractTest {

    static final Duration IDLE = Duration.ofMinutes(30);
    static final Duration ABSOLUTE = Duration.ofHours(4);
    static final SessionPolicy POLICY = new SessionPolicy(ABSOLUTE, IDLE, 3);

    MutableClock clock;
    List<AuditEvent> auditEvents;
    SessionStore store;
    RefreshTokenRotation rotation;
    final AtomicBoolean issuerFails = new AtomicBoolean();

    /** A repository with no rows, fresh for each test. */
    protected abstract SessionRepository newRepository();

    @BeforeEach
    void wire() {
        clock = new MutableClock(Instant.parse("2026-10-13T08:00:00Z").truncatedTo(ChronoUnit.MILLIS));
        auditEvents = Collections.synchronizedList(new ArrayList<>());
        AuditLogSink sink = new AuditLogSink() {
            @Override public void emit(AuditEvent event) { auditEvents.add(event); }
            @Override public List<AuditEvent> query(AuditQuery query) { return List.copyOf(auditEvents); }
            @Override public long count(AuditQuery query) { return auditEvents.size(); }
        };
        issuerFails.set(false);
        InMemoryAccessTokenIssuer delegate = new InMemoryAccessTokenIssuer();
        AccessTokenIssuer issuer = (subjectId, sessionId) -> {
            if (issuerFails.get()) {
                throw new IllegalStateException("signing key unavailable");
            }
            return delegate.issueAccessToken(subjectId, sessionId);
        };
        SessionManagementModule module = new SessionManagementModule(
                newRepository(), POLICY, issuer, new SessionAuditBridge(sink), clock);
        store = module.sessionStore();
        rotation = module.refreshTokenRotation();
    }

    record SignIn(UUID subjectId, Session session, IssuedRefreshToken token) {
        SessionPrincipal principal() {
            return TestPrincipals.authenticated(subjectId, session.id());
        }
    }

    SignIn signIn(UUID subjectId) {
        Session session = store.createSession(subjectId, ClientMetadata.of("Browser/1.0", "198.51.100.7"));
        return new SignIn(subjectId, session, rotation.issue(session.id(), subjectId));
    }

    SignIn signIn() {
        return signIn(UUID.randomUUID());
    }

    static RotationOutcome.Rotated rotated(RotationOutcome outcome) {
        assertThat(outcome).isInstanceOf(RotationOutcome.Rotated.class);
        return (RotationOutcome.Rotated) outcome;
    }

    static void assertRejected(RotationOutcome outcome, Reason reason) {
        assertThat(outcome).isEqualTo(new RotationOutcome.Rejected(reason));
    }

    @Nested
    @DisplayName("refresh rotation is strictly single-use")
    class SingleUse {

        @Test
        @DisplayName("a live token rotates once and its successor rotates in turn")
        void rotatesAndChains() {
            SignIn in = signIn();

            RotationOutcome.Rotated first = rotated(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()));
            assertThat(first.subjectId()).isEqualTo(in.subjectId());
            assertThat(first.sessionId()).isEqualTo(in.session().id());
            assertThat(first.refreshToken().rawToken()).isNotEqualTo(in.token().rawToken());
            assertThat(first.findAccessToken()).isPresent();

            rotated(rotation.rotate(first.refreshToken().rawToken(), ClientMetadata.empty()));
        }

        @Test
        @DisplayName("presenting a consumed token at the same instant is reuse: no grace window")
        void reuseAtTheSameInstantRevokesTheFamily() {
            SignIn in = signIn();
            RotationOutcome.Rotated first = rotated(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()));

            RotationOutcome again = rotation.rotate(in.token().rawToken(), ClientMetadata.empty());

            assertThat(again).isEqualTo(new RotationOutcome.ReuseDetected(in.session().id()));
            assertRejected(rotation.rotate(first.refreshToken().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
            assertThat(store.listSessions(in.principal())).isEmpty();
            assertThat(auditEvents).extracting(AuditEvent::action).contains("TOKEN_REPLAY_DETECTED");
        }

        @Test
        @DisplayName("an access token issuer that fails after the commit still hands the caller the successor")
        void issuerFailureKeepsTheSuccessor() {
            SignIn in = signIn();
            issuerFails.set(true);

            RotationOutcome.Rotated first = rotated(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()));

            assertThat(first.findAccessToken()).isEmpty();
            assertThat(first.refreshToken().rawToken()).isNotEqualTo(in.token().rawToken());

            issuerFails.set(false);
            RotationOutcome.Rotated second = rotated(rotation.rotate(first.refreshToken().rawToken(), ClientMetadata.empty()));
            assertThat(second.findAccessToken()).isPresent();

            assertThat(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()))
                    .isEqualTo(new RotationOutcome.ReuseDetected(in.session().id()));
        }

        @Test
        @DisplayName("presenting a consumed token after the session went idle is refused and reported as a replay")
        void replayAgainstAnIdleSessionIsAudited() {
            SignIn in = signIn();
            rotated(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()));
            clock.advance(IDLE);

            assertRejected(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_IDLE);
            assertThat(auditEvents).extracting(AuditEvent::action).contains("TOKEN_REPLAY_DETECTED");
        }

        @Test
        @DisplayName("reuse of an older ancestor revokes the family as well")
        void reuseOfAnAncestorRevokesTheFamily() {
            SignIn in = signIn();
            RotationOutcome.Rotated first = rotated(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()));
            clock.advance(Duration.ofMinutes(5));
            RotationOutcome.Rotated second = rotated(rotation.rotate(first.refreshToken().rawToken(), ClientMetadata.empty()));

            assertThat(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()))
                    .isEqualTo(new RotationOutcome.ReuseDetected(in.session().id()));
            assertRejected(rotation.rotate(second.refreshToken().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
        }

        @RepeatedTest(10)
        @DisplayName("two concurrent refreshes with one token: exactly one wins and the family is revoked")
        void concurrentDoubleRefresh() throws Exception {
            SignIn in = signIn();
            List<RotationOutcome> outcomes = race(in.token().rawToken(), 2);

            List<RotationOutcome.Rotated> winners = outcomes.stream()
                    .filter(RotationOutcome.Rotated.class::isInstance).map(RotationOutcome.Rotated.class::cast).toList();
            assertThat(winners).hasSize(1);
            assertThat(outcomes).containsOnlyOnce(new RotationOutcome.ReuseDetected(in.session().id()));

            assertRejected(rotation.rotate(winners.getFirst().refreshToken().rawToken(), ClientMetadata.empty()),
                    Reason.SESSION_REVOKED);
            assertThat(store.listSessions(in.principal())).isEmpty();
        }

        @Test
        @DisplayName("many concurrent refreshes with one token: exactly one wins, none is accepted after it")
        void concurrentStampede() throws Exception {
            SignIn in = signIn();
            List<RotationOutcome> outcomes = race(in.token().rawToken(), 8);

            assertThat(outcomes).filteredOn(RotationOutcome.Rotated.class::isInstance).hasSize(1);
            assertThat(outcomes).filteredOn(RotationOutcome.ReuseDetected.class::isInstance).isNotEmpty();
            assertThat(outcomes).filteredOn(o -> !(o instanceof RotationOutcome.Rotated)
                            && !(o instanceof RotationOutcome.ReuseDetected))
                    .allSatisfy(o -> assertThat(o).isEqualTo(new RotationOutcome.Rejected(Reason.SESSION_REVOKED)));
            assertThat(store.listSessions(in.principal())).isEmpty();
        }

        @Test
        @DisplayName("an unknown or blank token is rejected without touching any session")
        void unknownToken() {
            SignIn in = signIn();
            assertRejected(rotation.rotate("00000000000000000000000000000000", ClientMetadata.empty()), Reason.UNKNOWN_TOKEN);
            assertRejected(rotation.rotate(" ", ClientMetadata.empty()), Reason.UNKNOWN_TOKEN);
            assertRejected(rotation.rotate(null, ClientMetadata.empty()), Reason.UNKNOWN_TOKEN);
            assertThat(store.listSessions(in.principal())).hasSize(1);
        }

        @Test
        @DisplayName("a session's first token is issued once, to its own subject only")
        void issueIsOncePerSessionAndOwnerOnly() {
            SignIn in = signIn();
            UUID ownSession = in.session().id();
            UUID subject = in.subjectId();
            assertThatThrownBy(() -> rotation.issue(ownSession, subject))
                    .isInstanceOf(SessionException.class);

            UUID otherSession = store.createSession(UUID.randomUUID(), ClientMetadata.empty()).id();
            assertThatThrownBy(() -> rotation.issue(otherSession, subject))
                    .isInstanceOf(SessionNotFoundException.class);
        }

        @Test
        @DisplayName("revoking with a held token ends the whole family")
        void revokeByTokenEndsTheFamily() {
            SignIn in = signIn();
            RotationOutcome.Rotated first = rotated(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()));

            assertThat(rotation.revoke(first.refreshToken().rawToken())).isTrue();
            assertThat(rotation.revoke(first.refreshToken().rawToken())).isFalse();
            assertRejected(rotation.rotate(first.refreshToken().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
            assertThat(store.listSessions(in.principal())).isEmpty();
        }

        List<RotationOutcome> race(String rawToken, int contenders) throws Exception {
            ExecutorService pool = Executors.newFixedThreadPool(contenders);
            try {
                CyclicBarrier start = new CyclicBarrier(contenders);
                List<Future<RotationOutcome>> futures = new ArrayList<>();
                for (int i = 0; i < contenders; i++) {
                    futures.add(pool.submit(() -> {
                        start.await(10, TimeUnit.SECONDS);
                        return rotation.rotate(rawToken, ClientMetadata.empty());
                    }));
                }
                List<RotationOutcome> outcomes = new ArrayList<>();
                for (Future<RotationOutcome> f : futures) {
                    outcomes.add(f.get(30, TimeUnit.SECONDS));
                }
                return outcomes;
            } finally {
                pool.shutdownNow();
            }
        }
    }

    @Nested
    @DisplayName("session lifetime: idle timeout and absolute lifetime")
    class Lifetime {

        @Test
        @DisplayName("a session not refreshed within the idle timeout refuses refresh and is not listed")
        void idleSessionRefusesRefresh() {
            SignIn in = signIn();
            clock.advance(IDLE);

            assertRejected(rotation.rotate(in.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_IDLE);
            assertThat(store.listSessions(in.principal())).isEmpty();
        }

        @Test
        @DisplayName("refreshing within the idle timeout keeps the session alive past the first idle window")
        void refreshResetsTheIdleWindow() {
            SignIn in = signIn();
            String token = in.token().rawToken();
            for (int i = 0; i < 4; i++) {
                clock.advance(IDLE.minusMinutes(1));
                token = rotated(rotation.rotate(token, ClientMetadata.empty())).refreshToken().rawToken();
            }
            List<SessionInfo> listed = store.listSessions(in.principal());
            assertThat(listed).hasSize(1);
            assertThat(listed.getFirst().idleExpiresAt()).isEqualTo(clock.instant().plus(IDLE));
            assertThat(listed.getFirst().isCurrent()).isTrue();
        }

        @Test
        @DisplayName("past the absolute lifetime a session refuses refresh however recently it was used")
        void absoluteLifetimeIsNotExtendedByActivity() {
            SignIn in = signIn();
            String token = in.token().rawToken();
            Instant hardStop = in.session().expiresAt();
            while (clock.instant().plus(IDLE.minusMinutes(1)).isBefore(hardStop)) {
                clock.advance(IDLE.minusMinutes(1));
                RotationOutcome.Rotated r = rotated(rotation.rotate(token, ClientMetadata.empty()));
                assertThat(r.refreshToken().expiresAt()).isBeforeOrEqualTo(hardStop);
                token = r.refreshToken().rawToken();
            }
            clock.advance(Duration.between(clock.instant(), hardStop));

            assertRejected(rotation.rotate(token, ClientMetadata.empty()), Reason.SESSION_EXPIRED);
            assertThat(store.listSessions(in.principal())).isEmpty();
        }

        @Test
        @DisplayName("a first token cannot be issued for an idle session")
        void noIssueForAnIdleSession() {
            UUID subject = UUID.randomUUID();
            UUID sessionId = store.createSession(subject, ClientMetadata.empty()).id();
            clock.advance(IDLE);
            assertThatThrownBy(() -> rotation.issue(sessionId, subject)).isInstanceOf(SessionExpiredException.class);
        }

        @Test
        @DisplayName("creating more sessions than the policy allows revokes the oldest")
        void oldestSessionIsEvicted() {
            UUID subject = UUID.randomUUID();
            SignIn oldest = signIn(subject);
            clock.advance(Duration.ofSeconds(1));
            signIn(subject);
            clock.advance(Duration.ofSeconds(1));
            signIn(subject);
            clock.advance(Duration.ofSeconds(1));
            SignIn newest = signIn(subject);

            assertThat(store.listSessions(newest.principal())).extracting(SessionInfo::id)
                    .hasSize(3)
                    .doesNotContain(oldest.session().id());
            assertRejected(rotation.rotate(oldest.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
        }
    }

    @Nested
    @DisplayName("operations are scoped to the authenticated subject")
    class SubjectScoping {

        @Test
        @DisplayName("a subject cannot revoke another subject's session")
        void cannotRevokeAnotherSubjectsSession() {
            SignIn alice = signIn();
            SignIn mallory = signIn();

            assertThat(store.revokeSession(mallory.principal(), alice.session().id())).isFalse();

            assertThat(store.listSessions(alice.principal())).extracting(SessionInfo::id)
                    .containsExactly(alice.session().id());
            rotated(rotation.rotate(alice.token().rawToken(), ClientMetadata.empty()));
        }

        @Test
        @DisplayName("listing shows only the caller's own sessions")
        void listsOnlyOwnSessions() {
            SignIn alice = signIn();
            SignIn bob = signIn();

            assertThat(store.listSessions(bob.principal())).extracting(SessionInfo::id)
                    .containsExactly(bob.session().id());
            assertThat(store.listSessions(alice.principal())).extracting(SessionInfo::id)
                    .containsExactly(alice.session().id());
        }

        @Test
        @DisplayName("revoke-all affects the caller's sessions and nobody else's")
        void revokeAllIsOwnOnly() {
            UUID aliceId = UUID.randomUUID();
            SignIn alice1 = signIn(aliceId);
            SignIn alice2 = signIn(aliceId);
            SignIn bob = signIn();

            assertThat(store.revokeAllSessions(alice1.principal())).isEqualTo(2);

            assertRejected(rotation.rotate(alice2.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
            assertThat(store.listSessions(bob.principal())).hasSize(1);
            rotated(rotation.rotate(bob.token().rawToken(), ClientMetadata.empty()));
        }

        @Test
        @DisplayName("a subject revokes one of its own sessions; the others stay")
        void revokesOwnSession() {
            UUID subject = UUID.randomUUID();
            SignIn phone = signIn(subject);
            SignIn laptop = signIn(subject);

            assertThat(store.revokeSession(laptop.principal(), phone.session().id())).isTrue();
            assertThat(store.revokeSession(laptop.principal(), phone.session().id())).isFalse();

            assertRejected(rotation.rotate(phone.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
            assertThat(store.listSessions(laptop.principal())).extracting(SessionInfo::id)
                    .containsExactly(laptop.session().id());
        }

        @Test
        @DisplayName("logout revokes the session the caller authenticated with, and only that one")
        void logoutRevokesTheCurrentSession() {
            UUID subject = UUID.randomUUID();
            SignIn phone = signIn(subject);
            SignIn laptop = signIn(subject);

            assertThat(store.logout(laptop.principal())).isTrue();

            assertRejected(rotation.rotate(laptop.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
            rotated(rotation.rotate(phone.token().rawToken(), ClientMetadata.empty()));
        }

        @Test
        @DisplayName("logout with a principal from another subject's token cannot end the victim's session")
        void logoutCannotTargetAnotherSubjectsSession() {
            SignIn alice = signIn();
            SessionPrincipal forged = TestPrincipals.authenticated(UUID.randomUUID(), alice.session().id());

            assertThat(store.logout(forged)).isFalse();
            rotated(rotation.rotate(alice.token().rawToken(), ClientMetadata.empty()));
        }

        @Test
        @DisplayName("logout needs a principal that carries its session")
        void logoutNeedsASessionBoundPrincipal() {
            SignIn in = signIn();
            SessionPrincipal noSid = TestPrincipals.authenticatedWithoutSession(in.subjectId());

            assertThatThrownBy(() -> store.logout(noSid)).isInstanceOf(IllegalStateException.class);
            assertThat(store.listSessions(noSid)).extracting(SessionInfo::isCurrent).containsExactly(false);
        }

        @Test
        @DisplayName("a credential change revokes every session of that subject")
        void credentialChangeRevokesAll() {
            UUID subject = UUID.randomUUID();
            SignIn one = signIn(subject);
            SignIn two = signIn(subject);
            SignIn bystander = signIn();

            assertThat(store.revokeAllForSubject(subject)).isEqualTo(2);

            assertRejected(rotation.rotate(one.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
            assertRejected(rotation.rotate(two.token().rawToken(), ClientMetadata.empty()), Reason.SESSION_REVOKED);
            rotated(rotation.rotate(bystander.token().rawToken(), ClientMetadata.empty()));
        }
    }
}
