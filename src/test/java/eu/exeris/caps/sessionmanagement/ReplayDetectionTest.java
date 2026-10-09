package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.audittrail.api.AuditQuery;
import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.RotationResult;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.exception.InvalidRefreshTokenException;
import eu.exeris.caps.sessionmanagement.api.exception.RefreshTokenReplayedException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionRevokedException;
import eu.exeris.caps.sessionmanagement.internal.DefaultRefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.internal.DefaultSessionStore;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.repository.InMemorySessionRepository;
import eu.exeris.caps.sessionmanagement.spi.InMemoryAccessTokenIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Replay Detection and Invalidation Tests (ADR-099 Obligation 9)")
class ReplayDetectionTest {

    private InMemorySessionRepository repository;
    private List<AuditEvent> auditEvents;
    private SessionAuditBridge auditBridge;
    private DefaultSessionStore sessionStore;
    private DefaultRefreshTokenRotation rotation;
    private final SessionPolicy policy = SessionPolicy.defaults();

    @BeforeEach
    void setUp() {
        repository = new InMemorySessionRepository();
        auditEvents = new ArrayList<>();
        AuditLogSink sink = new AuditLogSink() {
            @Override public synchronized void emit(AuditEvent event) { auditEvents.add(event); }
            @Override public synchronized List<AuditEvent> query(AuditQuery query) { return auditEvents; }
            @Override public synchronized long count(AuditQuery query) { return auditEvents.size(); }
        };
        auditBridge = new SessionAuditBridge(sink);
        sessionStore = new DefaultSessionStore(repository, policy, auditBridge);
        rotation = new DefaultRefreshTokenRotation(repository, policy, new InMemoryAccessTokenIssuer(), auditBridge);
    }

    @Test
    @DisplayName("replaying a consumed refresh token revokes session and emits alert audit event")
    void replayConsumedTokenRevokesSession() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());
        IssuedRefreshToken token1 = rotation.issue(session.id(), subjectId);

        // First rotation: valid consumption
        RotationResult rotation1 = rotation.rotate(token1.rawToken(), ClientMetadata.empty());
        IssuedRefreshToken token2 = rotation1.refreshToken();
        assertThat(token2).isNotNull();

        // Second rotation with token1: REPLAY ATTACK!
        assertThatThrownBy(() -> rotation.rotate(token1.rawToken(), ClientMetadata.empty()))
                .isInstanceOf(RefreshTokenReplayedException.class)
                .hasMessageContaining("Refresh token replay detected");

        // The session must be immediately revoked
        assertThat(sessionStore.listActiveSessions(subjectId)).isEmpty();

        // The successor token token2 belongs to a revoked session now
        assertThatThrownBy(() -> rotation.rotate(token2.rawToken(), ClientMetadata.empty()))
                .isInstanceOf(SessionRevokedException.class);

        // Verify alert audit event
        AuditEvent replayEvent = auditEvents.stream()
                .filter(e -> "TOKEN_REPLAY_DETECTED".equals(e.action()))
                .findFirst()
                .orElseThrow();
        assertThat(replayEvent.resourceId()).isEqualTo(session.id().toString());
        assertThat(replayEvent.actorId()).isEqualTo(subjectId.toString());
        assertThat(replayEvent.details()).containsKey("tokenHashPrefix");
    }

    @Test
    @DisplayName("concurrent rotation race: exactly 1 wins, other attempts detect replay or revocation")
    void concurrentRotationRaceCondition() throws Exception {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());
        IssuedRefreshToken token = rotation.issue(session.id(), subjectId);

        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger replayOrRevokedCount = new AtomicInteger(0);

        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    rotation.rotate(token.rawToken(), ClientMetadata.empty());
                    successCount.incrementAndGet();
                } catch (RefreshTokenReplayedException | InvalidRefreshTokenException | SessionRevokedException e) {
                    replayOrRevokedCount.incrementAndGet();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
        }

        // Fire all threads simultaneously
        startLatch.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        // Exactly one concurrent rotation request must succeed
        assertThat(successCount.get()).isEqualTo(1);
        // All other concurrent requests were refused
        assertThat(replayOrRevokedCount.get()).isEqualTo(threadCount - 1);
    }
}
