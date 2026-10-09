package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.audittrail.api.AuditQuery;
import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.api.SessionInfo;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.internal.DefaultSessionStore;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.repository.InMemorySessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultSessionStore Unit Tests")
class DefaultSessionStoreTest {

    private InMemorySessionRepository repository;
    private List<AuditEvent> auditEvents;
    private SessionAuditBridge auditBridge;
    private DefaultSessionStore sessionStore;
    private final SessionPolicy policy = new SessionPolicy(Duration.ofHours(24), Duration.ofDays(7), 3);

    @BeforeEach
    void setUp() {
        repository = new InMemorySessionRepository();
        auditEvents = new ArrayList<>();
        AuditLogSink sink = new AuditLogSink() {
            @Override public void emit(AuditEvent event) { auditEvents.add(event); }
            @Override public List<AuditEvent> query(AuditQuery query) { return auditEvents; }
            @Override public long count(AuditQuery query) { return auditEvents.size(); }
        };
        auditBridge = new SessionAuditBridge(sink);
        sessionStore = new DefaultSessionStore(repository, policy, auditBridge);
    }

    @Test
    @DisplayName("createSession initializes session correctly and emits audit event")
    void createSessionSuccess() {
        UUID subjectId = UUID.randomUUID();
        ClientMetadata metadata = ClientMetadata.of("Chrome/120.0", "192.168.1.1");

        Session session = sessionStore.createSession(subjectId, metadata);

        assertThat(session).isNotNull();
        assertThat(session.id()).isNotNull();
        assertThat(session.subjectId()).isEqualTo(subjectId);
        assertThat(session.userAgent()).isEqualTo("Chrome/120.0");
        assertThat(session.ipAddress()).isEqualTo("192.168.1.1");
        assertThat(session.revokedAt()).isNull();
        assertThat(session.isActive(Instant.now())).isTrue();

        assertThat(auditEvents).hasSize(1);
        AuditEvent event = auditEvents.get(0);
        assertThat(event.action()).isEqualTo("SESSION_CREATED");
        assertThat(event.resourceId()).isEqualTo(session.id().toString());
        assertThat(event.actorId()).isEqualTo(subjectId.toString());
        assertThat(event.details().get("userAgent")).isEqualTo("Chrome/120.0");
    }

    @Test
    @DisplayName("listActiveSessions returns active sessions and isolates subjects")
    void listActiveSessionsIsolatesSubjects() {
        UUID subjectA = UUID.randomUUID();
        UUID subjectB = UUID.randomUUID();

        Session sessionA1 = sessionStore.createSession(subjectA, ClientMetadata.of("UA-1", "10.0.0.1"));
        Session sessionA2 = sessionStore.createSession(subjectA, ClientMetadata.of("UA-2", "10.0.0.2"));
        Session sessionB1 = sessionStore.createSession(subjectB, ClientMetadata.of("UA-3", "10.0.0.3"));

        List<SessionInfo> activeA = sessionStore.listActiveSessions(subjectA);
        assertThat(activeA).hasSize(2)
                .extracting(SessionInfo::id)
                .containsExactlyInAnyOrder(sessionA1.id(), sessionA2.id());

        List<SessionInfo> activeB = sessionStore.listActiveSessions(subjectB);
        assertThat(activeB).hasSize(1)
                .extracting(SessionInfo::id)
                .containsExactly(sessionB1.id());
    }

    @Test
    @DisplayName("listActiveSessions with currentSessionId marks isCurrent flag")
    void listActiveSessionsMarksCurrent() {
        UUID subjectId = UUID.randomUUID();
        Session s1 = sessionStore.createSession(subjectId, ClientMetadata.empty());
        Session s2 = sessionStore.createSession(subjectId, ClientMetadata.empty());

        List<SessionInfo> list = sessionStore.listActiveSessions(subjectId, s2.id());
        assertThat(list).hasSize(2);

        SessionInfo info1 = list.stream().filter(s -> s.id().equals(s1.id())).findFirst().orElseThrow();
        SessionInfo info2 = list.stream().filter(s -> s.id().equals(s2.id())).findFirst().orElseThrow();

        assertThat(info1.isCurrent()).isFalse();
        assertThat(info2.isCurrent()).isTrue();
    }

    @Test
    @DisplayName("findSession retrieves session view info")
    void findSessionRetrievesInfo() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.of("Firefox", "127.0.0.1"));

        Optional<SessionInfo> found = sessionStore.findSession(session.id());
        assertThat(found).isPresent();
        assertThat(found.get().id()).isEqualTo(session.id());
        assertThat(found.get().userAgent()).isEqualTo("Firefox");

        Optional<SessionInfo> notFound = sessionStore.findSession(UUID.randomUUID());
        assertThat(notFound).isEmpty();
    }

    @Test
    @DisplayName("revokeSession revokes individual session and emits audit event")
    void revokeSessionSuccess() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());

        boolean revoked = sessionStore.revokeSession(subjectId, session.id());
        assertThat(revoked).isTrue();

        List<SessionInfo> active = sessionStore.listActiveSessions(subjectId);
        assertThat(active).isEmpty();

        // Second revoke attempt returns false
        boolean secondRevoke = sessionStore.revokeSession(subjectId, session.id());
        assertThat(secondRevoke).isFalse();

        assertThat(auditEvents).hasSize(2); // created + revoked
        AuditEvent event = auditEvents.get(1);
        assertThat(event.action()).isEqualTo("SESSION_REVOKED");
        assertThat(event.resourceId()).isEqualTo(session.id().toString());
    }

    @Test
    @DisplayName("revokeSession fails if subject does not match")
    void revokeSessionSubjectMismatch() {
        UUID subject1 = UUID.randomUUID();
        UUID subject2 = UUID.randomUUID();
        Session session = sessionStore.createSession(subject1, ClientMetadata.empty());

        boolean revoked = sessionStore.revokeSession(subject2, session.id());
        assertThat(revoked).isFalse();
        assertThat(sessionStore.listActiveSessions(subject1)).hasSize(1);
    }

    @Test
    @DisplayName("revokeAllForSubject revokes all active sessions for that subject")
    void revokeAllForSubjectSuccess() {
        UUID subject1 = UUID.randomUUID();
        UUID subject2 = UUID.randomUUID();

        sessionStore.createSession(subject1, ClientMetadata.empty());
        sessionStore.createSession(subject1, ClientMetadata.empty());
        Session s2 = sessionStore.createSession(subject2, ClientMetadata.empty());

        int count = sessionStore.revokeAllForSubject(subject1);
        assertThat(count).isEqualTo(2);

        assertThat(sessionStore.listActiveSessions(subject1)).isEmpty();
        assertThat(sessionStore.listActiveSessions(subject2)).hasSize(1)
                .extracting(SessionInfo::id)
                .containsExactly(s2.id());

        AuditEvent event = auditEvents.stream()
                .filter(e -> "SESSIONS_REVOKED_ALL".equals(e.action()))
                .findFirst()
                .orElseThrow();
        assertThat(event.actorId()).isEqualTo(subject1.toString());
        assertThat(event.details().get("revokedCount")).isEqualTo(2);
    }

    @Test
    @DisplayName("maxActiveSessionsPerSubject evicts oldest active session when limit is exceeded")
    void maxActiveSessionsEviction() throws Exception {
        UUID subjectId = UUID.randomUUID();

        // Policy allows max 3 sessions
        Session s1 = sessionStore.createSession(subjectId, ClientMetadata.of("Client-1", "1.1.1.1"));
        Thread.sleep(10);
        Session s2 = sessionStore.createSession(subjectId, ClientMetadata.of("Client-2", "2.2.2.2"));
        Thread.sleep(10);
        Session s3 = sessionStore.createSession(subjectId, ClientMetadata.of("Client-3", "3.3.3.3"));

        assertThat(sessionStore.listActiveSessions(subjectId)).hasSize(3);

        // Creating 4th session should evict s1 (the oldest)
        Thread.sleep(10);
        Session s4 = sessionStore.createSession(subjectId, ClientMetadata.of("Client-4", "4.4.4.4"));

        List<SessionInfo> active = sessionStore.listActiveSessions(subjectId);
        assertThat(active).hasSize(3)
                .extracting(SessionInfo::id)
                .containsExactlyInAnyOrder(s2.id(), s3.id(), s4.id())
                .doesNotContain(s1.id());

        // Verify eviction audit event for s1
        boolean s1Evicted = auditEvents.stream()
                .anyMatch(e -> "SESSION_REVOKED".equals(e.action()) && s1.id().toString().equals(e.resourceId()));
        assertThat(s1Evicted).isTrue();
    }

    @Test
    @DisplayName("revokeSession(sessionId) resolves subject identifier for audit log")
    void revokeSessionByIdResolvesSubjectForAudit() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());

        boolean revoked = sessionStore.revokeSession(session.id());
        assertThat(revoked).isTrue();

        AuditEvent event = auditEvents.stream()
                .filter(e -> "SESSION_REVOKED".equals(e.action()))
                .findFirst()
                .orElseThrow();
        assertThat(event.actorId()).isEqualTo(subjectId.toString());
        assertThat(event.resourceId()).isEqualTo(session.id().toString());
    }

    @Test
    @DisplayName("client metadata safely truncates userAgent and ipAddress over max length")
    void clientMetadataTruncatesLongStrings() {
        String longUa = "A".repeat(600);
        String longIp = "1".repeat(100);
        ClientMetadata metadata = ClientMetadata.of(longUa, longIp);

        assertThat(metadata.userAgent()).hasSize(512);
        assertThat(metadata.ipAddress()).hasSize(64);

        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, metadata);
        assertThat(session.userAgent()).hasSize(512);
        assertThat(session.ipAddress()).hasSize(64);
    }
}
