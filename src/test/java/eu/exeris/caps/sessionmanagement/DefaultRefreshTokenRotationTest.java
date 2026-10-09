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
import eu.exeris.caps.sessionmanagement.api.exception.SessionExpiredException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionNotFoundException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionRevokedException;
import eu.exeris.caps.sessionmanagement.internal.DefaultRefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.internal.DefaultSessionStore;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.crypto.TokenHasher;
import eu.exeris.caps.sessionmanagement.internal.repository.InMemorySessionRepository;
import eu.exeris.caps.sessionmanagement.internal.repository.RefreshTokenRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRecord;
import eu.exeris.caps.sessionmanagement.spi.InMemoryAccessTokenIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("DefaultRefreshTokenRotation Unit Tests")
class DefaultRefreshTokenRotationTest {

    private InMemorySessionRepository repository;
    private List<AuditEvent> auditEvents;
    private SessionAuditBridge auditBridge;
    private DefaultSessionStore sessionStore;
    private DefaultRefreshTokenRotation rotation;
    private InMemoryAccessTokenIssuer tokenIssuer;
    private final SessionPolicy policy = new SessionPolicy(Duration.ofDays(7), Duration.ofDays(7), 5);

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
        tokenIssuer = new InMemoryAccessTokenIssuer();
        sessionStore = new DefaultSessionStore(repository, policy, auditBridge);
        rotation = new DefaultRefreshTokenRotation(repository, policy, tokenIssuer, auditBridge);
    }

    @Test
    @DisplayName("issue generates valid unhashed refresh token bound to session")
    void issueSuccess() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());

        IssuedRefreshToken token = rotation.issue(session.id(), subjectId);

        assertThat(token).isNotNull();
        assertThat(token.sessionId()).isEqualTo(session.id());
        assertThat(token.rawToken()).matches("^[0-9a-f]{32}$");
        assertThat(token.expiresAt()).isAfter(Instant.now());

        // Token hash is stored in repository, raw token is not
        String hash = TokenHasher.hash(token.rawToken());
        assertThat(repository.findRefreshTokenByHash(hash)).isPresent();
    }

    @Test
    @DisplayName("issue fails on non-existent, expired, or revoked session")
    void issueFailsOnInvalidSession() {
        UUID subjectId = UUID.randomUUID();

        // Non-existent
        assertThatThrownBy(() -> rotation.issue(UUID.randomUUID(), subjectId))
                .isInstanceOf(SessionNotFoundException.class);

        // Revoked
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());
        sessionStore.revokeSession(session.id());
        assertThatThrownBy(() -> rotation.issue(session.id(), subjectId))
                .isInstanceOf(SessionRevokedException.class);

        // Expired
        UUID expiredSessionId = UUID.randomUUID();
        SessionRecord expiredRecord = new SessionRecord(
                expiredSessionId,
                subjectId,
                Instant.now().minus(Duration.ofDays(2)),
                Instant.now().minus(Duration.ofDays(1)),
                Instant.now().minus(Duration.ofDays(2)),
                null,
                null,
                null
        );
        repository.saveSession(expiredRecord);
        assertThatThrownBy(() -> rotation.issue(expiredSessionId, subjectId))
                .isInstanceOf(SessionExpiredException.class);
    }

    @Test
    @DisplayName("rotate consumes presented token, provides fresh token and access token")
    void rotateSuccess() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.of("Old-UA", "1.1.1.1"));
        IssuedRefreshToken firstToken = rotation.issue(session.id(), subjectId);

        ClientMetadata newMeta = ClientMetadata.of("New-UA", "2.2.2.2");
        RotationResult result = rotation.rotate(firstToken.rawToken(), newMeta);

        assertThat(result.sessionId()).isEqualTo(session.id());
        assertThat(result.subjectId()).isEqualTo(subjectId);
        assertThat(result.refreshToken().rawToken()).isNotEqualTo(firstToken.rawToken());
        assertThat(result.refreshToken().sessionId()).isEqualTo(session.id());

        // Access token issued via SPI
        assertThat(result.findAccessToken()).isPresent();
        assertThat(result.accessToken().token()).contains(subjectId.toString());

        // Old token is now consumed
        String oldHash = TokenHasher.hash(firstToken.rawToken());
        RefreshTokenRecord oldRecord = repository.findRefreshTokenByHash(oldHash).orElseThrow();
        assertThat(oldRecord.isConsumed()).isTrue();

        // Audit event emitted
        boolean rotatedAudited = auditEvents.stream()
                .anyMatch(e -> "TOKEN_ROTATED".equals(e.action()) && session.id().toString().equals(e.resourceId()));
        assertThat(rotatedAudited).isTrue();
    }

    @Test
    @DisplayName("rotate without AccessTokenIssuer leaves access token null")
    void rotateWithoutAccessTokenIssuer() {
        DefaultRefreshTokenRotation noIssuerRotation = new DefaultRefreshTokenRotation(
                repository, policy, null, auditBridge
        );
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());
        IssuedRefreshToken firstToken = noIssuerRotation.issue(session.id(), subjectId);

        RotationResult result = noIssuerRotation.rotate(firstToken.rawToken(), ClientMetadata.empty());

        assertThat(result.findAccessToken()).isEmpty();
        assertThat(result.accessToken()).isNull();
    }

    @Test
    @DisplayName("rotate rejects null, blank, or unknown token")
    void rotateRejectsInvalidTokenStrings() {
        assertThatThrownBy(() -> rotation.rotate(null, ClientMetadata.empty()))
                .isInstanceOf(InvalidRefreshTokenException.class);
        assertThatThrownBy(() -> rotation.rotate("   ", ClientMetadata.empty()))
                .isInstanceOf(InvalidRefreshTokenException.class);
        assertThatThrownBy(() -> rotation.rotate("unknown-raw-token-1234567890abcdef", ClientMetadata.empty()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    @DisplayName("rotate rejects expired refresh token")
    void rotateRejectsExpiredToken() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());

        String rawToken = "0123456789abcdef0123456789abcdef";
        String hash = TokenHasher.hash(rawToken);
        RefreshTokenRecord expiredToken = new RefreshTokenRecord(
                UUID.randomUUID(),
                session.id(),
                hash,
                Instant.now().minus(Duration.ofDays(10)),
                Instant.now().minus(Duration.ofDays(1)),
                null,
                null
        );
        repository.saveRefreshToken(expiredToken);

        assertThatThrownBy(() -> rotation.rotate(rawToken, ClientMetadata.empty()))
                .isInstanceOf(SessionExpiredException.class);
    }

    @Test
    @DisplayName("rotate rejects token for explicitly revoked session")
    void rotateRejectsRevokedSession() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());
        IssuedRefreshToken token = rotation.issue(session.id(), subjectId);

        sessionStore.revokeSession(session.id());

        assertThatThrownBy(() -> rotation.rotate(token.rawToken(), ClientMetadata.empty()))
                .isInstanceOf(SessionRevokedException.class);
    }

    @Test
    @DisplayName("revoke invalidates refresh token so subsequent rotate fails")
    void explicitRevocation() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());
        IssuedRefreshToken token = rotation.issue(session.id(), subjectId);

        rotation.revoke(token.rawToken());

        assertThatThrownBy(() -> rotation.rotate(token.rawToken(), ClientMetadata.empty()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    @DisplayName("rotate with long client metadata truncates and preserves session activity")
    void rotateWithLongMetadata() {
        UUID subjectId = UUID.randomUUID();
        Session session = sessionStore.createSession(subjectId, ClientMetadata.empty());
        IssuedRefreshToken token = rotation.issue(session.id(), subjectId);

        String longUa = "X".repeat(800);
        String longIp = "2".repeat(120);
        RotationResult result = rotation.rotate(token.rawToken(), ClientMetadata.of(longUa, longIp));

        assertThat(result).isNotNull();
        SessionRecord updated = repository.findSession(session.id()).orElseThrow();
        assertThat(updated.userAgent()).hasSize(512);
        assertThat(updated.ipAddress()).hasSize(64);
    }

    @Test
    @DisplayName("rotation within 15s transition grace window returns fresh AccessToken without revoking session")
    void rotationWithinGraceWindowReturnsAccessToken() {
        InMemorySessionRepository repoWithGrace = new InMemorySessionRepository(Duration.ofSeconds(15));
        DefaultRefreshTokenRotation rotationWithGrace = new DefaultRefreshTokenRotation(repoWithGrace, policy, tokenIssuer, auditBridge);
        DefaultSessionStore storeWithGrace = new DefaultSessionStore(repoWithGrace, policy, auditBridge);

        UUID subjectId = UUID.randomUUID();
        Session session = storeWithGrace.createSession(subjectId, ClientMetadata.empty());
        IssuedRefreshToken initialToken = rotationWithGrace.issue(session.id(), subjectId);

        // First rotation: consumes initialToken, sets transition_until
        RotationResult firstRotation = rotationWithGrace.rotate(initialToken.rawToken(), ClientMetadata.empty());
        assertThat(firstRotation.refreshToken()).isNotNull();
        assertThat(firstRotation.accessToken()).isNotNull();

        // Second rotation within 15s window using initialToken: returns fresh AccessToken without revoking!
        RotationResult graceResult = rotationWithGrace.rotate(initialToken.rawToken(), ClientMetadata.empty());
        assertThat(graceResult.sessionId()).isEqualTo(session.id());
        assertThat(graceResult.accessToken()).isNotNull();
        assertThat(graceResult.refreshToken()).isNull();

        // Session must still be active!
        assertThat(storeWithGrace.listActiveSessions(subjectId)).hasSize(1);
    }
}
