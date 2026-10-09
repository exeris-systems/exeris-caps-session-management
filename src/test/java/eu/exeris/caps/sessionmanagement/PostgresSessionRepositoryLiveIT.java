package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.internal.repository.PostgresSessionRepository;
import eu.exeris.caps.sessionmanagement.internal.repository.RefreshTokenRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.RotationExecutionResult;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRecord;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PostgresSessionRepository Live PostgreSQL Integration Tests")
class PostgresSessionRepositoryLiveIT {

    private static final String PG_URL = "jdbc:postgresql://localhost:5432/exeris_showroom";
    private static final String PG_USER = "exeris";
    private static final String PG_PASS = "exeris_password";
    private static final String TEST_SCHEMA = "test_session_mgmt_live";

    private static Connection jdbcConn;
    private static PostgresSessionRepository repository;

    @BeforeAll
    static void setUpDatabase() {
        try (Connection initConn = DriverManager.getConnection(PG_URL, PG_USER, PG_PASS);
             Statement stmt = initConn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            stmt.execute("CREATE SCHEMA " + TEST_SCHEMA);
        } catch (SQLException e) {
            Assumptions.abort("PostgreSQL not reachable at " + PG_URL + ": " + e.getMessage());
            return;
        }

        try {
            jdbcConn = DriverManager.getConnection(PG_URL + "?currentSchema=" + TEST_SCHEMA, PG_USER, PG_PASS);
            try (Statement stmt = jdbcConn.createStatement()) {
                try (InputStream is = PostgresSessionRepositoryLiveIT.class.getResourceAsStream("/schema/session-management-schema.sql")) {
                    if (is != null) {
                        String ddl = new String(is.readAllBytes(), StandardCharsets.UTF_8);
                        String cleanDdl = ddl.replaceAll("(?m)^--.*$", "");
                        for (String command : cleanDdl.split(";")) {
                            String trimmed = command.trim();
                            if (!trimmed.isEmpty()) {
                                stmt.execute(trimmed);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Assumptions.abort("Failed to initialize test schema on PostgreSQL: " + e.getMessage());
            return;
        }

        TransactionalExecutor tx = new TransactionalExecutor() {
            @Override
            public void execute(TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public void executeManaged(TransactionalWork work) {
                try {
                    PersistenceConnection conn = new JdbcPersistenceConnection(jdbcConn);
                    conn.beginTransaction();
                    work.run(conn);
                    conn.commit();
                } catch (Exception e) {
                    try {
                        jdbcConn.rollback();
                    } catch (SQLException ignored) {}
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
                executeManaged(work);
            }

            @Override
            public <T> T query(Function<PersistenceConnection, T> query) {
                try {
                    PersistenceConnection conn = new JdbcPersistenceConnection(jdbcConn);
                    return query.apply(conn);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };

        repository = new PostgresSessionRepository(tx);
    }

    @AfterAll
    static void tearDownDatabase() {
        if (jdbcConn != null) {
            try (Statement stmt = jdbcConn.createStatement()) {
                stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            } catch (SQLException ignored) {
            } finally {
                try {
                    jdbcConn.close();
                } catch (SQLException ignored) {}
            }
        }
    }

    @Test
    @DisplayName("session lifecycle on live PostgreSQL: save, find, list active, update activity, revoke")
    void sessionLifecycleLivePostgres() {
        UUID sessionId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Duration.ofDays(7));

        SessionRecord session = new SessionRecord(
                sessionId,
                subjectId,
                now,
                expiresAt,
                now,
                null,
                "LiveBrowser/1.0",
                "192.168.1.100"
        );

        // 1. Save session
        repository.saveSession(session);

        // 2. Find session
        Optional<SessionRecord> found = repository.findSession(sessionId);
        assertThat(found).isPresent();
        assertThat(found.get().id()).isEqualTo(sessionId);
        assertThat(found.get().subjectId()).isEqualTo(subjectId);
        assertThat(found.get().userAgent()).isEqualTo("LiveBrowser/1.0");
        assertThat(found.get().ipAddress()).isEqualTo("192.168.1.100");
        assertThat(found.get().revokedAt()).isNull();

        // 3. Find active sessions
        List<SessionRecord> active = repository.findActiveSessions(subjectId, now);
        assertThat(active).hasSize(1);
        assertThat(active.get(0).id()).isEqualTo(sessionId);

        // 4. Update activity
        Instant later = now.plusSeconds(300);
        repository.updateSessionActivity(sessionId, later, "UpdatedBrowser/2.0", "192.168.1.101");
        SessionRecord updated = repository.findSession(sessionId).orElseThrow();
        assertThat(updated.userAgent()).isEqualTo("UpdatedBrowser/2.0");
        assertThat(updated.ipAddress()).isEqualTo("192.168.1.101");

        // 5. Revoke session
        boolean revoked = repository.revokeSession(subjectId, sessionId, later);
        assertThat(revoked).isTrue();

        // 6. Active listing should now be empty
        assertThat(repository.findActiveSessions(subjectId, later)).isEmpty();
    }

    @Test
    @DisplayName("revokeAllSessionsForSubject on live PostgreSQL")
    void revokeAllForSubjectLivePostgres() {
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();

        SessionRecord s1 = new SessionRecord(UUID.randomUUID(), subjectId, now, now.plusSeconds(3600), now, null, "UA1", "IP1");
        SessionRecord s2 = new SessionRecord(UUID.randomUUID(), subjectId, now, now.plusSeconds(3600), now, null, "UA2", "IP2");

        repository.saveSession(s1);
        repository.saveSession(s2);

        assertThat(repository.findActiveSessions(subjectId, now)).hasSize(2);

        int count = repository.revokeAllSessionsForSubject(subjectId, now);
        assertThat(count).isEqualTo(2);

        assertThat(repository.findActiveSessions(subjectId, now)).isEmpty();
    }

    @Test
    @DisplayName("refresh token rotation and atomic replay detection on live PostgreSQL")
    void refreshTokenRotationAndReplayLivePostgres() {
        UUID sessionId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Duration.ofDays(7));

        SessionRecord session = new SessionRecord(
                sessionId,
                subjectId,
                now,
                expiresAt,
                now,
                null,
                "Client/1.0",
                "127.0.0.1"
        );
        repository.saveSession(session);

        UUID token1Id = UUID.randomUUID();
        String token1Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        RefreshTokenRecord token1 = new RefreshTokenRecord(
                token1Id,
                sessionId,
                token1Hash,
                now,
                expiresAt,
                null,
                null
        );
        repository.saveRefreshToken(token1);

        // 1. Find by hash
        Optional<RefreshTokenRecord> foundToken = repository.findRefreshTokenByHash(token1Hash);
        assertThat(foundToken).isPresent();
        assertThat(foundToken.get().id()).isEqualTo(token1Id);

        // 2. Rotate token1 -> token2
        UUID token2Id = UUID.randomUUID();
        String token2Hash = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        Instant rotatedAt = now.plusSeconds(60);

        RotationExecutionResult result1 = repository.executeRotation(
                token1Hash,
                token2Id,
                token2Hash,
                expiresAt,
                ClientMetadata.of("RotatedClient/1.0", "127.0.0.2"),
                rotatedAt
        );

        assertThat(result1).isInstanceOf(RotationExecutionResult.Success.class);
        RotationExecutionResult.Success success1 = (RotationExecutionResult.Success) result1;
        assertThat(success1.session().id()).isEqualTo(sessionId);
        assertThat(success1.newRefreshToken().id()).isEqualTo(token2Id);

        // Verify token1 is consumed
        RefreshTokenRecord consumedToken1 = repository.findRefreshTokenByHash(token1Hash).orElseThrow();
        assertThat(consumedToken1.isConsumed()).isTrue();

        // 3. Replay attack: present token1 again!
        UUID token3Id = UUID.randomUUID();
        String token3Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        RotationExecutionResult result2 = repository.executeRotation(
                token1Hash,
                token3Id,
                token3Hash,
                expiresAt,
                ClientMetadata.empty(),
                now.plusSeconds(120)
        );

        assertThat(result2).isInstanceOf(RotationExecutionResult.ReplayDetected.class);
        RotationExecutionResult.ReplayDetected replay = (RotationExecutionResult.ReplayDetected) result2;
        assertThat(replay.sessionId()).isEqualTo(sessionId);
        assertThat(replay.subjectId()).isEqualTo(subjectId);

        // Verify session is revoked
        SessionRecord revokedSession = repository.findSession(sessionId).orElseThrow();
        assertThat(revokedSession.isRevoked()).isTrue();

        // Verify token2 is also revoked
        RefreshTokenRecord revokedToken2 = repository.findRefreshTokenByHash(token2Hash).orElseThrow();
        assertThat(revokedToken2.isRevoked()).isTrue();

        // 4. Rotating token2 on revoked session returns SessionRevoked
        RotationExecutionResult result3 = repository.executeRotation(
                token2Hash,
                UUID.randomUUID(),
                "token3hash",
                expiresAt,
                ClientMetadata.empty(),
                now.plusSeconds(180)
        );
        assertThat(result3).isInstanceOf(RotationExecutionResult.SessionRevoked.class);
    }
}
