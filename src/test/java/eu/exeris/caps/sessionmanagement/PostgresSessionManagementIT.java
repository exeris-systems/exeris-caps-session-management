package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.caps.sessionmanagement.internal.crypto.TokenHasher;
import eu.exeris.caps.sessionmanagement.internal.repository.PostgresSessionRepository;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Binds the session-management contract to live PostgreSQL, applying {@link SessionManagementModule#MIGRATIONS}. Each unit of work
 * gets its own connection, so the concurrency cases contend on real row locks.
 */
@Tag("integration")
@Testcontainers(disabledWithoutDocker = true)
@DisplayName("Session management contract — live PostgreSQL")
class PostgresSessionManagementIT extends AbstractSessionManagementContractTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16");

    @BeforeAll
    static void applyMigrations() throws SQLException {
        try (Connection c = open(); Statement stmt = c.createStatement()) {
            for (String migration : SessionManagementModule.MIGRATIONS) {
                stmt.execute(readResource(migration));
            }
        }
    }

    @Override
    protected SessionRepository newRepository() {
        try (Connection c = open(); Statement stmt = c.createStatement()) {
            stmt.execute("TRUNCATE refresh_tokens, sessions");
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        return new PostgresSessionRepository(new PerCallTransactionalExecutor());
    }

    @Test
    @DisplayName("only the SHA-256 hash of a refresh token reaches the database")
    void refreshTokensAreStoredHashed() throws SQLException {
        UUID subject = UUID.randomUUID();
        Session session = store.createSession(subject, ClientMetadata.empty());
        IssuedRefreshToken issued = rotation.issue(session.id(), subject);

        try (Connection c = open(); Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT token_hash FROM refresh_tokens")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getString(1))
                    .isEqualTo(TokenHasher.hash(issued.rawToken()))
                    .isNotEqualTo(issued.rawToken());
            assertThat(rs.next()).isFalse();
        }
    }

    @Test
    @DisplayName("a reuse-triggered revocation is committed and records its reason")
    void reuseRevocationIsDurable() throws SQLException {
        UUID subject = UUID.randomUUID();
        Session session = store.createSession(subject, ClientMetadata.empty());
        IssuedRefreshToken issued = rotation.issue(session.id(), subject);
        rotation.rotate(issued.rawToken(), ClientMetadata.empty());
        rotation.rotate(issued.rawToken(), ClientMetadata.empty());

        try (Connection c = open(); Statement stmt = c.createStatement();
             ResultSet rs = stmt.executeQuery(
                     "SELECT s.revocation_reason, count(t.*) FILTER (WHERE t.revoked_at IS NULL) "
                             + "FROM sessions s JOIN refresh_tokens t ON t.session_id = s.id GROUP BY s.revocation_reason")) {
            assertThat(rs.next()).isTrue();
            assertThat(rs.getString(1)).isEqualTo("REFRESH_TOKEN_REUSE");
            assertThat(rs.getLong(2)).isZero();
        }
    }

    private static Connection open() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    private static String readResource(String path) {
        try (InputStream in = PostgresSessionManagementIT.class.getClassLoader().getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException(path + " is not on the classpath");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** One JDBC connection per unit of work, committed or rolled back before it is closed. */
    private static final class PerCallTransactionalExecutor implements TransactionalExecutor {

        @Override
        public void execute(TransactionalWork work) {
            executeManaged(work);
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            try (Connection jdbc = open()) {
                PersistenceConnection conn = new JdbcPersistenceConnection(jdbc);
                conn.beginTransaction();
                try {
                    work.run(conn);
                    conn.commit();
                } catch (RuntimeException e) {
                    conn.rollback();
                    throw e;
                }
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            executeManaged(work);
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            try (Connection jdbc = open()) {
                return query.apply(new JdbcPersistenceConnection(jdbc));
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
