package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.internal.repository.PostgresSessionRepository;
import eu.exeris.caps.sessionmanagement.internal.repository.RefreshTokenRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.RotationExecutionResult;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRecord;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PostgresSessionRepository Unit Tests")
class PostgresSessionRepositoryTest {

    private CapturingTransactionalExecutor tx;
    private PostgresSessionRepository repository;

    @BeforeEach
    void setUp() {
        tx = new CapturingTransactionalExecutor();
        repository = new PostgresSessionRepository(tx);
    }

    @Test
    @DisplayName("saveSession executes managed insert with correct parameters")
    void saveSessionExecutesInsert() {
        UUID sessionId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(3600);

        SessionRecord session = new SessionRecord(
                sessionId,
                subjectId,
                now,
                expiresAt,
                now,
                null,
                "Mozilla/5.0",
                "192.168.1.10"
        );

        repository.saveSession(session);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("INSERT INTO sessions");
        assertThat(stmt.boundParameters.get(0)).isEqualTo(sessionId);
        assertThat(stmt.boundParameters.get(1)).isEqualTo(subjectId);
        assertThat(stmt.boundParameters.get(2)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(3)).isEqualTo(expiresAt);
        assertThat(stmt.boundParameters.get(4)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(5)).isNull();
        assertThat(stmt.boundParameters.get(6)).isEqualTo("Mozilla/5.0");
        assertThat(stmt.boundParameters.get(7)).isEqualTo("192.168.1.10");
    }

    @Test
    @DisplayName("findSession reads and maps row cursor correctly")
    void findSessionMapsRowCursor() {
        UUID sessionId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(86400);

        Object[] rowData = new Object[]{sessionId, subjectId, now, expiresAt, now, null, "Edge/12", "10.0.0.1"};
        tx.queryResultSupplier = () -> new StubQueryResult(java.util.Collections.singletonList(rowData));

        Optional<SessionRecord> result = repository.findSession(sessionId);

        assertThat(result).isPresent();
        SessionRecord session = result.get();
        assertThat(session.id()).isEqualTo(sessionId);
        assertThat(session.subjectId()).isEqualTo(subjectId);
        assertThat(session.userAgent()).isEqualTo("Edge/12");
        assertThat(session.ipAddress()).isEqualTo("10.0.0.1");
        assertThat(session.revokedAt()).isNull();
    }

    @Test
    @DisplayName("revokeSession executes update with revokedAt timestamp")
    void revokeSessionExecutesUpdate() {
        UUID sessionId = UUID.randomUUID();
        Instant now = Instant.now();
        tx.rowsAffectedResult = 1L;

        boolean revoked = repository.revokeSession(sessionId, now);

        assertThat(revoked).isTrue();
        assertThat(tx.executedStatements).hasSize(2);
        CapturingStatement tokenStmt = tx.executedStatements.get(0);
        assertThat(tokenStmt.sql).contains("UPDATE refresh_tokens SET revoked_at");
        assertThat(tokenStmt.boundParameters.get(0)).isEqualTo(now);
        assertThat(tokenStmt.boundParameters.get(1)).isEqualTo(sessionId);

        CapturingStatement sessionStmt = tx.executedStatements.get(1);
        assertThat(sessionStmt.sql).contains("UPDATE sessions SET revoked_at");
        assertThat(sessionStmt.boundParameters.get(0)).isEqualTo(now);
        assertThat(sessionStmt.boundParameters.get(1)).isEqualTo(sessionId);
    }

    @Test
    @DisplayName("executeRotation uses SELECT FOR UPDATE and returns Success when valid")
    void executeRotationSelectForUpdateSuccess() {
        UUID sessionId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        UUID oldTokenId = UUID.randomUUID();
        String oldHash = "oldhash123";
        Instant now = Instant.now();
        Instant tokenExpiresAt = now.plusSeconds(3600);
        Instant sessionExpiresAt = now.plusSeconds(7200);

        Object[] tokenRow = new Object[]{oldTokenId, sessionId, oldHash, now, tokenExpiresAt, null, null};
        Object[] sessionRow = new Object[]{sessionId, subjectId, now, sessionExpiresAt, now, null, "Safari", "1.2.3.4"};

        List<StubQueryResult> queryResults = new ArrayList<>();
        queryResults.add(new StubQueryResult(java.util.Collections.singletonList(tokenRow)));
        queryResults.add(new StubQueryResult(java.util.Collections.singletonList(sessionRow)));

        tx.multiQueryResultSupplier = queryResults;

        UUID newTokenId = UUID.randomUUID();
        String newHash = "newhash456";
        Instant newExpiresAt = now.plusSeconds(3600);

        RotationExecutionResult result = repository.executeRotation(
                oldHash,
                newTokenId,
                newHash,
                newExpiresAt,
                ClientMetadata.of("Safari-Updated", "1.2.3.5"),
                now
        );

        assertThat(result).isInstanceOf(RotationExecutionResult.Success.class);
        RotationExecutionResult.Success success = (RotationExecutionResult.Success) result;
        assertThat(success.session().id()).isEqualTo(sessionId);
        assertThat(success.newRefreshToken().id()).isEqualTo(newTokenId);

        // Verify SELECT FOR UPDATE was executed on refresh_tokens
        assertThat(tx.executedStatements.stream().anyMatch(s -> s.sql.contains("refresh_tokens WHERE token_hash = $1 FOR UPDATE"))).isTrue();
        // Verify SELECT FOR UPDATE was executed on sessions
        assertThat(tx.executedStatements.stream().anyMatch(s -> s.sql.contains("sessions WHERE id = $1 FOR UPDATE"))).isTrue();
    }

    @Test
    @DisplayName("executeRotation detects already consumed token as replay and revokes session")
    void executeRotationDetectsReplay() {
        UUID sessionId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        UUID oldTokenId = UUID.randomUUID();
        String oldHash = "replayedhash";
        Instant now = Instant.now();
        Instant consumedAt = now.minusSeconds(60);

        Object[] tokenRow = new Object[]{oldTokenId, sessionId, oldHash, now.minusSeconds(120), now.plusSeconds(3600), consumedAt, null};
        Object[] sessionRow = new Object[]{sessionId, subjectId, now.minusSeconds(120), now.plusSeconds(7200), now, null, "Safari", "1.2.3.4"};

        List<StubQueryResult> queryResults = new ArrayList<>();
        queryResults.add(new StubQueryResult(java.util.Collections.singletonList(tokenRow)));
        queryResults.add(new StubQueryResult(java.util.Collections.singletonList(sessionRow)));
        tx.multiQueryResultSupplier = queryResults;

        RotationExecutionResult result = repository.executeRotation(
                oldHash,
                UUID.randomUUID(),
                "newhash",
                now.plusSeconds(3600),
                ClientMetadata.empty(),
                now
        );

        assertThat(result).isInstanceOf(RotationExecutionResult.ReplayDetected.class);
        RotationExecutionResult.ReplayDetected replay = (RotationExecutionResult.ReplayDetected) result;
        assertThat(replay.sessionId()).isEqualTo(sessionId);
        assertThat(replay.subjectId()).isEqualTo(subjectId);

        // Verify revoke statement was triggered
        assertThat(tx.executedStatements.stream().anyMatch(s -> s.sql.contains("UPDATE sessions SET revoked_at = $1 WHERE id = $2"))).isTrue();
    }

    // =========================================================================
    // Test Doubles for TransactionalExecutor & Persistence SPI
    // =========================================================================

    private static final class CapturingTransactionalExecutor implements TransactionalExecutor {
        final List<CapturingStatement> executedStatements = new ArrayList<>();
        java.util.function.Supplier<QueryResult> queryResultSupplier;
        List<StubQueryResult> multiQueryResultSupplier;
        private int multiQueryIndex = 0;
        long rowsAffectedResult = 1L;

        @Override public void execute(TransactionalWork work) { work.run(new CapturingConnection(this)); }
        @Override public void executeManaged(TransactionalWork work) { work.run(new CapturingConnection(this)); }
        @Override public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) { work.run(new CapturingConnection(this)); }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            return query.apply(new CapturingConnection(this));
        }

        QueryResult nextQueryResult() {
            if (multiQueryResultSupplier != null && multiQueryIndex < multiQueryResultSupplier.size()) {
                return multiQueryResultSupplier.get(multiQueryIndex++);
            }
            if (queryResultSupplier != null) {
                return queryResultSupplier.get();
            }
            return new StubQueryResult(List.of());
        }
    }

    private static final class CapturingConnection implements PersistenceConnection {
        private final CapturingTransactionalExecutor executor;

        CapturingConnection(CapturingTransactionalExecutor executor) {
            this.executor = executor;
        }

        @Override
        public PersistenceStatement prepare(String sql) {
            CapturingStatement stmt = new CapturingStatement(sql, executor);
            executor.executedStatements.add(stmt);
            return stmt;
        }

        @Override public QueryResult executeQuery(String sql) { return null; }
        @Override public long executeUpdate(String sql) { return 0; }
        @Override public void beginTransaction() {}
        @Override public void beginTransaction(TransactionIsolation isolation, boolean readOnly) {}
        @Override public void commit() {}
        @Override public void rollback() {}
        @Override public boolean inTransaction() { return true; }
        @Override public boolean isOpen() { return true; }
        @Override public void close() {}
    }

    private static final class CapturingStatement implements PersistenceStatement {
        final String sql;
        final CapturingTransactionalExecutor executor;
        final Map<Integer, Object> boundParameters = new HashMap<>();

        CapturingStatement(String sql, CapturingTransactionalExecutor executor) {
            this.sql = sql;
            this.executor = executor;
        }

        @Override public PersistenceStatement bindInt(int index, int value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindLong(int index, long value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindShort(int index, short value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindFloat(int index, float value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindDouble(int index, double value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBoolean(int index, boolean value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindString(int index, String value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindUuid(int index, UUID value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBytes(int index, byte[] value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindInstant(int index, Instant value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindNull(int index) { boundParameters.put(index, null); return this; }

        @Override
        public QueryResult executeQuery() {
            return executor.nextQueryResult();
        }

        @Override
        public long executeUpdate() {
            return executor.rowsAffectedResult;
        }

        @Override
        public void close() {}
    }

    private static final class StubQueryResult implements QueryResult {
        private final List<Object[]> rows;
        private int cursor = -1;

        StubQueryResult(List<Object[]> rows) {
            this.rows = rows;
        }

        @Override
        public boolean next() {
            cursor++;
            return cursor < rows.size();
        }

        @Override
        public RowCursor row() {
            return new StubRowCursor(rows.get(cursor));
        }

        @Override public long rowsAffected() { return rows.size(); }
        @Override public int columnCount() { return rows.isEmpty() ? 0 : rows.get(0).length; }
        @Override public String commandTag() { return "SELECT"; }
        @Override public void close() {}
    }

    private static final class StubRowCursor implements RowCursor {
        private final Object[] values;

        StubRowCursor(Object[] values) {
            this.values = values;
        }

        @Override public int getInt(int column) { return (Integer) values[column]; }
        @Override public long getLong(int column) { return (Long) values[column]; }
        @Override public short getShort(int column) { return (Short) values[column]; }
        @Override public float getFloat(int column) { return (Float) values[column]; }
        @Override public double getDouble(int column) { return (Double) values[column]; }
        @Override public boolean getBoolean(int column) { return (Boolean) values[column]; }
        @Override public boolean isNull(int column) { return values[column] == null; }
        @Override public java.lang.foreign.MemorySegment getSegment(int column) { return null; }
        @Override public int getLength(int column) { return 0; }
        @Override public String getString(int column) { return (String) values[column]; }
        @Override public byte[] getBytes(int column) { return (byte[]) values[column]; }
        @Override public UUID getUuid(int column) { return (UUID) values[column]; }
        @Override public Instant getInstant(int column) { return (Instant) values[column]; }
        @Override public int columnCount() { return values.length; }
        @Override public boolean isValid() { return true; }
    }
}
