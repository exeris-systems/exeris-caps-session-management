package eu.exeris.caps.sessionmanagement.internal.repository;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome.Reason;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * PostgreSQL {@link SessionRepository} over the kernel Persistence SPI. The schema is the
 * migration list {@link eu.exeris.caps.sessionmanagement.SessionManagementModule#MIGRATIONS}.
 *
 * <p>Every statement numbers its placeholders {@code $1..$n} in ascending order, each used once: the
 * Community binding rewrites {@code $n} to a positional {@code ?}, so a repeated or out-of-order
 * placeholder would bind the wrong value.
 *
 * <p>Lock order, in every transaction that knows its subject up front: the subject's advisory lock
 * ({@link #lockSubject}), then the subject's {@code sessions} rows ordered by {@code created_at DESC, id DESC},
 * then those sessions' {@code refresh_tokens} rows. A transaction that starts from a refresh token
 * ({@link #rotate}, {@link #revokeFamilyByTokenHash}) cannot know the subject before it has a row, so it
 * takes the one {@code sessions} row, then its tokens, and never waits for a second session row; it
 * cannot close a cycle with the transactions above.
 *
 * <p>The advisory lock is what makes the per-subject session limit hold: the rows that a concurrent
 * sign-in would have to lock to be counted do not exist until it inserts them, so row locks alone let
 * two sign-ins both count below the limit and both insert.
 *
 * @since 0.1.0
 */
public final class PostgresSessionRepository implements SessionRepository {

    /**
     * First key of the two-key advisory lock taken per subject. Fixed, so that it names this capability's
     * lock space and does not collide with advisory locks taken by other capabilities on the same database.
     */
    static final int SUBJECT_LOCK_NAMESPACE = 0x53455353;

    private static final String SUBJECT_REQUIRED = "subjectId must not be null";

    private static final String SESSION_COLUMNS =
            "id, subject_id, created_at, expires_at, last_active_at, revoked_at, user_agent, ip_address";

    private final TransactionalExecutor tx;

    public PostgresSessionRepository(TransactionalExecutor tx) {
        this.tx = Objects.requireNonNull(tx, "tx must not be null");
    }

    @Override
    public List<UUID> createSession(SessionRecord session, int maxActive, Duration idleTimeout) {
        Objects.requireNonNull(session, "session must not be null");
        Instant now = session.createdAt();
        Instant idleCutoff = now.minus(idleTimeout);
        List<UUID> evicted = new ArrayList<>();
        tx.executeManaged(conn -> {
            lockSubject(conn, session.subjectId());
            List<UUID> active = new ArrayList<>();
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id FROM sessions "
                            + "WHERE subject_id = $1 AND revoked_at IS NULL AND expires_at > $2 AND last_active_at > $3 "
                            + "ORDER BY created_at DESC, id DESC FOR UPDATE")) {
                stmt.bindUuid(0, session.subjectId()).bindInstant(1, now).bindInstant(2, idleCutoff);
                try (QueryResult rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        active.add(rs.row().getUuid(0));
                    }
                }
            }
            for (int i = maxActive - 1; i < active.size(); i++) {
                UUID victim = active.get(i);
                revokeFamily(conn, victim, now, RevocationReason.EVICTED);
                evicted.add(victim);
            }
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO sessions (" + SESSION_COLUMNS + ", revocation_reason) "
                            + "VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, NULL)")) {
                stmt.bindUuid(0, session.id())
                        .bindUuid(1, session.subjectId())
                        .bindInstant(2, session.createdAt())
                        .bindInstant(3, session.expiresAt())
                        .bindInstant(4, session.lastActiveAt());
                bindNullableString(stmt, 5, session.userAgent());
                bindNullableString(stmt, 6, session.ipAddress());
                stmt.executeUpdate();
            }
        });
        return List.copyOf(evicted);
    }

    @Override
    public List<SessionRecord> findActiveSessions(UUID subjectId, Instant now, Duration idleTimeout) {
        Objects.requireNonNull(subjectId, SUBJECT_REQUIRED);
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT " + SESSION_COLUMNS + " FROM sessions "
                            + "WHERE subject_id = $1 AND revoked_at IS NULL AND expires_at > $2 AND last_active_at > $3 "
                            + "ORDER BY created_at ASC, id ASC")) {
                stmt.bindUuid(0, subjectId).bindInstant(1, now).bindInstant(2, now.minus(idleTimeout));
                try (QueryResult rs = stmt.executeQuery()) {
                    List<SessionRecord> list = new ArrayList<>();
                    while (rs.next()) {
                        list.add(mapSession(rs.row()));
                    }
                    return list;
                }
            }
        });
    }

    @Override
    public boolean revokeSession(UUID subjectId, UUID sessionId, Instant now, RevocationReason reason) {
        Objects.requireNonNull(subjectId, SUBJECT_REQUIRED);
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        AtomicInteger revoked = new AtomicInteger();
        tx.executeManaged(conn -> {
            lockSubject(conn, subjectId);
            long updated;
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE sessions SET revoked_at = $1, revocation_reason = $2 "
                            + "WHERE id = $3 AND subject_id = $4 AND revoked_at IS NULL")) {
                stmt.bindInstant(0, now).bindString(1, reason.name()).bindUuid(2, sessionId).bindUuid(3, subjectId);
                updated = stmt.executeUpdate();
            }
            if (updated > 0) {
                revokeTokensOfSession(conn, sessionId, now);
                revoked.set((int) updated);
            }
        });
        return revoked.get() > 0;
    }

    @Override
    public int revokeAllSessions(UUID subjectId, Instant now, RevocationReason reason) {
        Objects.requireNonNull(subjectId, SUBJECT_REQUIRED);
        AtomicInteger revoked = new AtomicInteger();
        tx.executeManaged(conn -> {
            lockSubject(conn, subjectId);
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id FROM sessions WHERE subject_id = $1 AND revoked_at IS NULL "
                            + "ORDER BY created_at DESC, id DESC FOR UPDATE")) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        // rows are held, in the documented order, until the transaction ends
                    }
                }
            }
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE sessions SET revoked_at = $1, revocation_reason = $2 "
                            + "WHERE subject_id = $3 AND revoked_at IS NULL")) {
                stmt.bindInstant(0, now).bindString(1, reason.name()).bindUuid(2, subjectId);
                revoked.set((int) stmt.executeUpdate());
            }
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE refresh_tokens SET revoked_at = $1 "
                            + "WHERE revoked_at IS NULL AND session_id IN (SELECT id FROM sessions WHERE subject_id = $2)")) {
                stmt.bindInstant(0, now).bindUuid(1, subjectId);
                stmt.executeUpdate();
            }
        });
        return revoked.get();
    }

    @Override
    public IssueResult issueFirstToken(UUID subjectId, RefreshTokenRecord token, Instant now, Duration idleTimeout) {
        Objects.requireNonNull(subjectId, SUBJECT_REQUIRED);
        Objects.requireNonNull(token, "token must not be null");
        AtomicReference<IssueResult> result = new AtomicReference<>();
        tx.executeManaged(conn -> {
            lockSubject(conn, subjectId);
            Optional<SessionRecord> locked = lockSession(conn, token.sessionId());
            if (locked.isEmpty() || !locked.get().subjectId().equals(subjectId)) {
                result.set(IssueResult.refused(IssueResult.Status.SESSION_NOT_FOUND));
                return;
            }
            SessionRecord session = locked.get();
            if (session.isRevoked()) {
                result.set(IssueResult.refused(IssueResult.Status.SESSION_REVOKED));
                return;
            }
            if (session.isExpired(now) || session.isIdle(now.minus(idleTimeout))) {
                result.set(IssueResult.refused(IssueResult.Status.SESSION_EXPIRED));
                return;
            }
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT 1 FROM refresh_tokens WHERE session_id = $1 LIMIT 1")) {
                stmt.bindUuid(0, session.id());
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        result.set(IssueResult.refused(IssueResult.Status.ALREADY_ISSUED));
                        return;
                    }
                }
            }
            Instant expiresAt = tokenExpiry(session, now, idleTimeout);
            insertToken(conn, token.id(), session.id(), token.tokenHash(), now, expiresAt);
            result.set(IssueResult.issued(expiresAt));
        });
        return result.get();
    }

    @Override
    public RotationExecutionResult rotate(
            String presentedHash,
            UUID newTokenId,
            String newTokenHash,
            ClientMetadata metadata,
            Instant now,
            Duration idleTimeout
    ) {
        Objects.requireNonNull(presentedHash, "presentedHash must not be null");
        AtomicReference<RotationExecutionResult> result = new AtomicReference<>();
        tx.executeManaged(conn -> result.set(rotateInTransaction(
                conn, presentedHash, newTokenId, newTokenHash, metadata, now, idleTimeout)));
        return result.get();
    }

    private static RotationExecutionResult endedByTime(SessionRecord session, boolean tokenConsumed, Reason reason) {
        return tokenConsumed
                ? new RotationExecutionResult.ReplayRejected(reason, session.id(), session.subjectId())
                : new RotationExecutionResult.Rejected(reason);
    }

    private static RotationExecutionResult rotateInTransaction(
            PersistenceConnection conn,
            String presentedHash,
            UUID newTokenId,
            String newTokenHash,
            ClientMetadata metadata,
            Instant now,
            Duration idleTimeout
    ) {
        // 1. Lock the family: the session row the presented token belongs to.
        UUID tokenId;
        SessionRecord session;
        boolean tokenConsumed;
        try (PersistenceStatement stmt = conn.prepare(
                "SELECT t.id, s.id, s.subject_id, s.created_at, s.expires_at, s.last_active_at, s.revoked_at, "
                        + "s.user_agent, s.ip_address, t.consumed_at IS NOT NULL "
                        + "FROM refresh_tokens t JOIN sessions s ON s.id = t.session_id "
                        + "WHERE t.token_hash = $1 FOR UPDATE OF s")) {
            stmt.bindString(0, presentedHash);
            try (QueryResult rs = stmt.executeQuery()) {
                if (!rs.next()) {
                    return new RotationExecutionResult.Rejected(Reason.UNKNOWN_TOKEN);
                }
                RowCursor row = rs.row();
                tokenId = row.getUuid(0);
                session = new SessionRecord(
                        row.getUuid(1),
                        row.getUuid(2),
                        row.getInstant(3),
                        row.getInstant(4),
                        row.getInstant(5),
                        row.isNull(6) ? null : row.getInstant(6),
                        row.getString(7),
                        row.getString(8));
                tokenConsumed = row.getBoolean(9);
            }
        }

        // 2. A session that has ended refuses every token and consumes none.
        if (session.isRevoked()) {
            return new RotationExecutionResult.Rejected(Reason.SESSION_REVOKED);
        }
        // A revoked session is the ordinary aftermath of a detected reuse or a sign-out and is not reported
        // again; a consumed token presented to a session that merely ended by time is still a replay.
        if (session.isExpired(now)) {
            return endedByTime(session, tokenConsumed, Reason.SESSION_EXPIRED);
        }
        if (session.isIdle(now.minus(idleTimeout))) {
            return endedByTime(session, tokenConsumed, Reason.SESSION_IDLE);
        }

        // 3. Consume: the single conditional write that decides which presentation wins.
        long claimed;
        try (PersistenceStatement stmt = conn.prepare(
                "UPDATE refresh_tokens SET consumed_at = $1 "
                        + "WHERE id = $2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $3")) {
            stmt.bindInstant(0, now).bindUuid(1, tokenId).bindInstant(2, now);
            claimed = stmt.executeUpdate();
        }

        if (claimed == 0) {
            boolean consumed;
            boolean revoked;
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT consumed_at IS NOT NULL, revoked_at IS NOT NULL FROM refresh_tokens WHERE id = $1")) {
                stmt.bindUuid(0, tokenId);
                try (QueryResult rs = stmt.executeQuery()) {
                    rs.next();
                    consumed = rs.row().getBoolean(0);
                    revoked = rs.row().getBoolean(1);
                }
            }
            if (consumed) {
                revokeFamily(conn, session.id(), now, RevocationReason.REFRESH_TOKEN_REUSE);
                return new RotationExecutionResult.ReuseDetected(session.id(), session.subjectId());
            }
            return new RotationExecutionResult.Rejected(revoked ? Reason.TOKEN_REVOKED : Reason.TOKEN_EXPIRED);
        }

        // 4. Store the successor and record the activity.
        insertToken(conn, newTokenId, session.id(), newTokenHash, now, tokenExpiry(session, now, idleTimeout));

        String ua = metadata != null && metadata.userAgent() != null ? metadata.userAgent() : session.userAgent();
        String ip = metadata != null && metadata.ipAddress() != null ? metadata.ipAddress() : session.ipAddress();
        try (PersistenceStatement stmt = conn.prepare(
                "UPDATE sessions SET last_active_at = $1, user_agent = $2, ip_address = $3 WHERE id = $4")) {
            stmt.bindInstant(0, now);
            bindNullableString(stmt, 1, ua);
            bindNullableString(stmt, 2, ip);
            stmt.bindUuid(3, session.id());
            stmt.executeUpdate();
        }
        return new RotationExecutionResult.Rotated(new SessionRecord(
                session.id(), session.subjectId(), session.createdAt(), session.expiresAt(), now, null, ua, ip));
    }

    @Override
    public Optional<FamilyRevocation> revokeFamilyByTokenHash(String tokenHash, Instant now, RevocationReason reason) {
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        AtomicReference<FamilyRevocation> result = new AtomicReference<>();
        tx.executeManaged(conn -> {
            UUID sessionId;
            UUID subjectId;
            boolean alreadyRevoked;
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT s.id, s.subject_id, s.revoked_at IS NOT NULL "
                            + "FROM refresh_tokens t JOIN sessions s ON s.id = t.session_id "
                            + "WHERE t.token_hash = $1 FOR UPDATE OF s")) {
                stmt.bindString(0, tokenHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (!rs.next()) {
                        return;
                    }
                    sessionId = rs.row().getUuid(0);
                    subjectId = rs.row().getUuid(1);
                    alreadyRevoked = rs.row().getBoolean(2);
                }
            }
            if (!alreadyRevoked) {
                revokeFamily(conn, sessionId, now, reason);
                result.set(new FamilyRevocation(sessionId, subjectId));
            }
        });
        return Optional.ofNullable(result.get());
    }

    /**
     * Serialises every transaction that counts or changes one subject's sessions, until it ends. The key is
     * derived from the subject alone because sessions carry no tenant.
     */
    private static void lockSubject(PersistenceConnection conn, UUID subjectId) {
        try (PersistenceStatement stmt = conn.prepare("SELECT pg_advisory_xact_lock($1, hashtext($2))")) {
            stmt.bindInt(0, SUBJECT_LOCK_NAMESPACE).bindString(1, subjectId.toString());
            try (QueryResult rs = stmt.executeQuery()) {
                rs.next();
            }
        }
    }

    private static Optional<SessionRecord> lockSession(PersistenceConnection conn, UUID sessionId) {
        try (PersistenceStatement stmt = conn.prepare(
                "SELECT " + SESSION_COLUMNS + " FROM sessions WHERE id = $1 FOR UPDATE")) {
            stmt.bindUuid(0, sessionId);
            try (QueryResult rs = stmt.executeQuery()) {
                return rs.next() ? Optional.of(mapSession(rs.row())) : Optional.empty();
            }
        }
    }

    /** Revokes a session and then its tokens; the caller holds or takes the session row first. */
    private static void revokeFamily(PersistenceConnection conn, UUID sessionId, Instant now, RevocationReason reason) {
        try (PersistenceStatement stmt = conn.prepare(
                "UPDATE sessions SET revoked_at = $1, revocation_reason = $2 WHERE id = $3 AND revoked_at IS NULL")) {
            stmt.bindInstant(0, now).bindString(1, reason.name()).bindUuid(2, sessionId);
            stmt.executeUpdate();
        }
        revokeTokensOfSession(conn, sessionId, now);
    }

    private static void revokeTokensOfSession(PersistenceConnection conn, UUID sessionId, Instant now) {
        try (PersistenceStatement stmt = conn.prepare(
                "UPDATE refresh_tokens SET revoked_at = $1 WHERE session_id = $2 AND revoked_at IS NULL")) {
            stmt.bindInstant(0, now).bindUuid(1, sessionId);
            stmt.executeUpdate();
        }
    }

    private static void insertToken(
            PersistenceConnection conn, UUID id, UUID sessionId, String tokenHash, Instant now, Instant expiresAt) {
        try (PersistenceStatement stmt = conn.prepare(
                "INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at) "
                        + "VALUES ($1, $2, $3, $4, $5, NULL, NULL)")) {
            stmt.bindUuid(0, id)
                    .bindUuid(1, sessionId)
                    .bindString(2, tokenHash)
                    .bindInstant(3, now)
                    .bindInstant(4, expiresAt);
            stmt.executeUpdate();
        }
    }

    /** A refresh token never outlives its session's idle window or absolute lifetime. */
    private static Instant tokenExpiry(SessionRecord session, Instant now, Duration idleTimeout) {
        return session.tokenExpiry(now, idleTimeout);
    }

    private static void bindNullableString(PersistenceStatement stmt, int index, String value) {
        if (value != null) {
            stmt.bindString(index, value);
        } else {
            stmt.bindNull(index);
        }
    }

    private static SessionRecord mapSession(RowCursor row) {
        return new SessionRecord(
                row.getUuid(0),
                row.getUuid(1),
                row.getInstant(2),
                row.getInstant(3),
                row.getInstant(4),
                row.isNull(5) ? null : row.getInstant(5),
                row.getString(6),
                row.getString(7)
        );
    }
}
