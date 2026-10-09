package eu.exeris.caps.sessionmanagement.internal.repository;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * PostgreSQL implementation of {@link SessionRepository} utilizing {@link TransactionalExecutor}
 * with pessimistic {@code SELECT FOR UPDATE} row-locking on refresh token rotation.
 *
 * @since 0.1.0
 */
public final class PostgresSessionRepository implements SessionRepository {

    public static final java.time.Duration DEFAULT_TRANSITION_GRACE_WINDOW = java.time.Duration.ofSeconds(15);

    private final TransactionalExecutor tx;
    private final java.time.Duration transitionGraceWindow;

    public PostgresSessionRepository(TransactionalExecutor tx) {
        this(tx, DEFAULT_TRANSITION_GRACE_WINDOW);
    }

    public PostgresSessionRepository(TransactionalExecutor tx, java.time.Duration transitionGraceWindow) {
        this.tx = Objects.requireNonNull(tx, "tx must not be null");
        this.transitionGraceWindow = Objects.requireNonNull(transitionGraceWindow, "transitionGraceWindow must not be null");
    }

    @Override
    public void saveSession(SessionRecord session) {
        Objects.requireNonNull(session, "session must not be null");
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO sessions (id, subject_id, created_at, expires_at, last_active_at, revoked_at, user_agent, ip_address, transition_until) " +
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")) {
                stmt.bindUuid(0, session.id())
                    .bindUuid(1, session.subjectId())
                    .bindInstant(2, session.createdAt())
                    .bindInstant(3, session.expiresAt())
                    .bindInstant(4, session.lastActiveAt());

                if (session.revokedAt() != null) {
                    stmt.bindInstant(5, session.revokedAt());
                } else {
                    stmt.bindNull(5);
                }

                if (session.userAgent() != null) {
                    stmt.bindString(6, session.userAgent());
                } else {
                    stmt.bindNull(6);
                }

                if (session.ipAddress() != null) {
                    stmt.bindString(7, session.ipAddress());
                } else {
                    stmt.bindNull(7);
                }

                if (session.transitionUntil() != null) {
                    stmt.bindInstant(8, session.transitionUntil());
                } else {
                    stmt.bindNull(8);
                }

                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<SessionRecord> findSession(UUID sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, created_at, expires_at, last_active_at, revoked_at, user_agent, ip_address, transition_until " +
                    "FROM sessions WHERE id = $1")) {
                stmt.bindUuid(0, sessionId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(mapSession(row));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public List<SessionRecord> findActiveSessions(UUID subjectId, Instant now) {
        if (subjectId == null) {
            return List.of();
        }
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, created_at, expires_at, last_active_at, revoked_at, user_agent, ip_address, transition_until " +
                    "FROM sessions " +
                    "WHERE subject_id = $1 AND revoked_at IS NULL AND expires_at > $2 " +
                    "ORDER BY created_at ASC, id ASC")) {
                stmt.bindUuid(0, subjectId)
                    .bindInstant(1, now);
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
    public boolean revokeSession(UUID sessionId, Instant revokedAt) {
        if (sessionId == null) {
            return false;
        }
        AtomicBoolean revoked = new AtomicBoolean(false);
        tx.executeManaged(conn -> {
            // Update refresh_tokens first, then sessions second (consistent lock order with executeRotation)
            try (PersistenceStatement tStmt = conn.prepare(
                    "UPDATE refresh_tokens SET revoked_at = $1 WHERE session_id = $2 AND revoked_at IS NULL")) {
                tStmt.bindInstant(0, revokedAt)
                     .bindUuid(1, sessionId);
                tStmt.executeUpdate();
            }

            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")) {
                stmt.bindInstant(0, revokedAt)
                    .bindUuid(1, sessionId);
                long updated = stmt.executeUpdate();
                if (updated > 0) {
                    revoked.set(true);
                }
            }
        });
        return revoked.get();
    }

    @Override
    public boolean revokeSession(UUID subjectId, UUID sessionId, Instant revokedAt) {
        if (sessionId == null) {
            return false;
        }
        if (subjectId == null) {
            return revokeSession(sessionId, revokedAt);
        }
        AtomicBoolean revoked = new AtomicBoolean(false);
        tx.executeManaged(conn -> {
            // Update refresh_tokens first, then sessions second
            try (PersistenceStatement tStmt = conn.prepare(
                    "UPDATE refresh_tokens SET revoked_at = $1 WHERE session_id = $2 AND revoked_at IS NULL")) {
                tStmt.bindInstant(0, revokedAt)
                     .bindUuid(1, sessionId);
                tStmt.executeUpdate();
            }

            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND subject_id = $3 AND revoked_at IS NULL")) {
                stmt.bindInstant(0, revokedAt)
                    .bindUuid(1, sessionId)
                    .bindUuid(2, subjectId);
                long updated = stmt.executeUpdate();
                if (updated > 0) {
                    revoked.set(true);
                }
            }
        });
        return revoked.get();
    }

    @Override
    public int revokeAllSessionsForSubject(UUID subjectId, Instant revokedAt) {
        if (subjectId == null) {
            return 0;
        }
        AtomicInteger affected = new AtomicInteger(0);
        tx.executeManaged(conn -> {
            try (PersistenceStatement tStmt = conn.prepare(
                    "UPDATE refresh_tokens SET revoked_at = $1 " +
                    "WHERE session_id IN (SELECT id FROM sessions WHERE subject_id = $2 AND revoked_at IS NULL) " +
                    "AND revoked_at IS NULL")) {
                tStmt.bindInstant(0, revokedAt)
                     .bindUuid(1, subjectId);
                tStmt.executeUpdate();
            }

            try (PersistenceStatement sStmt = conn.prepare(
                    "UPDATE sessions SET revoked_at = $1 WHERE subject_id = $2 AND revoked_at IS NULL")) {
                sStmt.bindInstant(0, revokedAt)
                     .bindUuid(1, subjectId);
                affected.set((int) sStmt.executeUpdate());
            }
        });
        return affected.get();
    }

    @Override
    public void updateSessionActivity(UUID sessionId, Instant lastActiveAt, String userAgent, String ipAddress) {
        String ua = userAgent != null && userAgent.length() > 512 ? userAgent.substring(0, 512) : userAgent;
        String ip = ipAddress != null && ipAddress.length() > 64 ? ipAddress.substring(0, 64) : ipAddress;
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE sessions SET last_active_at = $1, " +
                    "user_agent = COALESCE($2, user_agent), " +
                    "ip_address = COALESCE($3, ip_address) " +
                    "WHERE id = $4")) {
                stmt.bindInstant(0, lastActiveAt);
                if (ua != null) {
                    stmt.bindString(1, ua);
                } else {
                    stmt.bindNull(1);
                }
                if (ip != null) {
                    stmt.bindString(2, ip);
                } else {
                    stmt.bindNull(2);
                }
                stmt.bindUuid(3, sessionId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public void saveRefreshToken(RefreshTokenRecord token) {
        Objects.requireNonNull(token, "token must not be null");
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, transition_until) " +
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")) {
                stmt.bindUuid(0, token.id())
                    .bindUuid(1, token.sessionId())
                    .bindString(2, token.tokenHash())
                    .bindInstant(3, token.createdAt())
                    .bindInstant(4, token.expiresAt());

                if (token.consumedAt() != null) {
                    stmt.bindInstant(5, token.consumedAt());
                } else {
                    stmt.bindNull(5);
                }

                if (token.revokedAt() != null) {
                    stmt.bindInstant(6, token.revokedAt());
                } else {
                    stmt.bindNull(6);
                }

                if (token.transitionUntil() != null) {
                    stmt.bindInstant(7, token.transitionUntil());
                } else {
                    stmt.bindNull(7);
                }

                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<RefreshTokenRecord> findRefreshTokenByHash(String tokenHash) {
        if (tokenHash == null) {
            return Optional.empty();
        }
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, transition_until " +
                    "FROM refresh_tokens WHERE token_hash = $1")) {
                stmt.bindString(0, tokenHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(mapRefreshToken(row));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public boolean revokeRefreshToken(String tokenHash, Instant revokedAt) {
        if (tokenHash == null) {
            return false;
        }
        AtomicBoolean affected = new AtomicBoolean(false);
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE refresh_tokens SET revoked_at = $1 WHERE token_hash = $2 AND revoked_at IS NULL")) {
                stmt.bindInstant(0, revokedAt)
                    .bindString(1, tokenHash);
                affected.set(stmt.executeUpdate() > 0);
            }
        });
        return affected.get();
    }

    @Override
    public void revokeAllRefreshTokensForSession(UUID sessionId, Instant revokedAt) {
        if (sessionId == null) {
            return;
        }
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE refresh_tokens SET revoked_at = $1 WHERE session_id = $2 AND revoked_at IS NULL")) {
                stmt.bindInstant(0, revokedAt)
                    .bindUuid(1, sessionId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public RotationExecutionResult executeRotation(
            String oldTokenHash,
            UUID newTokenId,
            String newTokenHash,
            Instant newExpiresAt,
            ClientMetadata metadata,
            Instant now
    ) {
        AtomicReference<RotationExecutionResult> resultRef = new AtomicReference<>();
        tx.executeManaged(conn -> {
            // 1. Pessimistic lock on the presented refresh token
            RefreshTokenRecord token;
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, transition_until " +
                    "FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE")) {
                stmt.bindString(0, oldTokenHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (!rs.next()) {
                        resultRef.set(new RotationExecutionResult.TokenNotFound());
                        return;
                    }
                    token = mapRefreshToken(rs.row());
                }
            }

            // 2. Pessimistic lock on the associated session
            SessionRecord session;
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, created_at, expires_at, last_active_at, revoked_at, user_agent, ip_address, transition_until " +
                    "FROM sessions WHERE id = $1 FOR UPDATE")) {
                stmt.bindUuid(0, token.sessionId());
                try (QueryResult rs = stmt.executeQuery()) {
                    if (!rs.next()) {
                        resultRef.set(new RotationExecutionResult.SessionNotFound(token.sessionId()));
                        return;
                    }
                    session = mapSession(rs.row());
                }
            }

            // 3. Replay attack verification: token has already been consumed
            if (token.isConsumed()) {
                Instant effectiveGraceUntil = token.transitionUntil() != null
                        ? token.transitionUntil()
                        : (token.consumedAt() != null && !transitionGraceWindow.isZero()
                            ? token.consumedAt().plus(transitionGraceWindow)
                            : null);

                if (effectiveGraceUntil != null && now.isBefore(effectiveGraceUntil) && session.isActive(now)) {
                    // Grace window active: SPA stampede protection
                    resultRef.set(new RotationExecutionResult.GraceWindow(session));
                    return;
                }

                // Immediately revoke session and all refresh tokens
                // Update refresh_tokens first, then sessions second (consistent lock order)
                try (PersistenceStatement tStmt = conn.prepare(
                        "UPDATE refresh_tokens SET revoked_at = $1 WHERE session_id = $2 AND revoked_at IS NULL")) {
                    tStmt.bindInstant(0, now).bindUuid(1, session.id());
                    tStmt.executeUpdate();
                }
                try (PersistenceStatement sStmt = conn.prepare(
                        "UPDATE sessions SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL")) {
                    sStmt.bindInstant(0, now).bindUuid(1, session.id());
                    sStmt.executeUpdate();
                }
                resultRef.set(new RotationExecutionResult.ReplayDetected(session.id(), session.subjectId()));
                return;
            }

            // Check session status first
            if (session.isRevoked()) {
                resultRef.set(new RotationExecutionResult.SessionRevoked(session.id()));
                return;
            }

            if (token.isRevoked()) {
                resultRef.set(new RotationExecutionResult.TokenRevoked(session.id()));
                return;
            }

            if (session.isExpired(now)) {
                resultRef.set(new RotationExecutionResult.SessionExpired(session.id()));
                return;
            }

            if (token.isExpired(now)) {
                resultRef.set(new RotationExecutionResult.TokenExpired(session.id()));
                return;
            }

            Instant graceUntil = !transitionGraceWindow.isZero() ? now.plus(transitionGraceWindow) : null;

            // 4. Mark old token as consumed with transition_until
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE refresh_tokens SET consumed_at = $1, transition_until = $2 WHERE id = $3")) {
                stmt.bindInstant(0, now);
                if (graceUntil != null) {
                    stmt.bindInstant(1, graceUntil);
                } else {
                    stmt.bindNull(1);
                }
                stmt.bindUuid(2, token.id());
                stmt.executeUpdate();
            }

            // 5. Insert new token
            try (PersistenceStatement stmt = conn.prepare(
                    "INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, transition_until) " +
                    "VALUES ($1, $2, $3, $4, $5, NULL, NULL, NULL)")) {
                stmt.bindUuid(0, newTokenId)
                    .bindUuid(1, token.sessionId())
                    .bindString(2, newTokenHash)
                    .bindInstant(3, now)
                    .bindInstant(4, newExpiresAt);
                stmt.executeUpdate();
            }

            // 6. Update session last_active_at, transition_until and optional metadata
            String ua = metadata != null && metadata.userAgent() != null ? metadata.userAgent() : session.userAgent();
            String ip = metadata != null && metadata.ipAddress() != null ? metadata.ipAddress() : session.ipAddress();
            if (ua != null && ua.length() > 512) {
                ua = ua.substring(0, 512);
            }
            if (ip != null && ip.length() > 64) {
                ip = ip.substring(0, 64);
            }
            try (PersistenceStatement stmt = conn.prepare(
                    "UPDATE sessions SET last_active_at = $1, transition_until = $2, " +
                    "user_agent = COALESCE($3, user_agent), " +
                    "ip_address = COALESCE($4, ip_address) " +
                    "WHERE id = $5")) {
                stmt.bindInstant(0, now);
                if (graceUntil != null) {
                    stmt.bindInstant(1, graceUntil);
                } else {
                    stmt.bindNull(1);
                }
                if (ua != null) {
                    stmt.bindString(2, ua);
                } else {
                    stmt.bindNull(2);
                }
                if (ip != null) {
                    stmt.bindString(3, ip);
                } else {
                    stmt.bindNull(3);
                }
                stmt.bindUuid(4, session.id());
                stmt.executeUpdate();
            }

            SessionRecord updatedSession = new SessionRecord(
                    session.id(),
                    session.subjectId(),
                    session.createdAt(),
                    session.expiresAt(),
                    now,
                    null,
                    ua,
                    ip,
                    graceUntil
            );

            RefreshTokenRecord newRecord = new RefreshTokenRecord(
                    newTokenId,
                    token.sessionId(),
                    newTokenHash,
                    now,
                    newExpiresAt,
                    null,
                    null,
                    null
            );

            resultRef.set(new RotationExecutionResult.Success(updatedSession, newRecord));
        });
        return resultRef.get();
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
                row.getString(7),
                row.columnCount() > 8 && !row.isNull(8) ? row.getInstant(8) : null
        );
    }

    private static RefreshTokenRecord mapRefreshToken(RowCursor row) {
        return new RefreshTokenRecord(
                row.getUuid(0),
                row.getUuid(1),
                row.getString(2),
                row.getInstant(3),
                row.getInstant(4),
                row.isNull(5) ? null : row.getInstant(5),
                row.isNull(6) ? null : row.getInstant(6),
                row.columnCount() > 7 && !row.isNull(7) ? row.getInstant(7) : null
        );
    }
}
