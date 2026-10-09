package eu.exeris.caps.sessionmanagement.internal;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedAccessToken;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.RefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.api.RotationResult;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.exception.InvalidRefreshTokenException;
import eu.exeris.caps.sessionmanagement.api.exception.RefreshTokenReplayedException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionExpiredException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionNotFoundException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionRevokedException;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.crypto.TokenHasher;
import eu.exeris.caps.sessionmanagement.internal.repository.RefreshTokenRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.RotationExecutionResult;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;
import eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default implementation of {@link RefreshTokenRotation}.
 *
 * @since 0.1.0
 */
public final class DefaultRefreshTokenRotation implements RefreshTokenRotation {

    private final SessionRepository repository;
    private final SessionPolicy policy;
    private final AccessTokenIssuer accessTokenIssuer;
    private final SessionAuditBridge auditBridge;

    public DefaultRefreshTokenRotation(
            SessionRepository repository,
            SessionPolicy policy,
            AccessTokenIssuer accessTokenIssuer,
            SessionAuditBridge auditBridge
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.accessTokenIssuer = accessTokenIssuer;
        this.auditBridge = auditBridge;
    }

    @Override
    public IssuedRefreshToken issue(UUID sessionId, UUID subjectId) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Instant now = Instant.now();

        Optional<SessionRecord> sessionOpt = repository.findSession(sessionId);
        if (sessionOpt.isEmpty()) {
            throw new SessionNotFoundException(sessionId);
        }
        SessionRecord session = sessionOpt.get();
        if (session.revokedAt() != null) {
            throw new SessionRevokedException(sessionId);
        }
        if (session.isExpired(now)) {
            throw new SessionExpiredException(sessionId);
        }

        TokenHasher.GeneratedToken tokenPair = TokenHasher.generate();
        Instant expiresAt = now.plus(policy.refreshTokenTtl());
        UUID tokenId = UUID.randomUUID();

        RefreshTokenRecord record = new RefreshTokenRecord(
                tokenId,
                sessionId,
                tokenPair.tokenHash(),
                now,
                expiresAt,
                null,
                null
        );
        repository.saveRefreshToken(record);

        return new IssuedRefreshToken(tokenPair.rawToken(), expiresAt, sessionId);
    }

    @Override
    public RotationResult rotate(String rawRefreshToken, ClientMetadata metadata) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new InvalidRefreshTokenException("rawRefreshToken must not be null or blank");
        }
        String oldTokenHash = TokenHasher.hash(rawRefreshToken);
        TokenHasher.GeneratedToken freshToken = TokenHasher.generate();
        Instant now = Instant.now();
        Instant newExpiresAt = now.plus(policy.refreshTokenTtl());
        UUID newTokenId = UUID.randomUUID();

        RotationExecutionResult result = repository.executeRotation(
                oldTokenHash,
                newTokenId,
                freshToken.tokenHash(),
                newExpiresAt,
                metadata,
                now
        );

        return switch (result) {
            case RotationExecutionResult.Success s -> {
                if (auditBridge != null) {
                    auditBridge.emitTokenRotated(s.session().id(), s.session().subjectId(), metadata);
                }
                IssuedAccessToken accessToken = accessTokenIssuer != null
                        ? accessTokenIssuer.issueAccessToken(s.session().subjectId(), s.session().id())
                        : null;
                IssuedRefreshToken refreshToken = new IssuedRefreshToken(freshToken.rawToken(), newExpiresAt, s.session().id());
                yield new RotationResult(s.session().subjectId(), s.session().id(), refreshToken, accessToken);
            }
            case RotationExecutionResult.ReplayDetected r -> {
                if (auditBridge != null) {
                    auditBridge.emitTokenReplayDetected(r.sessionId(), r.subjectId(), oldTokenHash);
                }
                throw new RefreshTokenReplayedException("Refresh token replay detected. Session has been revoked.", r.sessionId());
            }
            case RotationExecutionResult.TokenNotFound ignored ->
                throw new InvalidRefreshTokenException("Refresh token not found");
            case RotationExecutionResult.TokenRevoked ignored ->
                throw new InvalidRefreshTokenException("Refresh token has been revoked");
            case RotationExecutionResult.TokenExpired r ->
                throw new SessionExpiredException("Refresh token has expired", r.sessionId());
            case RotationExecutionResult.SessionNotFound r ->
                throw new SessionNotFoundException(r.sessionId());
            case RotationExecutionResult.SessionRevoked r ->
                throw new SessionRevokedException(r.sessionId());
            case RotationExecutionResult.SessionExpired r ->
                throw new SessionExpiredException(r.sessionId());
            case RotationExecutionResult.GraceWindow g -> {
                if (auditBridge != null) {
                    auditBridge.emitTokenRotated(g.session().id(), g.session().subjectId(), metadata);
                }
                IssuedAccessToken accessToken = accessTokenIssuer != null
                        ? accessTokenIssuer.issueAccessToken(g.session().subjectId(), g.session().id())
                        : null;
                yield new RotationResult(g.session().subjectId(), g.session().id(), null, accessToken);
            }
        };
    }

    @Override
    public void revoke(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }
        String tokenHash = TokenHasher.hash(rawRefreshToken);
        repository.revokeRefreshToken(tokenHash, Instant.now());
    }
}
