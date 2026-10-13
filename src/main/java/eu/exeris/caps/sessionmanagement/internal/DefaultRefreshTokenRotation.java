package eu.exeris.caps.sessionmanagement.internal;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedAccessToken;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.RefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.sessionmanagement.api.exception.SessionException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionExpiredException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionNotFoundException;
import eu.exeris.caps.sessionmanagement.api.exception.SessionRevokedException;
import eu.exeris.caps.sessionmanagement.internal.audit.SessionAuditBridge;
import eu.exeris.caps.sessionmanagement.internal.crypto.TokenHasher;
import eu.exeris.caps.sessionmanagement.internal.repository.FamilyRevocation;
import eu.exeris.caps.sessionmanagement.internal.repository.IssueResult;
import eu.exeris.caps.sessionmanagement.internal.repository.RefreshTokenRecord;
import eu.exeris.caps.sessionmanagement.internal.repository.RevocationReason;
import eu.exeris.caps.sessionmanagement.internal.repository.RotationExecutionResult;
import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;
import eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Default {@link RefreshTokenRotation}. The single-use decision is made by the repository's
 * conditional write, never by a check in this class.
 *
 * @since 0.1.0
 */
public final class DefaultRefreshTokenRotation implements RefreshTokenRotation {

    private final SessionRepository repository;
    private final SessionPolicy policy;
    private final AccessTokenIssuer accessTokenIssuer;
    private final SessionAuditBridge auditBridge;
    private final Clock clock;

    public DefaultRefreshTokenRotation(
            SessionRepository repository,
            SessionPolicy policy,
            AccessTokenIssuer accessTokenIssuer,
            SessionAuditBridge auditBridge,
            Clock clock
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.accessTokenIssuer = accessTokenIssuer;
        this.auditBridge = auditBridge;
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @Override
    public IssuedRefreshToken issue(UUID sessionId, UUID subjectId) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Instant now = clock.instant();
        TokenHasher.GeneratedToken generated = TokenHasher.generate();
        RefreshTokenRecord record = new RefreshTokenRecord(
                UUID.randomUUID(), sessionId, generated.tokenHash(), now, now, null, null);

        IssueResult result = repository.issueFirstToken(subjectId, record, now, policy.idleTimeout());
        return switch (result.status()) {
            case ISSUED -> new IssuedRefreshToken(generated.rawToken(), result.expiresAt(), sessionId);
            case SESSION_NOT_FOUND -> throw new SessionNotFoundException(sessionId);
            case SESSION_REVOKED -> throw new SessionRevokedException(sessionId);
            case SESSION_EXPIRED -> throw new SessionExpiredException(sessionId);
            case ALREADY_ISSUED -> throw new SessionException(
                    "A refresh token was already issued for session " + sessionId + "; successors come from rotation");
        };
    }

    @Override
    public RotationOutcome rotate(String rawRefreshToken, ClientMetadata metadata) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return new RotationOutcome.Rejected(RotationOutcome.Reason.UNKNOWN_TOKEN);
        }
        String presentedHash = TokenHasher.hash(rawRefreshToken);
        TokenHasher.GeneratedToken successor = TokenHasher.generate();
        Instant now = clock.instant();

        RotationExecutionResult result = repository.rotate(
                presentedHash, UUID.randomUUID(), successor.tokenHash(), metadata, now, policy.idleTimeout());

        return switch (result) {
            case RotationExecutionResult.Rotated rotated -> {
                var session = rotated.session();
                if (auditBridge != null) {
                    auditBridge.emitTokenRotated(session.id(), session.subjectId(), metadata);
                }
                Instant expiresAt = session.tokenExpiry(now, policy.idleTimeout());
                IssuedAccessToken accessToken = accessTokenIssuer != null
                        ? accessTokenIssuer.issueAccessToken(session.subjectId(), session.id())
                        : null;
                yield new RotationOutcome.Rotated(
                        session.subjectId(),
                        session.id(),
                        new IssuedRefreshToken(successor.rawToken(), expiresAt, session.id()),
                        accessToken);
            }
            case RotationExecutionResult.ReuseDetected reuse -> {
                if (auditBridge != null) {
                    auditBridge.emitTokenReplayDetected(reuse.sessionId(), reuse.subjectId(), presentedHash);
                }
                yield new RotationOutcome.ReuseDetected(reuse.sessionId());
            }
            case RotationExecutionResult.Rejected rejected -> new RotationOutcome.Rejected(rejected.reason());
        };
    }

    @Override
    public boolean revoke(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return false;
        }
        Optional<FamilyRevocation> revoked = repository.revokeFamilyByTokenHash(
                TokenHasher.hash(rawRefreshToken), clock.instant(), RevocationReason.REFRESH_TOKEN_REVOKED);
        revoked.ifPresent(r -> {
            if (auditBridge != null) {
                auditBridge.emitSessionRevoked(r.sessionId(), r.subjectId(), RevocationReason.REFRESH_TOKEN_REVOKED);
            }
        });
        return revoked.isPresent();
    }
}
