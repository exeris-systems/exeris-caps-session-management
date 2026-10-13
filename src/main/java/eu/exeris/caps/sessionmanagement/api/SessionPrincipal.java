package eu.exeris.caps.sessionmanagement.api;

import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.security.PrincipalContext;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * The authenticated caller of a subject-scoped session operation.
 *
 * <p>The only way to obtain one is {@link #current()}, which reads the principal the kernel's security
 * edge bound to {@link KernelProviders#PRINCIPAL_CONTEXT} after verifying the request's access token.
 * There is no constructor or factory taking a subject identifier, so a route handler cannot turn a
 * {@code subjectId} from a request body, query string or header into a {@code SessionPrincipal}: every
 * operation that takes one acts on the verified subject and nobody else.
 *
 * @since 0.1.0
 */
public final class SessionPrincipal {

    private final UUID subjectId;
    private final UUID sessionId;

    private SessionPrincipal(UUID subjectId, UUID sessionId) {
        this.subjectId = Objects.requireNonNull(subjectId, "subjectId must not be null");
        this.sessionId = sessionId;
    }

    /**
     * The principal bound to the current request scope.
     *
     * @return the authenticated caller
     * @throws eu.exeris.kernel.spi.exceptions.security.PrincipalContextMissingException if no principal is
     *         bound, that is, outside an authenticated request ({@code EX-SEC-2001})
     */
    public static SessionPrincipal current() {
        PrincipalContext principal = KernelProviders.principal();
        UUID sid = principal instanceof SessionBoundPrincipal bound ? bound.sessionId() : null;
        return new SessionPrincipal(principal.principalId(), sid);
    }

    /**
     * The verified subject.
     */
    public UUID subjectId() {
        return subjectId;
    }

    /**
     * The session the caller's access token was issued for, when the bound principal carries one.
     */
    public Optional<UUID> sessionId() {
        return Optional.ofNullable(sessionId);
    }

    @Override
    public String toString() {
        return "SessionPrincipal[subjectId=" + subjectId + ", sessionId=" + sessionId + "]";
    }
}
