package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.api.SessionBoundPrincipal;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.security.ImmutablePrincipal;
import eu.exeris.kernel.spi.security.PrincipalContext;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Obtains a {@link SessionPrincipal} the only way production code can: by binding a kernel principal to
 * {@link KernelProviders#PRINCIPAL_CONTEXT}, as the security edge does after verifying a token.
 */
final class TestPrincipals {

    private TestPrincipals() {
    }

    record BoundPrincipal(UUID principalId, UUID sessionId) implements SessionBoundPrincipal {
        @Override
        public Optional<UUID> tenantId() {
            return Optional.empty();
        }

        @Override
        public Set<String> roles() {
            return Set.of();
        }

        @Override
        public Set<String> scopes() {
            return Set.of();
        }
    }

    /** The caller of a request whose access token named this subject and session. */
    static SessionPrincipal authenticated(UUID subjectId, UUID sessionId) {
        return bind(new BoundPrincipal(subjectId, sessionId));
    }

    /** The caller of a request whose principal names a subject but no session. */
    static SessionPrincipal authenticatedWithoutSession(UUID subjectId) {
        return bind(ImmutablePrincipal.ofScopes(subjectId, Set.of()));
    }

    static SessionPrincipal bind(PrincipalContext principal) {
        return ScopedValue.where(KernelProviders.PRINCIPAL_CONTEXT, principal).call(SessionPrincipal::current);
    }
}
