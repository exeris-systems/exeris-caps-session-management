package eu.exeris.caps.sessionmanagement.api;

import eu.exeris.kernel.spi.security.PrincipalContext;

import java.util.UUID;

/**
 * A kernel {@link PrincipalContext} that also carries the session the access token was issued for
 * (the token's {@code sid} claim).
 *
 * <p>The composition's {@code ClaimsMapper} produces it from verified claims, so the session identifier
 * is as trustworthy as the subject: both come from a token whose signature the kernel's security edge
 * has checked. A principal that does not implement this interface identifies a subject but no session,
 * and {@link SessionStore#logout(SessionPrincipal)} refuses it.
 *
 * @since 0.1.0
 */
public interface SessionBoundPrincipal extends PrincipalContext {

    /**
     * The session identifier from the verified token's {@code sid} claim.
     *
     * @return session identifier, never {@code null}
     */
    UUID sessionId();
}
