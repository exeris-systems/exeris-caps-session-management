package eu.exeris.caps.sessionmanagement.internal.repository;

/**
 * Why a session was revoked, recorded in {@code sessions.revocation_reason}.
 *
 * @since 0.1.0
 */
public enum RevocationReason {
    /** The subject signed out of this session. */
    LOGOUT,
    /** The subject revoked this session from a session listing. */
    REVOKED_BY_SUBJECT,
    /** The subject revoked all of their sessions. */
    REVOKED_ALL_BY_SUBJECT,
    /** The subject's credential was changed or reset. */
    CREDENTIAL_CHANGED,
    /** A newer session pushed the subject over the active-session limit. */
    EVICTED,
    /** A consumed refresh token of the session was presented again. */
    REFRESH_TOKEN_REUSE,
    /** A holder of one of the session's refresh tokens revoked it. */
    REFRESH_TOKEN_REVOKED
}
