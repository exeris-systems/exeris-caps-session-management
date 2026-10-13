package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.kernel.spi.exceptions.security.PrincipalContextMissingException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("SessionPrincipal comes from the kernel's verified principal only")
class SessionPrincipalTest {

    @Test
    @DisplayName("outside an authenticated scope there is no principal to act as")
    void refusesOutsideAnAuthenticatedScope() {
        assertThatThrownBy(SessionPrincipal::current).isInstanceOf(PrincipalContextMissingException.class);
    }

    @Test
    @DisplayName("it carries the bound principal's subject and, when present, its session")
    void carriesTheBoundSubjectAndSession() {
        UUID subject = UUID.randomUUID();
        UUID session = UUID.randomUUID();

        SessionPrincipal bound = TestPrincipals.authenticated(subject, session);
        assertThat(bound.subjectId()).isEqualTo(subject);
        assertThat(bound.sessionId()).contains(session);

        SessionPrincipal plain = TestPrincipals.authenticatedWithoutSession(subject);
        assertThat(plain.subjectId()).isEqualTo(subject);
        assertThat(plain.sessionId()).isEmpty();
    }

    @Test
    @DisplayName("no public constructor or factory accepts a subject identifier")
    void cannotBeBuiltFromACallerSuppliedSubject() {
        assertThat(SessionPrincipal.class.getConstructors()).isEmpty();
        assertThat(Arrays.stream(SessionPrincipal.class.getDeclaredMethods())
                .filter(m -> Modifier.isStatic(m.getModifiers()) && Modifier.isPublic(m.getModifiers())))
                .allSatisfy(m -> assertThat(m.getParameterCount()).isZero());
    }
}
