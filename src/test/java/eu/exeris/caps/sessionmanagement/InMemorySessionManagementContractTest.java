package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.internal.repository.SessionRepository;
import org.junit.jupiter.api.DisplayName;

@DisplayName("Session management contract — test-double repository")
class InMemorySessionManagementContractTest extends AbstractSessionManagementContractTest {

    @Override
    protected SessionRepository newRepository() {
        return new InMemorySessionRepository();
    }
}
