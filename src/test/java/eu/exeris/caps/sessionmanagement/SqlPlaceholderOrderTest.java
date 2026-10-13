package eu.exeris.caps.sessionmanagement;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Community persistence binding rewrites each {@code $n} to a positional {@code ?}, so a statement
 * binds correctly only if its placeholders read {@code $1, $2, ..., $k} left to right, each once. This
 * holds every statement the capability prepares to that shape, and keeps placeholders out of the
 * migrations, which are applied as plain DDL.
 */
@DisplayName("SQL placeholders are $1..$n, ascending, each used once")
class SqlPlaceholderOrderTest {

    private static final Path REPOSITORY_SOURCE = Path.of(
            "src/main/java/eu/exeris/caps/sessionmanagement/internal/repository/PostgresSessionRepository.java");
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$(\\d+)");
    private static final Pattern STRING_LITERAL = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final String PREPARE = "conn.prepare(";

    @Test
    @DisplayName("every statement PostgresSessionRepository prepares numbers its placeholders in order")
    void preparedStatementsUseAscendingSingleUsePlaceholders() throws IOException {
        List<String> statements = preparedStatements(Files.readString(REPOSITORY_SOURCE));

        assertThat(statements).hasSizeGreaterThanOrEqualTo(10);
        assertThat(statements).allSatisfy(sql ->
                assertThat(placeholders(sql)).as(sql).isEqualTo(ascendingFromOne(placeholders(sql).size())));
    }

    @Test
    @DisplayName("the rule check rejects a repeated and an out-of-order placeholder")
    void ruleCheckRejectsViolations() {
        assertThat(placeholders("UPDATE t SET a = $1 WHERE b = $1")).isNotEqualTo(ascendingFromOne(2));
        assertThat(placeholders("UPDATE t SET a = $2 WHERE b = $1")).isNotEqualTo(ascendingFromOne(2));
        assertThat(placeholders("UPDATE t SET a = $1 WHERE b = $2")).isEqualTo(ascendingFromOne(2));
    }

    @Test
    @DisplayName("migrations carry no bind placeholders")
    void migrationsHaveNoPlaceholders() throws IOException {
        assertThat(SessionManagementModule.MIGRATIONS).isNotEmpty();
        for (String migration : SessionManagementModule.MIGRATIONS) {
            try (InputStream in = getClass().getClassLoader().getResourceAsStream(migration)) {
                assertThat(in).as(migration + " on the classpath").isNotNull();
                String ddl = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                assertThat(PLACEHOLDER.matcher(ddl).find()).as(migration).isFalse();
            }
        }
    }

    /** The concatenated string literals of each {@code conn.prepare(...)} argument. */
    private static List<String> preparedStatements(String source) {
        List<String> statements = new ArrayList<>();
        int from = 0;
        while ((from = source.indexOf(PREPARE, from)) >= 0) {
            int start = from + PREPARE.length();
            int end = closingParenthesis(source, start);
            StringBuilder sql = new StringBuilder();
            Matcher literal = STRING_LITERAL.matcher(source.substring(start, end));
            while (literal.find()) {
                sql.append(literal.group(1));
            }
            statements.add(sql.toString());
            from = end;
        }
        return statements;
    }

    private static int closingParenthesis(String source, int start) {
        int depth = 1;
        boolean inString = false;
        for (int i = start; i < source.length(); i++) {
            char c = source.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
            } else if (c == '"') {
                inString = true;
            } else if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return i;
            }
        }
        throw new IllegalStateException("unbalanced conn.prepare( at " + start);
    }

    private static List<Integer> placeholders(String sql) {
        List<Integer> found = new ArrayList<>();
        Matcher m = PLACEHOLDER.matcher(sql);
        while (m.find()) {
            found.add(Integer.parseInt(m.group(1)));
        }
        return found;
    }

    private static List<Integer> ascendingFromOne(int count) {
        List<Integer> expected = new ArrayList<>();
        for (int i = 1; i <= count; i++) {
            expected.add(i);
        }
        return expected;
    }
}
