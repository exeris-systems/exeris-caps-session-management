package eu.exeris.caps.sessionmanagement;

import eu.exeris.caps.sessionmanagement.internal.crypto.TokenHasher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("TokenHasher Cryptographic Unit Tests")
class TokenHasherTest {

    @Test
    @DisplayName("generate produces 32-hex raw token and 64-hex SHA-256 hash")
    void generateProducesCorrectLengths() {
        TokenHasher.GeneratedToken token = TokenHasher.generate();

        assertThat(token.rawToken()).matches("^[0-9a-f]{32}$");
        assertThat(token.tokenHash()).matches("^[0-9a-f]{64}$");
    }

    @Test
    @DisplayName("hash is deterministic and case-insensitive on input")
    void hashIsDeterministic() {
        String raw = "0123456789abcdef0123456789abcdef";
        String hash1 = TokenHasher.hash(raw);
        String hash2 = TokenHasher.hash(raw.toUpperCase());

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).matches("^[0-9a-f]{64}$");
    }

    @Test
    @DisplayName("verify returns true for matching token and false for invalid")
    void verifyToken() {
        TokenHasher.GeneratedToken token = TokenHasher.generate();

        assertThat(TokenHasher.verify(token.rawToken(), token.tokenHash())).isTrue();
        assertThat(TokenHasher.verify("wrong-raw-token", token.tokenHash())).isFalse();
        assertThat(TokenHasher.verify(null, token.tokenHash())).isFalse();
        assertThat(TokenHasher.verify(token.rawToken(), null)).isFalse();
    }

    @Test
    @DisplayName("hash rejects null or blank raw tokens")
    void hashRejectsEmptyOrNull() {
        assertThatThrownBy(() -> TokenHasher.hash(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TokenHasher.hash(""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TokenHasher.hash("   "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("multiple generated tokens have distinct entropy")
    void tokensAreUnique() {
        Set<String> rawTokens = new HashSet<>();
        Set<String> hashes = new HashSet<>();

        for (int i = 0; i < 100; i++) {
            TokenHasher.GeneratedToken token = TokenHasher.generate();
            rawTokens.add(token.rawToken());
            hashes.add(token.tokenHash());
        }

        assertThat(rawTokens).hasSize(100);
        assertThat(hashes).hasSize(100);
    }
}
