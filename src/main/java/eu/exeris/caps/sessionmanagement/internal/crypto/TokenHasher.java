package eu.exeris.caps.sessionmanagement.internal.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;

/**
 * Generates and hashes cryptographically secure single-use opaque refresh tokens.
 *
 * <p>Raw tokens are 16 bytes of entropy encoded as 32 hex characters.
 * Persisted tokens are SHA-256 hashes encoded as 64 lowercase hex characters.
 *
 * @since 0.1.0
 */
public final class TokenHasher {

    private static final int RANDOM_BYTE_COUNT = 16;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private TokenHasher() {
    }

    /**
     * Pair containing the unpersisted raw token and its corresponding SHA-256 hash.
     */
    public record GeneratedToken(String rawToken, String tokenHash) {
        public GeneratedToken {
            Objects.requireNonNull(rawToken, "rawToken must not be null");
            Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        }
    }

    /**
     * Generates a fresh random 16-byte raw token and calculates its SHA-256 hash.
     *
     * @return generated token pair
     */
    public static GeneratedToken generate() {
        byte[] bytes = new byte[RANDOM_BYTE_COUNT];
        SECURE_RANDOM.nextBytes(bytes);
        String raw = HEX.formatHex(bytes);
        String hash = hash(raw);
        return new GeneratedToken(raw, hash);
    }

    /**
     * Computes the SHA-256 hash of a raw token string.
     *
     * @param rawToken raw token string
     * @return 64-character lowercase hex digest
     */
    public static String hash(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be null or blank");
        }
        String normalized = rawToken.trim().toLowerCase(Locale.ROOT);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest algorithm not available", e);
        }
    }

    /**
     * Verifies whether a raw token matches an expected hash in constant time.
     *
     * @param rawToken     raw token string
     * @param expectedHash expected SHA-256 hash
     * @return true if matching
     */
    public static boolean verify(String rawToken, String expectedHash) {
        if (rawToken == null || expectedHash == null) {
            return false;
        }
        String computed = hash(rawToken);
        return MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.UTF_8),
                expectedHash.getBytes(StandardCharsets.UTF_8)
        );
    }
}
