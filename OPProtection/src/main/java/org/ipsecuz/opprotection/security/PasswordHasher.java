package org.ipsecuz.opprotection.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Password hashing and legacy migration helpers. */
public final class PasswordHasher {
    private static final String PREFIX = "pbkdf2_sha256";
    private static final int ITERATIONS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int MIN_ACCEPTED_ITERATIONS = 50_000;
    private static final int MAX_ACCEPTED_ITERATIONS = 1_000_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] GENERATED_PASSWORD_CHARS =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%+=_-".toCharArray();

    private PasswordHasher() { }

    public static String hash(String rawPassword) {
        if (rawPassword == null) throw new IllegalArgumentException("Password cannot be null");
        byte[] salt = new byte[SALT_BYTES];
        char[] password = rawPassword.toCharArray();
        RANDOM.nextBytes(salt);
        try {
            byte[] derived = pbkdf2(password, salt, ITERATIONS, KEY_BITS);
            return PREFIX + "$" + ITERATIONS + "$"
                    + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(derived);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public static boolean verify(String rawPassword, String storedValue) {
        if (rawPassword == null || storedValue == null || storedValue.isBlank()) return false;
        if (storedValue.startsWith(PREFIX + "$")) return verifyPbkdf2(rawPassword, storedValue);
        if (isLegacySha256(storedValue)) {
            return MessageDigest.isEqual(
                    legacySha256(rawPassword).getBytes(StandardCharsets.UTF_8),
                    storedValue.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
        }
        return MessageDigest.isEqual(rawPassword.getBytes(StandardCharsets.UTF_8),
                storedValue.getBytes(StandardCharsets.UTF_8));
    }

    public static String generateRandomPassword(int length) {
        int safeLength = Math.max(16, length);
        StringBuilder generated = new StringBuilder(safeLength);
        for (int i = 0; i < safeLength; i++) {
            generated.append(GENERATED_PASSWORD_CHARS[RANDOM.nextInt(GENERATED_PASSWORD_CHARS.length)]);
        }
        return generated.toString();
    }

    public static boolean isStrongHash(String storedValue) {
        return parse(storedValue) != null;
    }

    public static boolean needsRehash(String storedValue) {
        ParsedHash parsed = parse(storedValue);
        return parsed == null || parsed.iterations < ITERATIONS || parsed.hash.length * 8 < KEY_BITS;
    }

    public static boolean isLegacySha256(String storedValue) {
        return storedValue != null && storedValue.matches("(?i)^[0-9a-f]{64}$");
    }

    private static boolean verifyPbkdf2(String rawPassword, String storedValue) {
        ParsedHash parsed = parse(storedValue);
        if (parsed == null) return false;
        char[] password = rawPassword.toCharArray();
        try {
            byte[] actual = pbkdf2(password, parsed.salt, parsed.iterations, parsed.hash.length * 8);
            return MessageDigest.isEqual(parsed.hash, actual);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static ParsedHash parse(String storedValue) {
        if (storedValue == null || storedValue.isBlank()) return null;
        try {
            String[] parts = storedValue.split("\\$", 4);
            if (parts.length != 4 || !PREFIX.equals(parts[0])) return null;
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS) return null;
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] hash = Base64.getDecoder().decode(parts[3]);
            if (salt.length < 8 || salt.length > 64 || hash.length < 16 || hash.length > 64) return null;
            return new ParsedHash(iterations, salt, hash);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBits) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot hash OPProtection password", ex);
        } finally {
            spec.clearPassword();
        }
    }

    private static String legacySha256(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot verify legacy SHA-256 password", ex);
        }
    }

    private record ParsedHash(int iterations, byte[] salt, byte[] hash) { }
}
