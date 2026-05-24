package org.ipsecuz.opprotection.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class PasswordHasher {
    private static final String PREFIX = "pbkdf2_sha256";
    private static final int ITERATIONS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] GENERATED_PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#$%+=_-".toCharArray();

    private PasswordHasher() {
    }

    public static String hash(String rawPassword) {
        if (rawPassword == null) {
            throw new IllegalArgumentException("Password cannot be null");
        }
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] derived = pbkdf2(rawPassword.toCharArray(), salt, ITERATIONS, KEY_BITS);
        return PREFIX + "$" + ITERATIONS + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(derived);
    }

    public static boolean verify(String rawPassword, String storedValue) {
        if (rawPassword == null || storedValue == null || storedValue.isBlank()) {
            return false;
        }

        if (storedValue.startsWith(PREFIX + "$")) {
            return verifyPbkdf2(rawPassword, storedValue);
        }

        if (isLegacySha256(storedValue)) {
            return MessageDigest.isEqual(
                    legacySha256(rawPassword).getBytes(StandardCharsets.UTF_8),
                    storedValue.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8)
            );
        }

        return MessageDigest.isEqual(
                rawPassword.getBytes(StandardCharsets.UTF_8),
                storedValue.getBytes(StandardCharsets.UTF_8)
        );
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
        return storedValue != null && storedValue.startsWith(PREFIX + "$");
    }

    public static boolean needsRehash(String storedValue) {
        return !isStrongHash(storedValue);
    }

    public static boolean isLegacySha256(String storedValue) {
        return storedValue != null && storedValue.matches("(?i)^[0-9a-f]{64}$");
    }

    private static boolean verifyPbkdf2(String rawPassword, String storedValue) {
        try {
            String[] parts = storedValue.split("\\$", 4);
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            byte[] actual = pbkdf2(rawPassword.toCharArray(), salt, iterations, expected.length * 8);
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception ignored) {
            return false;
        }
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBits) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot hash OPProtection password", e);
        }
    }

    private static String legacySha256(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(encoded.length * 2);
            for (byte b : encoded) {
                String s = Integer.toHexString(0xff & b);
                if (s.length() == 1) hex.append('0');
                hex.append(s);
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot verify legacy SHA-256 password", e);
        }
    }
}
