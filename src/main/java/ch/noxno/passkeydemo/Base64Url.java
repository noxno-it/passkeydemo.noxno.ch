package ch.noxno.passkeydemo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/** Byte helpers shared by every verifier. base64url is RFC 4648 section 5, no padding. */
public final class Base64Url {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Base64Url() {
    }

    public static String encode(byte[] raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /** Accepts padded and unpadded input (java.util.Base64 tolerates trailing '='). */
    public static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    public static String encodeStandard(byte[] raw) {
        return Base64.getEncoder().encodeToString(raw);
    }

    public static byte[] decodeStandard(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static byte[] random(int length) {
        byte[] buffer = new byte[length];
        RANDOM.nextBytes(buffer);
        return buffer;
    }

    public static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is mandatory in every JRE", e);
        }
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    public static String hex(byte[] raw) {
        char[] out = new char[raw.length * 2];
        for (int i = 0; i < raw.length; i++) {
            out[i * 2] = HEX[(raw[i] >> 4) & 0x0f];
            out[i * 2 + 1] = HEX[raw[i] & 0x0f];
        }
        return new String(out);
    }

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
