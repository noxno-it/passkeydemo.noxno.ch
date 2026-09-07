package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class Base64UrlTest {

    @Test
    void encodesWithoutPaddingAndDecodesBothForms() {
        byte[] raw = { 1, 2, 3, 4 };
        String encoded = Base64Url.encode(raw);

        assertEquals("AQIDBA", encoded);
        assertFalse(encoded.contains("="));
        assertArrayEquals(raw, Base64Url.decode(encoded));
        assertArrayEquals(raw, Base64Url.decode(encoded + "=="));
    }

    @Test
    void sha256MatchesTheKnownEmptyStringDigest() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Base64Url.hex(Base64Url.sha256(new byte[0])));
    }

    @Test
    void concatKeepsOrder() {
        assertArrayEquals(new byte[] { 1, 2, 3 },
                Base64Url.concat(new byte[] { 1 }, new byte[] { 2, 3 }));
    }

    @Test
    void constantTimeEqualsComparesContent() {
        assertTrue(Base64Url.constantTimeEquals(new byte[] { 7, 7 }, new byte[] { 7, 7 }));
        assertFalse(Base64Url.constantTimeEquals(new byte[] { 7, 7 }, new byte[] { 7, 8 }));
    }
}
