package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigTest {

    @Test
    void defaultsAreTheNeutralExampleValues() {
        Config config = Config.defaults();

        assertEquals("passkeydemo.noxno.ch", config.rpId());
        assertEquals("https://passkeydemo.noxno.ch", config.origin());
        assertEquals(java.util.List.of("https://passkeydemo.noxno.ch"), config.acceptedOrigins());
        assertEquals("strict", config.attestationPolicy());
        assertFalse(config.demoMode());
        assertEquals("public", config.staticDir().toString());
        assertEquals("com.example.passkeydemo", config.androidPackageName());
        assertEquals("/api", config.basePath());
        assertEquals(8099, config.port());
        assertEquals(604800L, config.unlockWindowSeconds());
        assertEquals(300L, config.ceremonyTtlSeconds());
        assertEquals(60, config.rateLimitPerMinute());
        assertEquals("change-me", config.adminToken());
        assertEquals(java.util.List.of("ABCDE12345.com.example.passkeydemo"), config.iosAppIds());
        assertTrue(config.serveWellKnown());
        assertEquals("ABCDE12345", config.appleTeamId());
        assertTrue(config.appAttestEnvironments().contains("appattestdevelop"));
        assertTrue(config.appleAppAttestRootPem().startsWith("-----BEGIN CERTIFICATE-----"));
    }

    @Test
    void readsUtf8PropertiesAndNormalisesDigests(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("application.properties");
        Files.writeString(file, String.join("\n",
                "port=9090",
                "rpId=passkeys.example.org",
                "rpName=Beispiel – Passkey-Demo",
                "androidSigningDigests=AA:BB:cc,DDEE",
                "verifiedBootPolicy=enforce",
                "allowSoftwareAttestationRoot=false"), StandardCharsets.UTF_8);

        Config config = Config.load(file);

        assertEquals(9090, config.port());
        assertEquals("https://passkeys.example.org", config.origin());
        assertEquals(java.util.List.of("https://passkeys.example.org"), config.acceptedOrigins());
        assertEquals("Beispiel – Passkey-Demo", config.rpName());
        assertEquals(java.util.Set.of("aabbcc", "ddee"), config.androidSigningDigests());
        assertEquals(config.androidSigningDigests(), config.androidWebCredentialDigests(),
                "unset androidWebCredentialDigests must fall back to the attestation digest list");
        assertEquals("enforce", config.verifiedBootPolicy());
        assertFalse(config.allowSoftwareAttestationRoot());
    }

    /** acceptedOrigins is the complete list when set - https://<rpId> is not added implicitly. */
    @Test
    void acceptedOriginsIsTheCompleteExplicitList(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("application.properties");
        Files.writeString(file, String.join("\n",
                "rpId=passkeys.example.org",
                "acceptedOrigins=https://passkeys.example.org, android:apk-key-hash:AAAA-BBBB_cc,"
                        + "https://passkeys.example.org"), StandardCharsets.UTF_8);

        Config config = Config.load(file);

        assertEquals(java.util.List.of("https://passkeys.example.org", "android:apk-key-hash:AAAA-BBBB_cc"),
                config.acceptedOrigins());
    }

    /**
     * The assetlinks fingerprint list may deliberately differ from the attestation acceptance list:
     * the first is a public grant, the second is a server-side check. Unset means "the same".
     */
    @Test
    void androidWebCredentialDigestsOverrideTheAttestationDigests(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("application.properties");
        Files.writeString(file, String.join("\n",
                "androidSigningDigests=AA:BB:cc,DDEE",
                "androidWebCredentialDigests=11:22:FF"), StandardCharsets.UTF_8);

        Config config = Config.load(file);

        assertEquals(java.util.Set.of("aabbcc", "ddee"), config.androidSigningDigests());
        assertEquals(java.util.Set.of("1122ff"), config.androidWebCredentialDigests());
    }

    /** basePath is the one client-specific piece of the route: normalised, and /api by default. */
    @Test
    void basePathIsNormalised(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("application.properties");
        Files.writeString(file, "basePath=/MyBackend/", StandardCharsets.UTF_8);
        assertEquals("/MyBackend", Config.load(file).basePath());
        assertEquals("/MyBackend/rest/authentication", PasskeyController.base(Config.load(file)));

        Files.writeString(file, "basePath=MyBackend", StandardCharsets.UTF_8);
        assertEquals("/MyBackend", Config.load(file).basePath());

        Files.writeString(file, "basePath=/", StandardCharsets.UTF_8);
        assertEquals("", Config.load(file).basePath());
        assertEquals("/rest/authentication", PasskeyController.base(Config.load(file)));

        assertEquals("/api/rest/authentication", PasskeyController.base(Config.defaults()));
    }

    @Test
    void serveWellKnownCanBeTurnedOff(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("application.properties");
        Files.writeString(file, "serveWellKnown=false", StandardCharsets.UTF_8);

        assertFalse(Config.load(file).serveWellKnown());
    }

    @Test
    void attestationPolicyIsStrictUnlessDemoIsSpelledOut(@TempDir Path dir) throws Exception {
        Path demo = dir.resolve("demo.properties");
        Files.writeString(demo, "attestationPolicy=DEMO", StandardCharsets.UTF_8);
        assertEquals("demo", Config.load(demo).attestationPolicy());
        assertTrue(Config.load(demo).demoMode());

        Path junk = dir.resolve("junk.properties");
        Files.writeString(junk, "attestationPolicy=lax", StandardCharsets.UTF_8);
        assertThrows(IllegalStateException.class, () -> Config.load(junk).attestationPolicy());
    }
}
