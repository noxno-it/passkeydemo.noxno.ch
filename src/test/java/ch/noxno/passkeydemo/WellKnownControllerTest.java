package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The two association files. Everything here is about the CONVENIENCE path (platform passkeys held
 * by iCloud Keychain / Google Password Manager, attestation "none", BSI trust level "normal"); the
 * attested, device-bound path is unaffected by these endpoints and needs none of them.
 */
class WellKnownControllerTest {

    /** A made-up, well-formed SHA-256 certificate digest. No real signing key is involved. */
    private static final String EXAMPLE_DIGEST_COLONS =
            "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
    private static final String EXAMPLE_DIGEST_PLAIN =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = Json.mapper();
    private Main.Wiring server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.app.stop();
            server = null;
        }
    }

    // ---------------------------------------------------------------- fingerprint conversion

    /**
     * Config normalises digests to lower-case hex without separators for the attestation compare;
     * assetlinks.json wants UPPER-CASE hex with a colon between every byte. Both spellings go in.
     */
    @Test
    void fingerprintConversionUppercasesAndInsertsColons() {
        assertEquals(EXAMPLE_DIGEST_COLONS, WellKnownController.toAssetLinksFingerprint(EXAMPLE_DIGEST_PLAIN));
        assertEquals(EXAMPLE_DIGEST_COLONS, WellKnownController.toAssetLinksFingerprint(EXAMPLE_DIGEST_COLONS),
                "an already colon-separated input must survive unchanged");
        assertEquals(EXAMPLE_DIGEST_COLONS,
                WellKnownController.toAssetLinksFingerprint(EXAMPLE_DIGEST_COLONS.toLowerCase(java.util.Locale.ROOT)));
        assertEquals(EXAMPLE_DIGEST_COLONS,
                WellKnownController.toAssetLinksFingerprint(EXAMPLE_DIGEST_PLAIN.toUpperCase(java.util.Locale.ROOT)));

        String all00 = WellKnownController.toAssetLinksFingerprint("00".repeat(32));
        assertEquals(95, all00.length(), "64 hex characters plus 31 colons");
        assertEquals(31, all00.chars().filter(c -> c == ':').count());
    }

    /** A placeholder left in application.properties must fail at boot, not be published as broken JSON. */
    @Test
    void fingerprintConversionRejectsAnythingThatIsNotASha256Digest() {
        assertThrows(IllegalStateException.class,
                () -> WellKnownController.toAssetLinksFingerprint("PLAY_APP_SIGNING_SHA256"));
        assertThrows(IllegalStateException.class, () -> WellKnownController.toAssetLinksFingerprint("aabbcc"));
        assertThrows(IllegalStateException.class, () -> WellKnownController.toAssetLinksFingerprint("zz".repeat(32)));
        assertThrows(IllegalStateException.class, () -> WellKnownController.toAssetLinksFingerprint(""));
    }

    // ---------------------------------------------------------------- content type and shape

    @Test
    void strictModeServesBothFilesAsApplicationJson(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=strict", "androidWebCredentialDigests=" + EXAMPLE_DIGEST_COLONS);

        HttpResponse<String> aasa = get(WellKnownController.AASA_PATH);
        assertEquals(200, aasa.statusCode());
        assertEquals("application/json", contentType(aasa),
                "the AASA path has no file extension - Apple needs exactly application/json");

        HttpResponse<String> links = get(WellKnownController.ASSETLINKS_PATH);
        assertEquals(200, links.statusCode());
        assertEquals("application/json", contentType(links));
    }

    /** The exact body Apple expects: only a webcredentials section, no applinks and no appclips. */
    @Test
    void appleAppSiteAssociationListsEveryConfiguredAppId(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=strict",
                "iosAppIds=ABCDE12345.com.example.passkeydemo,ABCDE12345.com.example.passkeydemo.dev");

        HttpResponse<String> response = get(WellKnownController.AASA_PATH);
        JsonNode body = mapper.readTree(response.body());

        assertEquals(1, body.size(), "no applinks and no appclips section");
        JsonNode apps = body.get("webcredentials").get("apps");
        assertEquals(2, apps.size());
        assertEquals("ABCDE12345.com.example.passkeydemo", apps.get(0).asString());
        assertEquals("ABCDE12345.com.example.passkeydemo.dev", apps.get(1).asString());
    }

    /** A bare bundle id in iosAppIds is qualified with appleTeamId; an explicit team id is kept. */
    @Test
    void bareBundleIdsAreQualifiedWithTheTeamId(@TempDir Path dir) throws Exception {
        start(dir, "appleTeamId=ABCDE12345",
                "iosAppIds=com.example.passkeydemo,ABCDE12345.com.example.passkeydemo.dev");

        JsonNode apps = mapper.readTree(get(WellKnownController.AASA_PATH).body())
                .get("webcredentials").get("apps");

        assertEquals(List.of("ABCDE12345.com.example.passkeydemo", "ABCDE12345.com.example.passkeydemo.dev"),
                List.of(apps.get(0).asString(), apps.get(1).asString()));
    }

    @Test
    void assetLinksIsAnArrayWithTheLoginCredsRelationAndUppercaseFingerprints(@TempDir Path dir) throws Exception {
        start(dir, "androidPackageName=com.example.passkeydemo",
                "androidWebCredentialDigests=" + EXAMPLE_DIGEST_PLAIN);

        JsonNode body = mapper.readTree(get(WellKnownController.ASSETLINKS_PATH).body());

        assertTrue(body.isArray(), "assetlinks.json is a JSON array, not an object");
        assertEquals(1, body.size());
        JsonNode entry = body.get(0);
        // BOTH relations, and this is load-bearing rather than belt-and-braces. Play Services'
        // app-facing passkey path still matches on handle_all_urls, so a statement carrying only
        // get_login_creds is rejected for EVERY rpId with "RP ID cannot be validated" - while
        // assetlinks:check?relation=get_login_creds cheerfully answers {"linked": true}. A browser
        // never notices, because a privileged browser authenticates by origin and skips Digital
        // Asset Links entirely; only the native app path breaks.
        assertEquals(2, entry.get("relation").size());
        assertEquals("delegate_permission/common.handle_all_urls", entry.get("relation").get(0).asString());
        assertEquals("delegate_permission/common.get_login_creds", entry.get("relation").get(1).asString());
        JsonNode target = entry.get("target");
        assertEquals("android_app", target.get("namespace").asString());
        assertEquals("com.example.passkeydemo", target.get("package_name").asString());
        assertEquals(1, target.get("sha256_cert_fingerprints").size());
        assertEquals(EXAMPLE_DIGEST_COLONS, target.get("sha256_cert_fingerprints").get(0).asString());
    }

    /** androidWebCredentialDigests is unset here, so the assetlinks list comes from androidSigningDigests. */
    @Test
    void assetLinksFallsBackToTheAttestationDigestList(@TempDir Path dir) throws Exception {
        start(dir, "androidSigningDigests=" + EXAMPLE_DIGEST_COLONS);

        JsonNode fingerprints = mapper.readTree(get(WellKnownController.ASSETLINKS_PATH).body())
                .get(0).get("target").get("sha256_cert_fingerprints");

        assertEquals(1, fingerprints.size());
        assertEquals(EXAMPLE_DIGEST_COLONS, fingerprints.get(0).asString());
    }

    // ---------------------------------------------------------------- gating

    /** App identity, not the demo: demo mode serves exactly the same two files. */
    @Test
    void demoModeServesBothFilesToo(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=demo", "androidWebCredentialDigests=" + EXAMPLE_DIGEST_PLAIN,
                "iosAppIds=ABCDE12345.com.example.passkeydemo,ABCDE12345.com.example.passkeydemo.dev");

        HttpResponse<String> aasa = get(WellKnownController.AASA_PATH);
        HttpResponse<String> links = get(WellKnownController.ASSETLINKS_PATH);

        assertEquals(200, aasa.statusCode());
        assertEquals("application/json", contentType(aasa));
        assertEquals(2, mapper.readTree(aasa.body()).get("webcredentials").get("apps").size());
        assertEquals(200, links.statusCode());
        assertEquals("application/json", contentType(links));
        assertEquals(EXAMPLE_DIGEST_COLONS, mapper.readTree(links.body())
                .get(0).get("target").get("sha256_cert_fingerprints").get(0).asString());
    }

    @Test
    void serveWellKnownFalseIs404(@TempDir Path dir) throws Exception {
        start(dir, "serveWellKnown=false");

        assertEquals(404, get(WellKnownController.AASA_PATH).statusCode());
        assertEquals(404, get(WellKnownController.ASSETLINKS_PATH).statusCode());
    }

    /**
     * An empty fingerprint list is valid JSON and breaks Android passkeys silently, so it has to be
     * a WARN. slf4j-simple writes to System.err, which is why the stream is captured here.
     */
    @Test
    void emptyFingerprintListIsStillServedButWarnsLoudly(@TempDir Path dir) throws Exception {
        PrintStream originalErr = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        String log;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            start(dir, "androidSigningDigests=", "androidWebCredentialDigests=");
        } finally {
            System.setErr(originalErr);
            log = captured.toString(StandardCharsets.UTF_8);
        }

        JsonNode fingerprints = mapper.readTree(get(WellKnownController.ASSETLINKS_PATH).body())
                .get(0).get("target").get("sha256_cert_fingerprints");
        assertEquals(0, fingerprints.size(), "an empty list is what actually gets published");
        assertTrue(log.contains("WARN"), "expected a WARN, got:\n" + log);
        assertTrue(log.contains("EMPTY sha256_cert_fingerprints list"), "expected the empty-list WARN, got:\n" + log);
        assertTrue(log.contains("Play Console"), "the WARN must say where the missing value comes from:\n" + log);
    }

    @Test
    void emptyIosAppIdsWarnsToo(@TempDir Path dir) throws Exception {
        PrintStream originalErr = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        String log;
        try {
            System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
            start(dir, "iosAppIds=");
        } finally {
            System.setErr(originalErr);
            log = captured.toString(StandardCharsets.UTF_8);
        }

        assertEquals(0, mapper.readTree(get(WellKnownController.AASA_PATH).body())
                .get("webcredentials").get("apps").size());
        assertTrue(log.contains("EMPTY webcredentials.apps list"), "expected the empty-apps WARN, got:\n" + log);
    }

    /** A placeholder that never got replaced must stop the boot, not silently publish broken JSON. */
    @Test
    void aPlaceholderDigestFailsAtStartup(@TempDir Path dir) throws Exception {
        Path properties = properties(dir, "androidWebCredentialDigests=PLAY_APP_SIGNING_SHA256_PLACEHOLDER");

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> Main.wire(Config.load(properties)));

        assertTrue(failure.getMessage().contains("Not a SHA-256 certificate digest"), failure.getMessage());
    }

    // ---------------------------------------------------------------- helpers

    private Path properties(Path dir, String... extra) throws Exception {
        Files.writeString(dir.resolve("users.json"), "[]", StandardCharsets.UTF_8);
        StringBuilder text = new StringBuilder()
                .append("usersFile=").append(dir.resolve("users.json")).append('\n')
                .append("vectorsDir=").append(dir.resolve("vectors")).append('\n')
                .append("cacheDir=").append(dir.resolve("cache")).append('\n');
        for (String line : extra) {
            text.append(line).append('\n');
        }
        Path file = dir.resolve("application.properties");
        Files.writeString(file, text.toString(), StandardCharsets.UTF_8);
        return file;
    }

    private void start(Path dir, String... extra) throws Exception {
        server = Main.wire(Config.load(properties(dir, extra)));
        server.app.start(0);
    }

    private HttpResponse<String> get(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + server.app.port() + path))
                .GET()
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String contentType(HttpResponse<String> response) {
        return response.headers().firstValue("content-type").orElse("<absent>");
    }
}
