package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;

/**
 * attestationPolicy=strict|demo: what each policy accepts, how an unattested credential is marked,
 * and that the whole /demo surface does not exist outside demo mode.
 */
class AttestationPolicyTest {

    private static final String USER = "demo@example.com";
    private static final String PASSWORD = "Test123!";

    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private Main.Wiring server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.app.stop();
            server = null;
        }
    }

    // ------------------------------------------------------------ verifier level

    @Test
    void strictRejectsFmtNone() throws Exception {
        Config strict = Config.defaults();
        assertEquals("strict", strict.attestationPolicy());
        WebAuthnVerifier verifier = new WebAuthnVerifier(strict, new GoogleRoots(strict, Json.mapper()));
        TestAuthenticator authenticator = new TestAuthenticator(strict.rpId());
        byte[] challenge = Base64Url.random(32);
        String json = authenticator.registrationJsonWithoutAttestation(challenge);

        ApiException failure = assertThrows(ApiException.class, () -> verifier.verifyRegistration(json, challenge));

        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
        assertTrue(failure.getMessage().contains("none"), failure.getMessage());
        assertTrue(failure.getMessage().contains("strict"), failure.getMessage());
    }

    @Test
    void demoAcceptsFmtNoneAndMarksItUnattested(@TempDir Path dir) throws Exception {
        Config demo = config(dir, "attestationPolicy=demo");
        WebAuthnVerifier verifier = new WebAuthnVerifier(demo, new GoogleRoots(demo, Json.mapper()));
        TestAuthenticator authenticator = new TestAuthenticator(demo.rpId());
        byte[] challenge = Base64Url.random(32);

        WebAuthnVerifier.RegistrationResult result =
                verifier.verifyRegistration(authenticator.registrationJsonWithoutAttestation(challenge), challenge);

        assertEquals(WebAuthnVerifier.FORMAT_NONE, result.format);
        assertFalse(result.attestedFormat, "fmt=none must never count as attested");
        assertTrue(result.deviceBound, "BE/BS were clear in this vector");
        assertFalse(result.backupEligible);
    }

    /** Demo mode tolerates a syncable passkey for fmt=none, and records that it is not device bound. */
    @Test
    void demoRecordsASyncablePasskeyAsNotDeviceBound(@TempDir Path dir) throws Exception {
        Config demo = config(dir, "attestationPolicy=demo");
        WebAuthnVerifier verifier = new WebAuthnVerifier(demo, new GoogleRoots(demo, Json.mapper()));
        TestAuthenticator authenticator = new TestAuthenticator(demo.rpId());
        authenticator.extraFlags = 0x18; // BE | BS
        byte[] challenge = Base64Url.random(32);

        WebAuthnVerifier.RegistrationResult result =
                verifier.verifyRegistration(authenticator.registrationJsonWithoutAttestation(challenge), challenge);

        assertFalse(result.attestedFormat);
        assertFalse(result.deviceBound);
        assertTrue(result.backupEligible);
        assertTrue(result.backupState);

        // the assertion of such a credential must still verify, with the BE/BS check relaxed for it
        byte[] loginChallenge = Base64Url.random(32);
        WebAuthnVerifier.AssertionResult assertion = verifier.verifyAssertion(
                authenticator.assertionJson(loginChallenge, Base64Url.random(32), 1), loginChallenge,
                result.record, false);
        assertEquals(1L, assertion.signCount);
    }

    /** Even in demo mode a device-bound credential still has to stay device bound. */
    @Test
    void demoStillRejectsASyncableAssertionForADeviceBoundCredential(@TempDir Path dir) throws Exception {
        Config demo = config(dir, "attestationPolicy=demo");
        WebAuthnVerifier verifier = new WebAuthnVerifier(demo, new GoogleRoots(demo, Json.mapper()));
        TestAuthenticator authenticator = new TestAuthenticator(demo.rpId());
        byte[] challenge = Base64Url.random(32);
        WebAuthnVerifier.RegistrationResult result =
                verifier.verifyRegistration(authenticator.registrationJson(challenge), challenge);
        assertTrue(result.deviceBound);

        authenticator.extraFlags = 0x18;
        byte[] loginChallenge = Base64Url.random(32);
        String json = authenticator.assertionJson(loginChallenge, Base64Url.random(32), 1);

        ApiException failure = assertThrows(ApiException.class,
                () -> verifier.verifyAssertion(json, loginChallenge, result.record, true));
        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
    }

    @Test
    void acceptedOriginsIsEnforcedAndAnUnlistedOriginIsRejected(@TempDir Path dir) throws Exception {
        Config demo = config(dir, "attestationPolicy=demo", "rpId=passkeys.example.org",
                "acceptedOrigins=https://passkeys.example.org,android:apk-key-hash:AAAA");
        WebAuthnVerifier verifier = new WebAuthnVerifier(demo, new GoogleRoots(demo, Json.mapper()));
        assertEquals(2, verifier.acceptedOrigins().size());

        // TestAuthenticator writes origin https://<its rpId>; an authenticator that claims a
        // different rpId therefore also carries an origin that is not in the accepted set
        TestAuthenticator foreign = new TestAuthenticator("evil.example");
        byte[] challenge = Base64Url.random(32);
        String json = foreign.registrationJson(challenge);

        ApiException failure = assertThrows(ApiException.class, () -> verifier.verifyRegistration(json, challenge));
        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
    }

    // ------------------------------------------------------------ HTTP level

    @Test
    void demoEndpointsAnd404InStrictMode(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=strict");

        assertEquals(404, post("/demo/api/register/options", "{\"username\":\"demo\"}").statusCode());
        assertEquals(404, post("/demo/api/register/verify", "{}").statusCode());
        assertEquals(404, post("/demo/api/login/options", "{}").statusCode());
        assertEquals(404, post("/demo/api/login/verify", "{}").statusCode());
        assertEquals(404, get("/demo/api/status").statusCode());
        assertEquals(404, get("/demo/api/list?username=demo").statusCode());
        assertEquals(404, get("/demo/").statusCode(), "no static files outside demo mode");
    }

    @Test
    void demoEndpointsDriveAFullCeremonyInDemoMode(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=demo");
        TestAuthenticator authenticator = new TestAuthenticator(server.config.rpId());

        JsonNode status = json(get("/demo/api/status"));
        assertEquals("demo", status.get("attestationPolicy").asString());
        assertEquals("passkeydemo.noxno.ch", status.get("rpId").asString(), "the shipped default rpId");
        assertTrue(status.get("noneAccepted").asBoolean());

        JsonNode options = json(post("/demo/api/register/options", "{\"username\":\"Demo@Example.COM\"}"));
        assertEquals("passkeydemo.noxno.ch", options.get("publicKey").get("rp").get("id").asString());
        // Demo mode accepts fmt=none, so it must ASK for none. Asking for "direct" here made
        // a security key emit packed+x5c, which then failed the cert-path check with
        // "invalid cert path" - a real failure seen against Chrome's virtual authenticator.
        assertEquals("none", options.get("publicKey").get("attestation").asString());
        byte[] challenge = Base64Url.decode(options.get("publicKey").get("challenge").asString());
        byte[] userHandle = Base64Url.decode(options.get("publicKey").get("user").get("id").asString());

        HttpResponse<String> registered = post("/demo/api/register/verify",
                "{\"ceremonyId\":\"" + options.get("ceremonyId").asString() + "\",\"credential\":"
                        + authenticator.registrationJsonWithoutAttestation(challenge) + "}");
        assertEquals(200, registered.statusCode(), registered.body());
        JsonNode body = json(registered);
        assertEquals("demo@example.com", body.get("username").asString());
        assertEquals("none", body.get("attestationFmt").asString());
        assertFalse(body.get("attested").asBoolean(), "fmt=none must be marked unattested");
        assertTrue(body.get("attestationNote").asString().contains("none"));

        JsonNode listed = json(get("/demo/api/list?username=demo@example.com"));
        assertEquals(1, listed.size());
        assertFalse(listed.get(0).get("attested").asBoolean());
        assertEquals("none", listed.get(0).get("attestationFmt").asString());

        JsonNode loginOptions = json(post("/demo/api/login/options", "{\"username\":\"demo@example.com\"}"));
        byte[] loginChallenge = Base64Url.decode(loginOptions.get("publicKey").get("challenge").asString());
        HttpResponse<String> loggedIn = post("/demo/api/login/verify",
                "{\"ceremonyId\":\"" + loginOptions.get("ceremonyId").asString() + "\",\"credential\":"
                        + authenticator.assertionJson(loginChallenge, userHandle, 1) + "}");
        assertEquals(200, loggedIn.statusCode(), loggedIn.body());
        assertEquals(1L, json(loggedIn).get("signCount").asLong());
        assertFalse(json(loggedIn).get("attested").asBoolean());
    }

    /** A demo ceremonyId must not open the compliance endpoints, and vice versa. */
    @Test
    void demoAndComplianceCeremoniesAreSeparate(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=demo");
        String demoCeremony = json(post("/demo/api/login/options", "{}")).get("ceremonyId").asString();

        HttpResponse<String> crossed = post(PasskeyController.base(server.config) + "/passkey/unlock/verify",
                "{\"ceremonyId\":\"" + demoCeremony + "\",\"credential\":{\"id\":\"x\"}}");

        assertEquals(403, crossed.statusCode(), crossed.body());
        assertEquals(ApiException.CEREMONY_EXPIRED, json(crossed).get("errors").get(0).asString());
    }

    /** The marking has to be visible where the app reads it: passkey/list. */
    @Test
    void passkeyListMarksAnUnattestedCredential(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=demo");
        TestAuthenticator authenticator = new TestAuthenticator(server.config.rpId());
        String token = enrolThroughTheAppEndpoints(authenticator, "none");

        JsonNode listed = json(get(PasskeyController.base(server.config) + "/passkey/list",
                "authorization", "Bearer " + token));

        assertEquals(1, listed.size());
        assertFalse(listed.get(0).get("attested").asBoolean());
        assertEquals("none", listed.get(0).get("attestationFmt").asString());
        assertEquals("web", listed.get(0).get("platform").asString());
        assertEquals("none", listed.get(0).get("securityLevel").asString());
        assertNotNull(listed.get(0).get("attestationNote"));
    }

    @Test
    void theAppEndpointRejectsFmtNoneInStrictMode(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=strict");
        TestAuthenticator authenticator = new TestAuthenticator(server.config.rpId());

        ApiException failure = assertThrows(ApiException.class,
                () -> enrolThroughTheAppEndpoints(authenticator, "none"));

        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
    }

    @Test
    void demoModeServesTheStaticDemoPage(@TempDir Path dir) throws Exception {
        start(dir, "attestationPolicy=demo", "staticDir=" + dir.resolve("does-not-exist"));

        HttpResponse<String> page = get("/demo/");

        assertEquals(200, page.statusCode());
        assertTrue(page.body().contains("<html"), page.body());
        assertTrue(page.body().contains("fmt=none"), "the placeholder has to state the attestation truth");
        // Jetty itself sends /demo -> /demo/ so the relative asset paths of the page resolve
        assertEquals(302, get("/demo").statusCode());
    }

    // ------------------------------------------------------------ helpers

    /**
     * Runs the real app enrolment: legacy password login for a bearer token, register/options with
     * the password, then register/verify with the requested attestation format.
     *
     * @return the bearer token; throws the ApiException of register/verify when it is refused
     */
    private String enrolThroughTheAppEndpoints(TestAuthenticator authenticator, String fmt) throws Exception {
        HttpResponse<String> login = post(PasskeyController.base(server.config), "{\"username\":\"" + USER
                + "\",\"password\":\"" + PASSWORD + "\",\"permanently\":false}");
        assertEquals(200, login.statusCode(), login.body());
        String token = json(login).get("token").asString();

        JsonNode options = json(post(PasskeyController.base(server.config) + "/passkey/register/options",
                "{\"password\":\"" + PASSWORD + "\"}", "authorization", "Bearer " + token));
        byte[] challenge = Base64Url.decode(options.get("publicKey").get("challenge").asString());
        String credentialJson = "none".equals(fmt)
                ? authenticator.registrationJsonWithoutAttestation(challenge)
                : authenticator.registrationJson(challenge);

        HttpResponse<String> verified = post(PasskeyController.base(server.config) + "/passkey/register/verify",
                "{\"ceremonyId\":\"" + options.get("ceremonyId").asString()
                        + "\",\"deviceName\":\"Browser\",\"credential\":" + credentialJson + "}",
                "authorization", "Bearer " + token);
        if (verified.statusCode() != 200) {
            throw new ApiException(json(verified).get("errors").get(0).asString(), verified.body());
        }
        return token;
    }

    private Config config(Path dir, String... lines) throws Exception {
        Files.writeString(dir.resolve("users.json"),
                "[{\"username\":\"" + USER + "\",\"password\":\"" + PASSWORD + "\"}]", StandardCharsets.UTF_8);
        Path properties = dir.resolve("application.properties");
        StringBuilder text = new StringBuilder()
                .append("usersFile=").append(dir.resolve("users.json")).append('\n')
                .append("vectorsDir=").append(dir.resolve("vectors")).append('\n')
                .append("cacheDir=").append(dir.resolve("cache")).append('\n');
        for (String line : lines) {
            text.append(line).append('\n');
        }
        Files.writeString(properties, text.toString(), StandardCharsets.UTF_8);
        return Config.load(properties);
    }

    private void start(Path dir, String... lines) throws Exception {
        server = Main.wire(config(dir, lines));
        server.app.start(0);
    }

    private String url(String path) {
        return "http://localhost:" + server.app.port() + path;
    }

    private HttpResponse<String> post(String path, String body, String... headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url(path)))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Never follows redirects, so /demo -> /demo/ is observable as a 302. */
    private HttpResponse<String> get(String path, String... headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url(path))).GET();
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode json(HttpResponse<String> response) {
        return server.mapper.readTree(response.body());
    }
}
