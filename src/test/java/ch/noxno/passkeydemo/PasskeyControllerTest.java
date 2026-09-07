package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;

/**
 * Drives the HTTP layer on a random port with the real stores and a synthetic authenticator.
 * The credential is inserted into the store directly (as platform "android", so assertions need
 * no App Attest) because a full synthetic enrolment is impossible: android-key needs a
 * Google-signed chain and packed needs a real App Attest object.
 */
class PasskeyControllerTest {

    private static final String USER = "demo@example.com";
    private static final String PASSWORD = "Test123!";
    private static final String ADMIN_TOKEN = "hotline-secret";
    private static final String LEGACY_LOGIN = "{\"username\":\"" + USER + "\",\"password\":\"" + PASSWORD
            + "\",\"osVersion\":\"x\",\"appVersion\":\"y\",\"permanently\":false,\"challengeId\":\"0\",\"challengeResponse\":\"\"}";

    private final HttpClient http = HttpClient.newHttpClient();
    private Main.Wiring server;
    private String base;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("users.json"),
                "[{\"username\":\"" + USER + "\",\"password\":\"" + PASSWORD + "\"}]", StandardCharsets.UTF_8);
        Path properties = dir.resolve("application.properties");
        Files.writeString(properties, String.join("\n",
                "usersFile=" + dir.resolve("users.json"),
                "vectorsDir=" + dir.resolve("vectors"),
                "cacheDir=" + dir.resolve("cache"),
                "adminToken=" + ADMIN_TOKEN), StandardCharsets.UTF_8);
        server = Main.wire(Config.load(properties));
        server.app.start(0);
        base = "http://localhost:" + server.app.port() + PasskeyController.base(server.config);
    }

    @AfterEach
    void tearDown() {
        server.app.stop();
    }

    @Test
    void unlockInsideTheWindowIssuesAToken() throws Exception {
        TestAuthenticator authenticator = new TestAuthenticator(server.config.rpId());
        CredentialStore.Credential credential = enrol(authenticator);

        HttpResponse<String> response = unlock(authenticator);

        assertEquals(200, response.statusCode(), response.body());
        JsonNode login = json(response);
        assertEquals(64, login.get("token").asString().length());
        assertEquals("/tabs/home", login.get("startpage").asString());
        assertEquals(1L, credential.record.getCounter());
        assertNotNull(credential.lastUsedAt);
    }

    @Test
    void unlockOutsideTheWindowIsFullLoginRequired() throws Exception {
        TestAuthenticator authenticator = new TestAuthenticator(server.config.rpId());
        CredentialStore.Credential credential = enrol(authenticator);
        credential.fullLoginAt = Instant.now().minusSeconds(server.config.unlockWindowSeconds() + 60);

        HttpResponse<String> response = unlock(authenticator);

        assertEquals(403, response.statusCode(), response.body());
        assertEquals(ApiException.FULL_LOGIN_REQUIRED, json(response).get("errors").get(0).asString());
        assertEquals(0L, credential.record.getCounter(), "the assertion must not have been verified");
        assertNull(credential.lastUsedAt);
    }

    @Test
    void adminResetWithoutOrWithWrongTokenIs401() throws Exception {
        String body = "{\"username\":\"" + USER + "\"}";

        assertEquals(401, post("/passkey/admin/reset", body).statusCode());

        HttpResponse<String> wrong = post("/passkey/admin/reset", body, "X-Admin-Token", "nope");
        assertEquals(401, wrong.statusCode());
        assertEquals("TOKEN_INVALID", json(wrong).get("errors").get(0).asString());
    }

    @Test
    void adminResetRevokesCredentialsAndClearsPasskeyRequired() throws Exception {
        TestAuthenticator authenticator = new TestAuthenticator(server.config.rpId());
        CredentialStore.Credential credential = enrol(authenticator);
        HttpResponse<String> blocked = post("", LEGACY_LOGIN);
        assertEquals(403, blocked.statusCode(), blocked.body());
        assertEquals(ApiException.PASSKEY_REQUIRED, json(blocked).get("errors").get(0).asString());

        HttpResponse<String> reset = post("/passkey/admin/reset", "{\"username\":\"" + USER + "\"}",
                "X-Admin-Token", ADMIN_TOKEN);

        assertEquals(200, reset.statusCode(), reset.body());
        assertNotNull(credential.revokedAt);
        assertFalse(server.users.find(USER).orElseThrow().passkeyRequired);

        HttpResponse<String> login = post("", LEGACY_LOGIN);
        assertEquals(200, login.statusCode(), login.body());
        HttpResponse<String> list = get("/passkey/list", "authorization", "Bearer " + json(login).get("token").asString());
        assertEquals("[]", list.body());

        HttpResponse<String> unlock = unlock(authenticator);
        assertEquals(403, unlock.statusCode(), unlock.body());
        assertEquals(ApiException.CREDENTIAL_UNKNOWN, json(unlock).get("errors").get(0).asString());
    }

    /** A verified packed self attestation stored as an Android credential with fullLoginAt = now. */
    private CredentialStore.Credential enrol(TestAuthenticator authenticator) throws Exception {
        byte[] challenge = Base64Url.random(32);
        WebAuthnVerifier.RegistrationResult result =
                server.webAuthn.verifyRegistration(authenticator.registrationJson(challenge), challenge);
        Instant now = Instant.now();
        CredentialStore.Credential credential = new CredentialStore.Credential(
                Base64Url.encode(result.credentialId), result.credentialId, USER, result.record, "android",
                result.format, result.attestationObjectBytes, result.clientDataJsonBytes, "tee", "Testgerät", now);
        credential.aaguid = result.aaguid;
        credential.fullLoginAt = now;
        server.credentials.add(credential);
        server.users.find(USER).orElseThrow().passkeyRequired = true;
        return credential;
    }

    private HttpResponse<String> unlock(TestAuthenticator authenticator) throws Exception {
        JsonNode options = json(post("/passkey/unlock/options", "{}"));
        byte[] challenge = Base64Url.decode(options.get("publicKey").get("challenge").asString());
        byte[] userHandle = server.users.userHandle(server.users.find(USER).orElseThrow());
        String body = "{\"ceremonyId\":\"" + options.get("ceremonyId").asString()
                + "\",\"osVersion\":\"test\",\"appVersion\":\"test\",\"credential\":"
                + authenticator.assertionJson(challenge, userHandle, 1) + "}";
        return post("/passkey/unlock/verify", body);
    }

    private HttpResponse<String> post(String path, String body, String... headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String... headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path)).GET();
        for (int i = 0; i < headers.length; i += 2) {
            request.header(headers[i], headers[i + 1]);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode json(HttpResponse<String> response) {
        return server.mapper.readTree(response.body());
    }
}
