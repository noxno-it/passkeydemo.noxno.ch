package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;

/**
 * The packed (iOS) path end to end with a synthetic authenticator instead of a device, plus the
 * vector-gated chain-level rejection of an emulator (software root) registration.
 */
class WebAuthnVerifierTest {

    private Config config;
    private WebAuthnVerifier verifier;
    private TestAuthenticator authenticator;

    @BeforeEach
    void setUp() throws Exception {
        config = Config.defaults();
        verifier = new WebAuthnVerifier(config, new GoogleRoots(config, Json.mapper()));
        authenticator = new TestAuthenticator(config.rpId());
    }

    @Test
    void acceptsPackedSelfAttestation() throws Exception {
        byte[] challenge = Base64Url.random(32);
        WebAuthnVerifier.RegistrationResult result =
                verifier.verifyRegistration(authenticator.registrationJson(challenge), challenge);

        assertEquals(WebAuthnVerifier.FORMAT_PACKED, result.format);
        assertEquals(TestAuthenticator.AAGUID_IOS, result.aaguid);
        assertArrayEquals(authenticator.credentialId, result.credentialId);
        assertEquals(0L, result.record.getCounter());
    }

    @Test
    void rejectsWrongChallenge() throws Exception {
        byte[] challenge = Base64Url.random(32);
        String json = authenticator.registrationJson(challenge);

        ApiException failure = assertThrows(ApiException.class,
                () -> verifier.verifyRegistration(json, Base64Url.random(32)));
        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
    }

    @Test
    void rejectsAaguidThatDoesNotMatchTheFormat() throws Exception {
        // packed must carry the iOS constant; the Android one is a mismatch (spec 6.4)
        authenticator.aaguid = TestAuthenticator.AAGUID_ANDROID;
        byte[] challenge = Base64Url.random(32);
        String json = authenticator.registrationJson(challenge);

        ApiException failure = assertThrows(ApiException.class,
                () -> verifier.verifyRegistration(json, challenge));
        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
        assertTrue(failure.getMessage().contains("AAGUID"), failure.getMessage());
    }

    @Test
    void rejectsNoneAttestationFormat() throws Exception {
        byte[] challenge = Base64Url.random(32);
        String json = authenticator.registrationJsonWithoutAttestation(challenge);

        ApiException failure = assertThrows(ApiException.class,
                () -> verifier.verifyRegistration(json, challenge));
        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
    }

    /** Spec 9: with allowSoftwareAttestationRoot=false an emulator chain does not reach a Google root. */
    @Test
    void rejectsSoftwareRootVectorWhenNotAllowed(@TempDir Path dir) throws Exception {
        List<JsonNode> vectors = AndroidKeyVectorTest.softwareRootVectors();
        assumeFalse(vectors.isEmpty(), "no emulator vector (software attestation root) recorded yet");

        Config strict = AndroidKeyVectorTest.configWith(dir, "allowSoftwareAttestationRoot=false");
        WebAuthnVerifier strictVerifier = new WebAuthnVerifier(strict, new GoogleRoots(strict, Json.mapper()));

        for (JsonNode vector : vectors) {
            String credentialJson = Json.mapper().writeValueAsString(vector.get("request").get("credential"));
            byte[] challenge = Base64Url.decode(vector.get("challenge").asString());
            ApiException failure = assertThrows(ApiException.class,
                    () -> strictVerifier.verifyRegistration(credentialJson, challenge));
            assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
        }
    }

    @Test
    void acceptsAssertionAndRejectsCounterRegression() throws Exception {
        byte[] registrationChallenge = Base64Url.random(32);
        WebAuthnVerifier.RegistrationResult registration =
                verifier.verifyRegistration(authenticator.registrationJson(registrationChallenge),
                        registrationChallenge);

        byte[] loginChallenge = Base64Url.random(32);
        byte[] userHandle = Base64Url.random(32);
        WebAuthnVerifier.AssertionResult assertion = verifier.verifyAssertion(
                authenticator.assertionJson(loginChallenge, userHandle, 1), loginChallenge, registration.record);
        assertEquals(1L, assertion.signCount);
        assertArrayEquals(userHandle, assertion.userHandle);
        registration.record.setCounter(assertion.signCount);

        byte[] replayChallenge = Base64Url.random(32);
        String replay = authenticator.assertionJson(replayChallenge, userHandle, 1);
        ApiException failure = assertThrows(ApiException.class,
                () -> verifier.verifyAssertion(replay, replayChallenge, registration.record));
        assertEquals(ApiException.COUNTER_REGRESSION, failure.getCode());
    }

    @Test
    void rejectsAssertionForAnotherRpId() throws Exception {
        byte[] registrationChallenge = Base64Url.random(32);
        WebAuthnVerifier.RegistrationResult registration =
                verifier.verifyRegistration(authenticator.registrationJson(registrationChallenge),
                        registrationChallenge);

        TestAuthenticator foreign = new TestAuthenticator("attacker.example");
        byte[] challenge = Base64Url.random(32);
        String json = foreign.assertionJson(challenge, Base64Url.random(32), 1);

        ApiException failure = assertThrows(ApiException.class,
                () -> verifier.verifyAssertion(json, challenge, registration.record));
        assertEquals(ApiException.ATTESTATION_REJECTED, failure.getCode());
    }
}
