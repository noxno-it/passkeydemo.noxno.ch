package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;

/**
 * Replays every recorded Android registration through AndroidKeyAttestationPolicy, including the
 * policy-level negative cases of spec section 9 (the chain-level software-root rejection lives in
 * WebAuthnVerifierTest). Skipped when vectors/android-*.json does not exist yet - record one by
 * enrolling on a real phone (or, for the software-root case, an emulator) against this server.
 * Certificate validity and revocation are deliberately not replayed here: they are time-dependent
 * and belong to GoogleRoots.
 */
class AndroidKeyVectorTest {

    private static final AttestationObjectConverter CONVERTER =
            new AttestationObjectConverter(new ObjectConverter());

    @Test
    void replaysRecordedAndroidRegistrations() throws Exception {
        List<JsonNode> vectors = VectorFiles.load("android", "register");
        assumeFalse(vectors.isEmpty(), "no vectors/android-*.json recorded yet");

        AndroidKeyAttestationPolicy policy = new AndroidKeyAttestationPolicy(Config.defaults());

        for (JsonNode vector : vectors) {
            AndroidKeyAttestationPolicy.Result result = policy.verify(chainOf(vector), clientDataHashOf(vector));
            assertNotNull(result.securityLevel);
            assertTrue(List.of("tee", "strongbox", "software").contains(result.securityLevel),
                    "unexpected security level " + result.securityLevel);
            assertTrue(new String(clientDataJsonOf(vector), StandardCharsets.UTF_8)
                    .contains(vector.get("challenge").asString()), "clientDataJSON does not carry the recorded challenge");
        }
    }

    /** Spec 9: a software security level (emulator) is DEVICE_NOT_ELIGIBLE once the test knob is off. */
    @Test
    void rejectsSoftwareSecurityLevelWhenNotAllowed(@TempDir Path dir) throws Exception {
        List<JsonNode> vectors = softwareRootVectors();
        assumeFalse(vectors.isEmpty(), "no emulator vector (software attestation root) recorded yet");

        AndroidKeyAttestationPolicy policy = new AndroidKeyAttestationPolicy(
                configWith(dir, "allowSoftwareAttestationRoot=false"));

        for (JsonNode vector : vectors) {
            List<X509Certificate> chain = chainOf(vector);
            byte[] clientDataHash = clientDataHashOf(vector);
            ApiException failure = assertThrows(ApiException.class, () -> policy.verify(chain, clientDataHash));
            assertEquals(ApiException.DEVICE_NOT_ELIGIBLE, failure.getCode());
        }
    }

    /** Spec 9: a foreign package name or signing digest fails the app-identity rule of spec 6.4. */
    @Test
    void rejectsForeignPackageAndSigningDigest(@TempDir Path dir) throws Exception {
        List<JsonNode> vectors = VectorFiles.load("android", "register");
        assumeFalse(vectors.isEmpty(), "no vectors/android-*.json recorded yet");

        AndroidKeyAttestationPolicy foreignPackage = new AndroidKeyAttestationPolicy(
                configWith(dir, "androidPackageName=com.example.other"));
        AndroidKeyAttestationPolicy foreignDigest = new AndroidKeyAttestationPolicy(
                configWith(dir, "androidSigningDigests=" + "00".repeat(32)));

        for (JsonNode vector : vectors) {
            List<X509Certificate> chain = chainOf(vector);
            byte[] clientDataHash = clientDataHashOf(vector);

            ApiException packageFailure = assertThrows(ApiException.class,
                    () -> foreignPackage.verify(chain, clientDataHash));
            assertEquals(ApiException.ATTESTATION_REJECTED, packageFailure.getCode());
            assertTrue(packageFailure.getMessage().contains("packageName"), packageFailure.getMessage());

            ApiException digestFailure = assertThrows(ApiException.class,
                    () -> foreignDigest.verify(chain, clientDataHash));
            assertEquals(ApiException.ATTESTATION_REJECTED, digestFailure.getCode());
            assertTrue(digestFailure.getMessage().contains("Signaturzertifikat"), digestFailure.getMessage());
        }
    }

    /** The recorded Android registrations whose chain ends in the AOSP software attestation root. */
    static List<JsonNode> softwareRootVectors() throws IOException {
        List<JsonNode> out = new ArrayList<>();
        for (JsonNode vector : VectorFiles.load("android", "register")) {
            List<X509Certificate> chain = chainOf(vector);
            if (GoogleRoots.isSoftwareRoot(chain.get(chain.size() - 1))) {
                out.add(vector);
            }
        }
        return out;
    }

    static byte[] clientDataJsonOf(JsonNode vector) {
        return Base64Url.decode(vector.get("request").get("credential").get("response").get("clientDataJSON").asString());
    }

    static byte[] clientDataHashOf(JsonNode vector) {
        return Base64Url.sha256(clientDataJsonOf(vector));
    }

    static List<X509Certificate> chainOf(JsonNode vector) {
        byte[] attestationObjectBytes = Base64Url.decode(
                vector.get("request").get("credential").get("response").get("attestationObject").asString());
        AttestationObject attestationObject = CONVERTER.convert(attestationObjectBytes);
        assertEquals(AndroidKeyAttestationStatement.FORMAT, attestationObject.getFormat());
        return ((AndroidKeyAttestationStatement) attestationObject.getAttestationStatement()).getX5c();
    }

    /** A Config with the defaults, one overridden line and a private cache directory. */
    static Config configWith(Path dir, String line) throws IOException {
        Path file = Files.createTempFile(dir, "config", ".properties");
        Files.writeString(file, line + "\ncacheDir=" + dir.resolve("cache") + "\n", StandardCharsets.UTF_8);
        return Config.load(file);
    }
}
