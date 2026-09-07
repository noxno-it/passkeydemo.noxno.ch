package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import com.webauthn4j.appattest.DeviceCheckManager;
import com.webauthn4j.appattest.data.DCAttestationData;
import com.webauthn4j.appattest.data.DCAttestationRequest;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

/**
 * Replays every recorded iOS registration and checks the binding that makes App Attest meaningful
 * for this design: nonce == SHA256(appAttestAuthData || SHA256(SHA256(webauthnAttestationObject) ||
 * appAttestChallenge)) and SHA256(credCert public key) == keyId. Skipped when vectors/ios-*.json
 * does not exist yet. Apple's leaf certificates live three days, so chain validity is verified live
 * by AppAttestVerifier and not replayed here.
 */
class AppAttestVectorTest {

    private static final String APPLE_NONCE_OID = "1.2.840.113635.100.8.2";

    @Test
    void replaysRecordedIosRegistrations() throws Exception {
        List<JsonNode> vectors = VectorFiles.load("ios", "register");
        assumeFalse(vectors.isEmpty(), "no vectors/ios-*.json recorded yet");

        DeviceCheckManager manager = DeviceCheckManager.createNonStrictDeviceCheckManager();
        AttestationObjectConverter converter =
                new AttestationObjectConverter(DeviceCheckManager.createObjectConverter());

        for (JsonNode vector : vectors) {
            JsonNode request = vector.get("request");
            byte[] appAttestChallenge = Base64Url.decode(vector.get("appAttestChallenge").asString());
            byte[] webauthnAttestationObject = Base64Url.decode(
                    request.get("credential").get("response").get("attestationObject").asString());
            byte[] keyId = Base64Url.decodeStandard(request.get("deviceAttestation").get("keyId").asString());
            byte[] appAttestObject = Base64Url.decodeStandard(
                    request.get("deviceAttestation").get("attestationObject").asString());

            byte[] clientDataHash = AppAttestVerifier.registrationClientDataHash(
                    webauthnAttestationObject, appAttestChallenge);
            DCAttestationData data = manager.parse(new DCAttestationRequest(keyId, appAttestObject, clientDataHash));

            byte[] appAttestAuthData = converter.extractAuthenticatorData(appAttestObject);
            byte[] expectedNonce = Base64Url.sha256(Base64Url.concat(appAttestAuthData, clientDataHash));

            CertificateBaseAttestationStatement statement =
                    (CertificateBaseAttestationStatement) data.getAttestationObject().getAttestationStatement();
            X509Certificate credCert = statement.getX5c().get(0);
            byte[] extension = credCert.getExtensionValue(APPLE_NONCE_OID);
            assertNotNull(extension, "credCert has no " + APPLE_NONCE_OID + " extension");
            ASN1OctetString wrapper = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extension));
            ASN1Sequence sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(wrapper.getOctets()));
            ASN1OctetString nonce = ASN1OctetString.getInstance(
                    org.bouncycastle.asn1.ASN1TaggedObject.getInstance(sequence.getObjectAt(0))
                            .getExplicitBaseObject());
            assertArrayEquals(expectedNonce, nonce.getOctets(), "App Attest nonce is not bound to the credential");

            ECPublicKey publicKey = (ECPublicKey) credCert.getPublicKey();
            byte[] uncompressed = Base64Url.concat(new byte[] { 0x04 },
                    coordinate(publicKey.getW().getAffineX()), coordinate(publicKey.getW().getAffineY()));
            assertArrayEquals(keyId, Base64Url.sha256(uncompressed), "SHA256(credCert public key) != keyId");

            assertEquals(0L, data.getAttestationObject().getAuthenticatorData().getSignCount());
        }
    }

    private static byte[] coordinate(java.math.BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        if (raw.length >= 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }
}
