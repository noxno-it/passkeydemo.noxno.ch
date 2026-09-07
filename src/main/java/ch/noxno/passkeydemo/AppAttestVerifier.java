package ch.noxno.passkeydemo;

import com.webauthn4j.appattest.DeviceCheckManager;
import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.appattest.authenticator.DCAppleDeviceImpl;
import com.webauthn4j.appattest.data.DCAssertionData;
import com.webauthn4j.appattest.data.DCAssertionParameters;
import com.webauthn4j.appattest.data.DCAssertionRequest;
import com.webauthn4j.appattest.data.DCAttestationData;
import com.webauthn4j.appattest.data.DCAttestationParameters;
import com.webauthn4j.appattest.data.DCAttestationRequest;
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement;
import com.webauthn4j.appattest.server.DCServerProperty;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import com.webauthn4j.verifier.exception.VerificationException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Apple App Attest, verified with webauthn4j-appattest. On iOS the WebAuthn attestation is a
 * packed self attestation, so this is the part that proves genuine Apple hardware and an
 * unmodified build - bound to the credential through
 * clientDataHash = SHA256(SHA256(webauthnAttestationObject) || appAttestChallenge).
 */
public final class AppAttestVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(AppAttestVerifier.class);

    public static final String ENVIRONMENT_PRODUCTION = "appattest";
    public static final String ENVIRONMENT_DEVELOPMENT = "appattestdevelop";

    private static final byte[] AAGUID_PRODUCTION = "appattest\0\0\0\0\0\0\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAGUID_DEVELOPMENT = "appattestdevelop".getBytes(StandardCharsets.UTF_8);

    /**
     * Everything the server persists per iOS credential. receipt is the App Attest receipt of the
     * attestation statement (AppleAppAttestAttestationStatement.getReceipt()), stored so a production
     * backend can later exchange it with Apple for fraud metrics (spec 6.5).
     */
    public static final class AttestationResult {
        public final DCAppleDevice device;
        public final String environment;
        public final String appId;
        public final byte[] keyId;
        public final byte[] receipt;

        AttestationResult(DCAppleDevice device, String environment, String appId, byte[] keyId, byte[] receipt) {
            this.device = device;
            this.environment = environment;
            this.appId = appId;
            this.keyId = keyId;
            this.receipt = receipt;
        }
    }

    private final Config config;
    private final DeviceCheckManager manager;

    public AppAttestVerifier(Config config) {
        this.config = config;
        X509Certificate appleRoot = GoogleRoots.parseCertificate(config.appleAppAttestRootPem());
        this.manager = new DeviceCheckManager(new AppleCertPathVerifier(appleRoot),
                DeviceCheckManager.createObjectConverter());
    }

    /** Registration binding: SHA256(SHA256(webauthnAttestationObject) || appAttestChallenge). */
    public static byte[] registrationClientDataHash(byte[] webauthnAttestationObject, byte[] appAttestChallenge) {
        return Base64Url.sha256(
                Base64Url.concat(Base64Url.sha256(webauthnAttestationObject), appAttestChallenge));
    }

    /** Assertion binding: SHA256(SHA256(authenticatorData) || SHA256(clientDataJSON) || appAttestChallenge). */
    public static byte[] assertionClientDataHash(byte[] authenticatorData, byte[] clientDataJson,
            byte[] appAttestChallenge) {
        return Base64Url.sha256(Base64Url.concat(
                Base64Url.sha256(authenticatorData), Base64Url.sha256(clientDataJson), appAttestChallenge));
    }

    /**
     * @param keyIdBase64            standard base64 keyId as returned by DCAppAttestService.generateKey
     * @param attestationBase64      standard base64 of the CBOR attestation object from attestKey
     * @param webauthnAttestationObject raw bytes of the WebAuthn attestationObject of the same ceremony
     * @param appAttestChallenge     the ceremony's App Attest challenge (32 bytes)
     */
    public AttestationResult verifyAttestation(String keyIdBase64, String attestationBase64,
            byte[] webauthnAttestationObject, byte[] appAttestChallenge) {
        byte[] keyId;
        byte[] attestation;
        try {
            keyId = Base64Url.decodeStandard(keyIdBase64);
            attestation = Base64Url.decodeStandard(attestationBase64);
        } catch (RuntimeException e) {
            throw ApiException.attestationRejected("deviceAttestation ist kein gültiges Base64", e);
        }
        byte[] clientDataHash = registrationClientDataHash(webauthnAttestationObject, appAttestChallenge);

        DCAttestationRequest request = new DCAttestationRequest(keyId, attestation, clientDataHash);
        DCAttestationData data;
        try {
            data = manager.parse(request);
        } catch (RuntimeException e) {
            throw ApiException.attestationRejected("App-Attest-Objekt konnte nicht gelesen werden", e);
        }
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData =
                data.getAttestationObject().getAuthenticatorData();
        AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();
        if (attestedCredentialData == null) {
            throw ApiException.attestationRejected("App Attest ohne attestedCredentialData");
        }

        String environment = environmentOf(attestedCredentialData.getAaguid());
        Set<String> allowedEnvironments = config.appAttestEnvironments();
        if (!allowedEnvironments.contains(environment)) {
            throw ApiException.deviceNotEligible("App-Attest-Umgebung " + environment + " ist nicht erlaubt");
        }
        String appId = appIdFor(authenticatorData.getRpIdHash());

        try {
            synchronized (manager) {
                manager.getAttestationDataValidator().setProduction(ENVIRONMENT_PRODUCTION.equals(environment));
                // DCServerProperty(rpId = "TEAMID.bundleId", challenge); the 3-arg
                // (teamIdentifier, cfBundleIdentifier, challenge) form is equivalent in 0.31.10.RELEASE
                manager.validate(data, new DCAttestationParameters(
                        new DCServerProperty(appId, new DefaultChallenge(appAttestChallenge))));
            }
        } catch (VerificationException e) {
            throw ApiException.attestationRejected("App Attest: " + e.getMessage(), e);
        }

        verifyAppleExtensions(authenticatorData, environment);

        // DeviceCheckManager only knows fmt=apple-appattest, so after validate() this cast holds;
        // the statement carries the receipt next to the x5c chain
        AttestationStatement statement = data.getAttestationObject().getAttestationStatement();
        if (!(statement instanceof AppleAppAttestAttestationStatement appleStatement)) {
            throw ApiException.attestationRejected("App-Attest-Statement hat nicht das Format apple-appattest");
        }
        DCAppleDevice device = new DCAppleDeviceImpl(attestedCredentialData, appleStatement,
                authenticatorData.getSignCount(), authenticatorData.getExtensions());
        return new AttestationResult(device, environment, appId, keyId, appleStatement.getReceipt());
    }

    /**
     * @param clientDataHash SHA256(SHA256(authenticatorData) || SHA256(clientDataJSON) || appAttestChallenge)
     * @return the new App Attest counter, already written into the stored device
     */
    public long verifyAssertion(CredentialStore.Credential credential, String assertionBase64, byte[] clientDataHash) {
        if (credential.appAttestDevice == null || credential.appAttestKeyId == null) {
            throw ApiException.attestationRejected("für diesen Passkey ist kein App-Attest-Schlüssel hinterlegt");
        }
        byte[] keyId;
        byte[] assertion;
        try {
            keyId = Base64Url.decodeStandard(credential.appAttestKeyId);
            assertion = Base64Url.decodeStandard(assertionBase64);
        } catch (RuntimeException e) {
            throw ApiException.attestationRejected("deviceAssertion ist kein gültiges Base64", e);
        }
        DCAssertionRequest request = new DCAssertionRequest(keyId, assertion, clientDataHash);
        DCAssertionData data;
        try {
            data = manager.validate(request, new DCAssertionParameters(
                    new DCServerProperty(credential.appAttestAppId, null), credential.appAttestDevice));
        } catch (MaliciousCounterValueException e) {
            throw ApiException.counterRegression();
        } catch (RuntimeException e) {
            throw ApiException.attestationRejected("App-Attest-Assertion: " + e.getMessage(), e);
        }
        long counter = data.getAuthenticatorData().getSignCount();
        credential.appAttestDevice.setCounter(counter);
        return counter;
    }

    static String environmentOf(AAGUID aaguid) {
        byte[] bytes = aaguid.getBytes();
        if (Arrays.equals(bytes, AAGUID_PRODUCTION)) {
            return ENVIRONMENT_PRODUCTION;
        }
        if (Arrays.equals(bytes, AAGUID_DEVELOPMENT)) {
            return ENVIRONMENT_DEVELOPMENT;
        }
        return "unknown";
    }

    private String appIdFor(byte[] rpIdHash) {
        for (String appId : config.iosAppIds()) {
            if (Base64Url.constantTimeEquals(rpIdHash, Base64Url.sha256(Base64Url.utf8(appId)))) {
                return appId;
            }
        }
        throw ApiException.deviceNotEligible("die App-ID der Attestierung ist nicht konfiguriert");
    }

    /**
     * WWDC26 added apple_validation_category_01 (UInt32) and apple_bundle_version_01 (String) to the
     * authenticator data. Older systems omit them, so absence is tolerated and only logged.
     */
    private void verifyAppleExtensions(AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData,
            String environment) {
        Object category = authenticatorData.getExtensions().getValue("apple_validation_category_01");
        Object bundleVersion = authenticatorData.getExtensions().getValue("apple_bundle_version_01");
        if (category == null) {
            LOG.info("App Attest without apple_validation_category_01 (older iOS) - tolerated");
            return;
        }
        if (!(category instanceof Number number)) {
            throw ApiException.attestationRejected("apple_validation_category_01 ist keine Zahl");
        }
        int value = number.intValue();
        List<Integer> allowed = ENVIRONMENT_PRODUCTION.equals(environment) ? List.of(2, 4) : List.of(3);
        if (!allowed.contains(value)) {
            throw ApiException.attestationRejected(
                    "apple_validation_category_01=" + value + " ist in der Umgebung " + environment + " nicht erlaubt");
        }
        LOG.info("App Attest validation category {} bundle version {}", value, bundleVersion);
    }

    /** Verifies credCert -> intermediate -> Apple App Attestation Root CA, validity enforced. */
    private static final class AppleCertPathVerifier implements CertPathTrustworthinessVerifier {

        private final X509Certificate root;

        AppleCertPathVerifier(X509Certificate root) {
            this.root = root;
        }

        @Override
        public void verify(AAGUID aaguid, CertificateBaseAttestationStatement attestationStatement, Instant timestamp) {
            List<X509Certificate> chain = attestationStatement.getX5c();
            if (chain == null || chain.isEmpty()) {
                throw new BadAttestationStatementException("App Attest statement without x5c");
            }
            Date at = Date.from(timestamp);
            try {
                for (int i = 0; i < chain.size() - 1; i++) {
                    chain.get(i).verify(chain.get(i + 1).getPublicKey());
                }
                chain.get(chain.size() - 1).verify(root.getPublicKey());
                for (X509Certificate certificate : chain) {
                    certificate.checkValidity(at);
                }
                root.checkValidity(at);
            } catch (Exception e) {
                throw new BadAttestationStatementException(
                        "App Attest chain does not verify against the Apple App Attestation Root CA", e);
            }
        }
    }
}
