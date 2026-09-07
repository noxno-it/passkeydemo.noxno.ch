package ch.noxno.passkeydemo;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.attestation.statement.AttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import com.webauthn4j.verifier.exception.VerificationException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The WebAuthn half of spec section 6.4: strict webauthn4j verification with
 * AndroidKeyAttestationStatementVerifier (chain checked against the Google roots) and
 * PackedAttestationStatementVerifier (iOS self attestation), plus the checks webauthn4j
 * leaves to the relying party (BE/BS, signCount==0, ES256, accepted formats, the app's AAGUID).
 *
 * <p>With attestationPolicy=demo a third format, fmt=none, is additionally accepted. A browser
 * always produces fmt=none - it is <em>not</em> hardware attestation, and every credential that
 * arrives that way is flagged {@code attested=false} so it can never be mistaken for one of the
 * two attested formats.
 */
public final class WebAuthnVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnVerifier.class);

    public static final String FORMAT_ANDROID_KEY = AndroidKeyAttestationStatement.FORMAT;
    public static final String FORMAT_PACKED = PackedAttestationStatement.FORMAT;
    /** "none" - what every browser returns, and what demo mode additionally accepts. */
    public static final String FORMAT_NONE = NoneAttestationStatement.FORMAT;

    /**
     * The relying party's own app AAGUIDs: the attestation format decides which one an attested
     * registration must carry. These are EXAMPLE values for the demo - a real deployment substitutes
     * the AAGUIDs its own authenticator implementation reports.
     */
    public static final AAGUID AAGUID_ANDROID = new AAGUID("2b9c7d6e-5f4a-4c3b-8a2d-1e0f9c8b7a6d");
    public static final AAGUID AAGUID_IOS = new AAGUID("7a0e4c5e-1d3b-4b8f-9a6c-3f2e1d0c9b8a");

    public static final class RegistrationResult {
        public final RegistrationData data;
        public final String format;
        public final String aaguid;
        public final byte[] credentialId;
        public final CredentialRecord record;
        public final byte[] attestationObjectBytes;
        public final byte[] clientDataJsonBytes;
        public final byte[] clientDataHash;
        public final List<X509Certificate> x5c;
        /**
         * false for fmt=none: the ceremony was cryptographically sound but nothing proves which
         * hardware holds the key. Only android-key and packed can ever set this true, and packed
         * additionally needs the Apple App Attest object that register/verify demands.
         */
        public final boolean attestedFormat;
        /** false when BE or BS is set, i.e. the credential is a syncable (multi-device) passkey. */
        public final boolean deviceBound;
        public final boolean backupEligible;
        public final boolean backupState;

        RegistrationResult(RegistrationData data, String format, String aaguid, byte[] credentialId,
                CredentialRecord record, byte[] attestationObjectBytes, byte[] clientDataJsonBytes,
                byte[] clientDataHash, List<X509Certificate> x5c, boolean attestedFormat,
                boolean deviceBound, boolean backupEligible, boolean backupState) {
            this.data = data;
            this.format = format;
            this.aaguid = aaguid;
            this.credentialId = credentialId;
            this.record = record;
            this.attestationObjectBytes = attestationObjectBytes;
            this.clientDataJsonBytes = clientDataJsonBytes;
            this.clientDataHash = clientDataHash;
            this.x5c = x5c;
            this.attestedFormat = attestedFormat;
            this.deviceBound = deviceBound;
            this.backupEligible = backupEligible;
            this.backupState = backupState;
        }
    }

    public static final class AssertionResult {
        public final AuthenticationData data;
        public final long signCount;
        public final byte[] authenticatorDataBytes;
        public final byte[] clientDataJsonBytes;
        public final byte[] userHandle;

        AssertionResult(AuthenticationData data, long signCount, byte[] authenticatorDataBytes,
                byte[] clientDataJsonBytes, byte[] userHandle) {
            this.data = data;
            this.signCount = signCount;
            this.authenticatorDataBytes = authenticatorDataBytes;
            this.clientDataJsonBytes = clientDataJsonBytes;
            this.userHandle = userHandle;
        }
    }

    private final Config config;
    private final WebAuthnManager manager;
    private final Set<Origin> acceptedOrigins;
    private final boolean demoMode;

    public WebAuthnVerifier(Config config, GoogleRoots googleRoots) {
        this.config = config;
        this.demoMode = config.demoMode();
        this.acceptedOrigins = parseOrigins(config.acceptedOrigins());
        AndroidKeyAttestationStatementVerifier androidKey = new AndroidKeyAttestationStatementVerifier();
        // teeEnforcedOnly=false only in the test configuration that also accepts the software root
        androidKey.setTeeEnforcedOnly(!config.allowSoftwareAttestationRoot());
        // strict manager (interfaces section 8): the statement verifiers, a
        // DefaultCertPathTrustworthinessVerifier(TrustAnchorRepository) over the Google roots and the
        // self attestation verifier for packed
        List<AttestationStatementVerifier> verifiers = new ArrayList<>();
        verifiers.add(androidKey);
        verifiers.add(new PackedAttestationStatementVerifier());
        if (demoMode) {
            // without this webauthn4j itself rejects fmt=none with BadAttestationStatementException
            verifiers.add(new NoneAttestationStatementVerifier());
        }
        this.manager = new WebAuthnManager(
                List.copyOf(verifiers),
                googleRoots.certPathVerifier(),
                new DefaultSelfAttestationTrustworthinessVerifier());
        LOG.info("WebAuthn verification: rpId={} attestationPolicy={} acceptedOrigins={}",
                config.rpId(), config.attestationPolicy(), config.acceptedOrigins());
    }

    /** Every configured origin string, parsed once at startup so a typo fails the boot, not a login. */
    private static Set<Origin> parseOrigins(List<String> configured) {
        if (configured.isEmpty()) {
            throw new IllegalStateException("acceptedOrigins is empty - no clientDataJSON.origin could ever match");
        }
        Set<Origin> out = new LinkedHashSet<>();
        for (String value : configured) {
            try {
                out.add(Origin.create(value));
            } catch (RuntimeException e) {
                throw new IllegalStateException("acceptedOrigins contains an unparsable origin: " + value, e);
            }
        }
        return Set.copyOf(out);
    }

    /** The origin set enforced against clientDataJSON.origin, for logging and the demo status page. */
    public Set<Origin> acceptedOrigins() {
        return acceptedOrigins;
    }

    private ServerProperty serverProperty(byte[] challenge) {
        return ServerProperty.builder()
                .origins(acceptedOrigins)
                .rpId(config.rpId())
                .challenge(new DefaultChallenge(challenge))
                .build();
    }

    public RegistrationResult verifyRegistration(String credentialJson, byte[] challenge) {
        RegistrationData data;
        try {
            data = manager.parseRegistrationResponseJSON(credentialJson);
        } catch (RuntimeException e) {
            throw ApiException.attestationRejected("die Registrierungsantwort ist nicht lesbar", e);
        }

        // the format decides which of the relying-party checks below are hard failures, so it is
        // read (and gated on the policy) before webauthn4j runs
        String format = data.getAttestationObject().getFormat();
        boolean noneFormat = FORMAT_NONE.equals(format);
        if (noneFormat) {
            if (!demoMode) {
                throw ApiException.attestationRejected("Attestierungsformat none wird nicht akzeptiert"
                        + " (attestationPolicy=strict verlangt android-key oder packed+App Attest)");
            }
        } else if (!FORMAT_ANDROID_KEY.equals(format) && !FORMAT_PACKED.equals(format)) {
            throw ApiException.attestationRejected("Attestierungsformat " + format + " wird nicht akzeptiert");
        }

        RegistrationParameters parameters = new RegistrationParameters(
                serverProperty(challenge),
                List.of(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.ES256)),
                true, true);
        try {
            manager.verify(data, parameters);
        } catch (VerificationException e) {
            throw ApiException.attestationRejected(String.valueOf(e.getMessage()), e);
        }

        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData =
                data.getAttestationObject().getAuthenticatorData();
        boolean backupEligible = authenticatorData.isFlagBE();
        boolean backupState = authenticatorData.isFlagBS();
        boolean deviceBound = !backupEligible && !backupState;
        if (!deviceBound && !noneFormat) {
            throw ApiException.attestationRejected("der Passkey ist nicht gerätegebunden (BE/BS gesetzt)");
        }
        if (authenticatorData.getSignCount() != 0 && !noneFormat) {
            throw ApiException.attestationRejected("signCount ist bei der Registrierung nicht 0");
        }
        AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();
        if (attestedCredentialData == null) {
            throw ApiException.attestationRejected("attestedCredentialData fehlt");
        }
        if (!COSEAlgorithmIdentifier.ES256.equals(attestedCredentialData.getCOSEKey().getAlgorithm())) {
            throw ApiException.attestationRejected("der Schlüssel ist nicht ES256");
        }

        List<X509Certificate> x5c = null;
        AAGUID aaguid = attestedCredentialData.getAaguid();
        if (FORMAT_ANDROID_KEY.equals(format)) {
            x5c = ((AndroidKeyAttestationStatement) data.getAttestationObject().getAttestationStatement()).getX5c();
        }
        if (noneFormat) {
            // no app AAGUID to match: the AAGUID of a browser passkey belongs to the platform
            // password manager, and it is unauthenticated data because nothing attests it
            LOG.warn("DEMO MODE: accepting fmt=none registration, NOT hardware attested. "
                    + "aaguid={} (unattested) backupEligible={} backupState={} signCount={}",
                    aaguid, backupEligible, backupState, authenticatorData.getSignCount());
        } else {
            AAGUID expectedAaguid = FORMAT_ANDROID_KEY.equals(format) ? AAGUID_ANDROID : AAGUID_IOS;
            if (!expectedAaguid.equals(aaguid)) {
                throw ApiException.attestationRejected(
                        "AAGUID " + aaguid + " passt nicht zum Attestierungsformat " + format);
            }
        }

        CredentialRecord record = new CredentialRecordImpl(data.getAttestationObject(),
                data.getCollectedClientData(), data.getClientExtensions(), data.getTransports());
        return new RegistrationResult(data, format, aaguid.toString(), attestedCredentialData.getCredentialId(),
                record, data.getAttestationObjectBytes(), data.getCollectedClientDataBytes(),
                data.getClientDataHash(), x5c, !noneFormat, deviceBound, backupEligible, backupState);
    }

    public AssertionResult verifyAssertion(String credentialJson, byte[] challenge, CredentialRecord record) {
        return verifyAssertion(credentialJson, challenge, record, true);
    }

    /**
     * @param requireDeviceBound false only for a credential that was enrolled as a syncable passkey
     *     in demo mode; every attested credential is device bound and passes true.
     */
    public AssertionResult verifyAssertion(String credentialJson, byte[] challenge, CredentialRecord record,
            boolean requireDeviceBound) {
        AuthenticationData data;
        try {
            data = manager.parseAuthenticationResponseJSON(credentialJson);
        } catch (RuntimeException e) {
            throw ApiException.attestationRejected("die Anmeldeantwort ist nicht lesbar", e);
        }
        AuthenticationParameters parameters =
                new AuthenticationParameters(serverProperty(challenge), record, null, true, true);
        try {
            manager.verify(data, parameters);
        } catch (MaliciousCounterValueException e) {
            throw ApiException.counterRegression();
        } catch (VerificationException e) {
            throw ApiException.attestationRejected(String.valueOf(e.getMessage()), e);
        }
        if (requireDeviceBound
                && (data.getAuthenticatorData().isFlagBE() || data.getAuthenticatorData().isFlagBS())) {
            throw ApiException.attestationRejected("der Passkey ist nicht gerätegebunden (BE/BS gesetzt)");
        }
        return new AssertionResult(data, data.getAuthenticatorData().getSignCount(),
                data.getAuthenticatorDataBytes(), data.getCollectedClientDataBytes(), data.getUserHandle());
    }
}
