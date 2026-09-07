package ch.noxno.passkeydemo;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.List;
import tools.jackson.databind.JsonNode;

/** Wire shapes of every endpoint. Field names are the contract - do not rename. */
public final class Dto {

    private Dto() {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class ErrorBody {
        public String message;
        public List<String> errors = new ArrayList<>();
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RpEntity {
        public String id;
        public String name;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class UserEntity {
        public String id;
        public String name;
        public String displayName;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class CredParam {
        public String type = "public-key";
        public int alg = -7;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class CredentialDescriptor {
        public String type = "public-key";
        public String id;
        public List<String> transports = List.of("internal");
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class AuthenticatorSelection {
        public String authenticatorAttachment = "platform";
        public String residentKey = "required";
        public boolean requireResidentKey = true;
        public String userVerification = "required";
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class CreationOptions {
        public RpEntity rp = new RpEntity();
        public UserEntity user = new UserEntity();
        public String challenge;
        public List<CredParam> pubKeyCredParams = List.of(new CredParam());
        public int timeout = 120000;
        public List<CredentialDescriptor> excludeCredentials = new ArrayList<>();
        public AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection();
        /**
         * Set per policy by the controllers, never hard-coded: asking for "direct" while
         * accepting "none" makes a security key emit packed+x5c, which then fails the
         * cert-path check with "invalid cert path". Demo mode asks for what it can
         * actually verify.
         */
        public String attestation = "none";
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RequestOptions {
        public String challenge;
        public String rpId;
        public int timeout = 120000;
        public List<CredentialDescriptor> allowCredentials = new ArrayList<>();
        public String userVerification = "required";
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RegisterOptionsRequest {
        public String password;
        public String challengeId;
        public String challengeResponse;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RegisterOptionsResponse {
        public String ceremonyId;
        public CreationOptions publicKey;
        public String appAttestChallenge;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DeviceAttestation {
        public String platform;
        public String keyId;
        public String attestationObject;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DeviceAssertion {
        public String platform;
        public String keyId;
        public String assertion;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RegisterVerifyRequest {
        public String ceremonyId;
        public JsonNode credential;
        public DeviceAttestation deviceAttestation;
        public String deviceName;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RegisterVerifyResponse {
        public String credentialId;
        public String deviceName;
        public String platform;
        public String createdAt;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class AssertionOptionsResponse {
        public String ceremonyId;
        public RequestOptions publicKey;
        public String appAttestChallenge;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class LoginVerifyRequest {
        public String ceremonyId;
        public String username;
        public String password;
        public String osVersion;
        public String appVersion;
        public boolean permanently;
        public JsonNode credential;
        public DeviceAssertion deviceAssertion;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class UnlockVerifyRequest {
        public String ceremonyId;
        public String osVersion;
        public String appVersion;
        public JsonNode credential;
        public DeviceAssertion deviceAssertion;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class LoginResponse {
        public String message = "";
        public String token;
        public String startpage = "/tabs/home";
        public String loginMessage = "";
        public boolean acceptBeingAsked = true;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RemoteCredential {
        public String credentialId;
        public String deviceName;
        public String platform;
        public String securityLevel;
        public String createdAt;
        public String lastUsedAt;
        /** Primitive on purpose: the flag must appear in every row, never be omitted as null. */
        public boolean attested;
        public boolean deviceBound = true;
        public String attestationFmt;
        /** Present exactly when attested is false: why this credential is not hardware attested. */
        public String attestationNote;
    }

    // ------------------------------------------------------------ browser demo (attestationPolicy=demo)

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DemoOptionsRequest {
        public String username;
        public String deviceName;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DemoVerifyRequest {
        public String ceremonyId;
        public String username;
        public String deviceName;
        public JsonNode credential;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DemoRegisterOptionsResponse {
        public String ceremonyId;
        public CreationOptions publicKey;
        /** Repeated in every demo response so the page can never render an attestation claim by accident. */
        public String attestationPolicy;
        public String note;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DemoAssertionOptionsResponse {
        public String ceremonyId;
        public RequestOptions publicKey;
        public String attestationPolicy;
        public String note;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DemoVerifyResponse {
        /** Repeated here too, so every demo response states the policy it was produced under. */
        public String attestationPolicy;
        public String username;
        public String credentialId;
        public String deviceName;
        public String attestationFmt;
        public String aaguid;
        public boolean attested;
        public boolean deviceBound;
        public boolean backupEligible;
        public boolean backupState;
        public long signCount;
        public String attestationNote;
        public String createdAt;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class DemoStatusResponse {
        public String attestationPolicy;
        public String rpId;
        public String rpName;
        public List<String> acceptedOrigins = new ArrayList<>();
        public List<String> attestedFormats = List.of("android-key", "packed + Apple App Attest");
        public boolean noneAccepted;
        public String truth = "Attestation is only obtainable from a native app. A browser at "
                + "this origin performs a real WebAuthn ceremony but always returns attestation "
                + "\"none\": it demonstrates the ceremony, never the attestation.";
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class RemoveRequest {
        public String credentialId;
        public String password;
        public String challengeId;
        public String challengeResponse;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class AdminResetRequest {
        public String username;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class LegacyLoginRequest {
        public String username;
        public String password;
        public String osVersion;
        public String appVersion;
        public boolean permanently;
        public String challengeId;
        public String challengeResponse;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class CryptoChallengeResponse {
        public String identifier;
        public String nonce;
        public String validTill;
        public String validTillFormated;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static final class SeedUser {
        public String username;
        public String password;
    }
}
