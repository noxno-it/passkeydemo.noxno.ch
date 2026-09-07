package ch.noxno.passkeydemo;

import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.credential.CredentialRecord;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** In-memory passkey_credential table (spec 6.1). */
public final class CredentialStore {

    public static final class Credential {
        public final String credentialId;
        public final byte[] credentialIdBytes;
        public final String username;
        public final CredentialRecord record;
        public final String platform;
        public final String attestationFmt;
        public final byte[] attestationObject;
        public final byte[] clientDataJson;
        public final String securityLevel;
        public final String deviceName;
        public final Instant createdAt;

        /** UUID string of the attested AAGUID (spec 6.1), set by register/verify after the format check. */
        public volatile String aaguid;
        /**
         * true only when hardware attestation was actually verified: android-key with a chain up to a
         * Google root, or packed together with an Apple App Attest object. A credential enrolled with
         * attestationFmt "none" (demo mode, browser) is ALWAYS false - the ceremony proved possession
         * of a key, not which hardware holds it.
         */
        public volatile boolean attested;
        /** false when the authenticator set BE/BS, i.e. a syncable passkey rather than a device-bound one. */
        public volatile boolean deviceBound = true;
        /** Human readable reason shown in passkey/list whenever attested is false. */
        public volatile String attestationNote;
        public volatile DCAppleDevice appAttestDevice;
        public volatile String appAttestKeyId;
        public volatile String appAttestAppId;
        public volatile String appAttestEnvironment;
        public volatile byte[] appAttestReceipt;
        public volatile Instant lastUsedAt;
        public volatile Instant fullLoginAt;
        public volatile Instant revokedAt;

        public Credential(String credentialId, byte[] credentialIdBytes, String username, CredentialRecord record,
                String platform, String attestationFmt, byte[] attestationObject, byte[] clientDataJson,
                String securityLevel, String deviceName, Instant createdAt) {
            this.credentialId = credentialId;
            this.credentialIdBytes = credentialIdBytes;
            this.username = username;
            this.record = record;
            this.platform = platform;
            this.attestationFmt = attestationFmt;
            this.attestationObject = attestationObject;
            this.clientDataJson = clientDataJson;
            this.securityLevel = securityLevel;
            this.deviceName = deviceName;
            this.createdAt = createdAt;
        }
    }

    private final Map<String, Credential> byCredentialId = new ConcurrentHashMap<>();

    public void add(Credential credential) {
        byCredentialId.put(credential.credentialId, credential);
    }

    public Optional<Credential> byId(String credentialId) {
        return Optional.ofNullable(byCredentialId.get(credentialId));
    }

    public boolean exists(String credentialId) {
        return byCredentialId.containsKey(credentialId);
    }

    public List<Credential> activeByUser(String username) {
        List<Credential> out = new ArrayList<>();
        for (Credential credential : byCredentialId.values()) {
            if (credential.username.equals(username) && credential.revokedAt == null) {
                out.add(credential);
            }
        }
        out.sort((a, b) -> a.createdAt.compareTo(b.createdAt));
        return out;
    }

    public void remove(String credentialId) {
        byCredentialId.remove(credentialId);
    }
}
