package ch.noxno.passkeydemo;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Builds exactly the bytes a native authenticator plugin produces: clientDataJSON with a
 * fixed key order, authenticatorData with flags 0x45 / 0x05, a COSE ES256 key and a packed
 * self attestation. Used to exercise the verifier without a device.
 */
final class TestAuthenticator {

    static final String AAGUID_IOS = "7a0e4c5e-1d3b-4b8f-9a6c-3f2e1d0c9b8a";
    static final String AAGUID_ANDROID = "2b9c7d6e-5f4a-4c3b-8a2d-1e0f9c8b7a6d";

    final String rpId;
    final KeyPair keyPair;
    final byte[] credentialId;
    /** AAGUID written into the next registration; tests set it to provoke a mismatch. */
    String aaguid = AAGUID_IOS;
    /** OR-ed into the authenticatorData flags; 0x18 = BE|BS, i.e. a syncable (not device bound) passkey. */
    int extraFlags = 0;
    byte[] lastAttestationObject;

    TestAuthenticator(String rpId) throws Exception {
        this.rpId = rpId;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        this.keyPair = generator.generateKeyPair();
        this.credentialId = Base64Url.random(32);
    }

    byte[] clientDataJson(String type, byte[] challenge) {
        String json = "{\"type\":\"" + type + "\",\"challenge\":\"" + Base64Url.encode(challenge)
                + "\",\"origin\":\"https://" + rpId + "\",\"crossOrigin\":false}";
        return Base64Url.utf8(json);
    }

    private static byte[] aaguidBytes(String uuid) {
        UUID parsed = UUID.fromString(uuid);
        return ByteBuffer.allocate(16)
                .putLong(parsed.getMostSignificantBits())
                .putLong(parsed.getLeastSignificantBits())
                .array();
    }

    private static byte[] coordinate(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        if (raw.length >= 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    byte[] registrationAuthData(long signCount) {
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        byte[] cose = TestCbor.coseKeyEs256(
                coordinate(publicKey.getW().getAffineX()), coordinate(publicKey.getW().getAffineY()));
        return Base64Url.concat(
                Base64Url.sha256(Base64Url.utf8(rpId)),
                new byte[] { (byte) (0x45 | extraFlags) },
                ByteBuffer.allocate(4).putInt((int) signCount).array(),
                aaguidBytes(aaguid),
                ByteBuffer.allocate(2).putShort((short) credentialId.length).array(),
                credentialId,
                cose);
    }

    byte[] assertionAuthData(long signCount) {
        return Base64Url.concat(
                Base64Url.sha256(Base64Url.utf8(rpId)),
                new byte[] { (byte) (0x05 | extraFlags) },
                ByteBuffer.allocate(4).putInt((int) signCount).array());
    }

    byte[] sign(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        return signature.sign();
    }

    /** RegistrationResponseJSON with fmt=packed self attestation. */
    String registrationJson(byte[] challenge) throws Exception {
        return registrationJson(challenge, "packed");
    }

    /** RegistrationResponseJSON with fmt=none (empty attStmt) - the server must reject it. */
    String registrationJsonWithoutAttestation(byte[] challenge) throws Exception {
        return registrationJson(challenge, "none");
    }

    private String registrationJson(byte[] challenge, String fmt) throws Exception {
        byte[] clientDataJson = clientDataJson("webauthn.create", challenge);
        byte[] clientDataHash = Base64Url.sha256(clientDataJson);
        byte[] authData = registrationAuthData(0);
        Map<String, Object> attStmt = new LinkedHashMap<>();
        if ("packed".equals(fmt)) {
            attStmt.put("alg", -7);
            attStmt.put("sig", sign(Base64Url.concat(authData, clientDataHash)));
        }
        lastAttestationObject = TestCbor.attestationObject(fmt, attStmt, authData);
        return "{\"id\":\"" + Base64Url.encode(credentialId) + "\","
                + "\"rawId\":\"" + Base64Url.encode(credentialId) + "\","
                + "\"type\":\"public-key\","
                + "\"response\":{\"clientDataJSON\":\"" + Base64Url.encode(clientDataJson) + "\","
                + "\"attestationObject\":\"" + Base64Url.encode(lastAttestationObject) + "\","
                + "\"transports\":[\"internal\"]},"
                + "\"authenticatorAttachment\":\"platform\","
                + "\"clientExtensionResults\":{}}";
    }

    /** AuthenticationResponseJSON for login and unlock. */
    String assertionJson(byte[] challenge, byte[] userHandle, long signCount) throws Exception {
        byte[] clientDataJson = clientDataJson("webauthn.get", challenge);
        byte[] clientDataHash = Base64Url.sha256(clientDataJson);
        byte[] authData = assertionAuthData(signCount);
        byte[] signature = sign(Base64Url.concat(authData, clientDataHash));
        return "{\"id\":\"" + Base64Url.encode(credentialId) + "\","
                + "\"rawId\":\"" + Base64Url.encode(credentialId) + "\","
                + "\"type\":\"public-key\","
                + "\"response\":{\"clientDataJSON\":\"" + Base64Url.encode(clientDataJson) + "\","
                + "\"authenticatorData\":\"" + Base64Url.encode(authData) + "\","
                + "\"signature\":\"" + Base64Url.encode(signature) + "\","
                + "\"userHandle\":\"" + Base64Url.encode(userHandle) + "\"},"
                + "\"authenticatorAttachment\":\"platform\","
                + "\"clientExtensionResults\":{}}";
    }
}
