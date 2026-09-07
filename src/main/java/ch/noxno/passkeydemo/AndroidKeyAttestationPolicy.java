package ch.noxno.passkeydemo;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Android policy of spec section 6.4: parses the key attestation extension
 * 1.3.6.1.4.1.11129.2.1.17 and enforces challenge binding, security level, key properties,
 * app identity and (per verifiedBootPolicy) the root of trust.
 */
public final class AndroidKeyAttestationPolicy {

    private static final Logger LOG = LoggerFactory.getLogger(AndroidKeyAttestationPolicy.class);

    public static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
    public static final String PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30";

    public static final int SECURITY_LEVEL_SOFTWARE = 0;
    public static final int SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int SECURITY_LEVEL_STRONGBOX = 2;

    public static final int ORIGIN_GENERATED = 0;
    public static final int PURPOSE_SIGN = 2;
    public static final int ALGORITHM_EC = 3;
    public static final int EC_CURVE_P_256 = 1;
    public static final int DIGEST_SHA_2_256 = 4;
    public static final long HW_AUTH_FINGERPRINT = 2L;
    public static final long HW_AUTH_ANY = 0xFFFFFFFFL;

    public static final int VERIFIED_BOOT_STATE_VERIFIED = 0;

    /** What the server stores about the attested Android key. */
    public static final class Result {
        public final String securityLevel;
        public final int attestationVersion;
        public final boolean deviceLocked;
        public final int verifiedBootState;

        Result(String securityLevel, int attestationVersion, boolean deviceLocked, int verifiedBootState) {
            this.securityLevel = securityLevel;
            this.attestationVersion = attestationVersion;
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState;
        }
    }

    static final class RootOfTrust {
        boolean deviceLocked;
        int verifiedBootState = -1;
    }

    static final class AppId {
        final Set<String> packageNames = new LinkedHashSet<>();
        final Set<String> signatureDigests = new LinkedHashSet<>();
    }

    static final class AuthorizationList {
        Set<Integer> purposes = new LinkedHashSet<>();
        Integer algorithm;
        Integer ecCurve;
        Set<Integer> digests = new LinkedHashSet<>();
        boolean noAuthRequired;
        Long userAuthType;
        boolean unlockedDeviceRequired;
        Integer origin;
        RootOfTrust rootOfTrust;
        AppId attestationApplicationId;
    }

    private final Config config;

    public AndroidKeyAttestationPolicy(Config config) {
        this.config = config;
    }

    public Result verify(List<X509Certificate> chain, byte[] clientDataHash) {
        int index = -1;
        for (int i = chain.size() - 1; i >= 0; i--) {
            if (chain.get(i).getExtensionValue(KEY_DESCRIPTION_OID) != null) {
                index = i;
                break;
            }
        }
        if (index < 0) {
            throw ApiException.attestationRejected("kein Key-Attestation-Zertifikatsattribut in der Kette");
        }
        if (index != 0) {
            throw ApiException.attestationRejected(
                    "das Key-Attestation-Attribut steht nicht im Blattzertifikat (Kette verlängert)");
        }

        ASN1Sequence keyDescription = parseKeyDescription(chain.get(index));
        int attestationVersion = intOf(keyDescription.getObjectAt(0));
        int attestationSecurityLevel = enumOf(keyDescription.getObjectAt(1));
        int keyMintSecurityLevel = enumOf(keyDescription.getObjectAt(3));
        byte[] attestationChallenge = ASN1OctetString.getInstance(keyDescription.getObjectAt(4)).getOctets();
        AuthorizationList softwareEnforced = parseAuthorizationList(
                ASN1Sequence.getInstance(keyDescription.getObjectAt(6)));
        AuthorizationList hardwareEnforced = parseAuthorizationList(
                ASN1Sequence.getInstance(keyDescription.getObjectAt(7)));

        if (!Base64Url.constantTimeEquals(attestationChallenge, clientDataHash)) {
            throw ApiException.attestationRejected("attestationChallenge entspricht nicht dem clientDataHash");
        }

        boolean softwareAllowed = config.allowSoftwareAttestationRoot();
        if (!softwareAllowed && (attestationSecurityLevel == SECURITY_LEVEL_SOFTWARE
                || keyMintSecurityLevel == SECURITY_LEVEL_SOFTWARE)) {
            throw ApiException.deviceNotEligible("die Attestierung stammt nicht aus TEE oder StrongBox");
        }

        AuthorizationList effective = softwareAllowed ? merge(hardwareEnforced, softwareEnforced) : hardwareEnforced;

        if (effective.origin == null || effective.origin != ORIGIN_GENERATED) {
            throw ApiException.attestationRejected("origin ist nicht GENERATED");
        }
        if (!effective.purposes.contains(PURPOSE_SIGN)) {
            throw ApiException.attestationRejected("purpose enthält nicht SIGN");
        }
        if (effective.algorithm == null || effective.algorithm != ALGORITHM_EC) {
            throw ApiException.attestationRejected("algorithm ist nicht EC");
        }
        if (effective.ecCurve == null || effective.ecCurve != EC_CURVE_P_256) {
            throw ApiException.attestationRejected("ecCurve ist nicht P-256");
        }
        if (!effective.digests.isEmpty() && !effective.digests.contains(DIGEST_SHA_2_256)) {
            throw ApiException.attestationRejected("digest enthält nicht SHA-256");
        }
        if (effective.noAuthRequired) {
            throw ApiException.attestationRejected("der Schlüssel verlangt keine Nutzerauthentisierung");
        }
        if (effective.userAuthType == null
                || ((effective.userAuthType & HW_AUTH_FINGERPRINT) == 0 && effective.userAuthType != HW_AUTH_ANY)) {
            throw ApiException.attestationRejected("userAuthType enthält keine Biometrie");
        }

        AppId appId = softwareEnforced.attestationApplicationId != null
                ? softwareEnforced.attestationApplicationId
                : hardwareEnforced.attestationApplicationId;
        if (appId == null) {
            throw ApiException.attestationRejected("attestationApplicationId fehlt");
        }
        if (!appId.packageNames.contains(config.androidPackageName())) {
            throw ApiException.attestationRejected("packageName " + appId.packageNames + " ist nicht erlaubt");
        }
        Set<String> allowedDigests = config.androidSigningDigests();
        if (allowedDigests.isEmpty()) {
            LOG.warn("androidSigningDigests is empty - accepting signing certificate {} unchecked",
                    appId.signatureDigests);
        } else {
            boolean match = false;
            for (String digest : appId.signatureDigests) {
                if (allowedDigests.contains(digest)) {
                    match = true;
                    break;
                }
            }
            if (!match) {
                throw ApiException.attestationRejected(
                        "Signaturzertifikat " + appId.signatureDigests + " ist nicht erlaubt");
            }
        }

        RootOfTrust rootOfTrust = effective.rootOfTrust;
        boolean deviceLocked = rootOfTrust != null && rootOfTrust.deviceLocked;
        int verifiedBootState = rootOfTrust == null ? -1 : rootOfTrust.verifiedBootState;
        boolean bootOk = deviceLocked && verifiedBootState == VERIFIED_BOOT_STATE_VERIFIED;
        if (!bootOk) {
            if ("enforce".equalsIgnoreCase(config.verifiedBootPolicy())) {
                throw ApiException.deviceNotEligible(
                        "Bootloader entsperrt oder Verified Boot nicht bestätigt (deviceLocked=" + deviceLocked
                                + ", verifiedBootState=" + verifiedBootState + ")");
            }
            LOG.warn("verifiedBootPolicy=log: deviceLocked={} verifiedBootState={}", deviceLocked, verifiedBootState);
        }

        String securityLevel = switch (attestationSecurityLevel) {
            case SECURITY_LEVEL_STRONGBOX -> "strongbox";
            case SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee";
            default -> "software";
        };
        return new Result(securityLevel, attestationVersion, deviceLocked, verifiedBootState);
    }

    static ASN1Sequence parseKeyDescription(X509Certificate certificate) {
        try {
            byte[] raw = certificate.getExtensionValue(KEY_DESCRIPTION_OID);
            ASN1OctetString wrapper = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(raw));
            return ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(wrapper.getOctets()));
        } catch (Exception e) {
            throw ApiException.attestationRejected("KeyDescription konnte nicht gelesen werden", e);
        }
    }

    static AuthorizationList parseAuthorizationList(ASN1Sequence sequence) {
        AuthorizationList list = new AuthorizationList();
        for (ASN1Encodable element : sequence) {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(element);
            ASN1Object base = tagged.getExplicitBaseObject();
            switch (tagged.getTagNo()) {
                case 1 -> list.purposes = intSet(ASN1Set.getInstance(base));
                case 2 -> list.algorithm = intOf(base);
                case 5 -> list.digests = intSet(ASN1Set.getInstance(base));
                case 10 -> list.ecCurve = intOf(base);
                case 503 -> list.noAuthRequired = true;
                case 504 -> list.userAuthType = ASN1Integer.getInstance(base).getValue().longValue();
                case 509 -> list.unlockedDeviceRequired = true;
                case 702 -> list.origin = intOf(base);
                case 704 -> list.rootOfTrust = parseRootOfTrust(ASN1Sequence.getInstance(base));
                case 709 -> list.attestationApplicationId = parseAppId(
                        ASN1OctetString.getInstance(base).getOctets());
                default -> {
                    // every other authorization tag is irrelevant for this policy
                }
            }
        }
        return list;
    }

    private static RootOfTrust parseRootOfTrust(ASN1Sequence sequence) {
        RootOfTrust rootOfTrust = new RootOfTrust();
        rootOfTrust.deviceLocked = ASN1Boolean.getInstance(sequence.getObjectAt(1)).isTrue();
        rootOfTrust.verifiedBootState = ASN1Enumerated.getInstance(sequence.getObjectAt(2)).intValueExact();
        return rootOfTrust;
    }

    static AppId parseAppId(byte[] der) {
        AppId appId = new AppId();
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));
            ASN1Set packages = ASN1Set.getInstance(sequence.getObjectAt(0));
            for (ASN1Encodable element : packages) {
                ASN1Sequence info = ASN1Sequence.getInstance(element);
                appId.packageNames.add(new String(
                        ASN1OctetString.getInstance(info.getObjectAt(0)).getOctets(), StandardCharsets.UTF_8));
            }
            ASN1Set digests = ASN1Set.getInstance(sequence.getObjectAt(1));
            for (ASN1Encodable element : digests) {
                appId.signatureDigests.add(
                        Base64Url.hex(ASN1OctetString.getInstance(element).getOctets()).toLowerCase(Locale.ROOT));
            }
        } catch (Exception e) {
            throw ApiException.attestationRejected("attestationApplicationId konnte nicht gelesen werden", e);
        }
        return appId;
    }

    private static AuthorizationList merge(AuthorizationList primary, AuthorizationList fallback) {
        AuthorizationList merged = new AuthorizationList();
        merged.purposes = primary.purposes.isEmpty() ? fallback.purposes : primary.purposes;
        merged.algorithm = primary.algorithm != null ? primary.algorithm : fallback.algorithm;
        merged.ecCurve = primary.ecCurve != null ? primary.ecCurve : fallback.ecCurve;
        merged.digests = primary.digests.isEmpty() ? fallback.digests : primary.digests;
        merged.noAuthRequired = primary.noAuthRequired || fallback.noAuthRequired;
        merged.userAuthType = primary.userAuthType != null ? primary.userAuthType : fallback.userAuthType;
        merged.unlockedDeviceRequired = primary.unlockedDeviceRequired || fallback.unlockedDeviceRequired;
        merged.origin = primary.origin != null ? primary.origin : fallback.origin;
        merged.rootOfTrust = primary.rootOfTrust != null ? primary.rootOfTrust : fallback.rootOfTrust;
        merged.attestationApplicationId = primary.attestationApplicationId != null
                ? primary.attestationApplicationId : fallback.attestationApplicationId;
        return merged;
    }

    private static Set<Integer> intSet(ASN1Set set) {
        Set<Integer> out = new LinkedHashSet<>();
        List<Integer> values = new ArrayList<>();
        for (ASN1Encodable element : set) {
            values.add(intOf(element));
        }
        out.addAll(values);
        return out;
    }

    private static int intOf(ASN1Encodable value) {
        return ASN1Integer.getInstance(value).intValueExact();
    }

    private static int enumOf(ASN1Encodable value) {
        return ASN1Enumerated.getInstance(value).intValueExact();
    }
}
