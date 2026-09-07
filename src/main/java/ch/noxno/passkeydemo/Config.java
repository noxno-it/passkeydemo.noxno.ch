package ch.noxno.passkeydemo;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/** All tunables of the reference server, read from application.properties in the working directory. */
public final class Config {

    /** Apple App Attestation Root CA, https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem */
    public static final String APPLE_APP_ATTEST_ROOT_PEM = String.join("\n",
            "-----BEGIN CERTIFICATE-----",
            "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw",
            "JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK",
            "QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa",
            "Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv",
            "biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y",
            "bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh",
            "NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au",
            "Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/",
            "MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw",
            "CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn",
            "53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV",
            "oyFraWVIyd/dganmrduC1bmTBGwD",
            "-----END CERTIFICATE-----");

    private final Properties props;

    private Config(Properties props) {
        this.props = props;
    }

    public static Config load(Path file) {
        Properties p = new Properties();
        if (Files.isRegularFile(file)) {
            // UTF-8 on purpose: rpName may carry non-ASCII, and Properties.load(InputStream) is ISO-8859-1
            try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                p.load(in);
            } catch (IOException e) {
                throw new IllegalStateException("Cannot read " + file.toAbsolutePath(), e);
            }
        }
        return new Config(p);
    }

    public static Config defaults() {
        return new Config(new Properties());
    }

    private String str(String key, String fallback) {
        String value = props.getProperty(key);
        return value == null ? fallback : value.trim();
    }

    private int integer(String key, int fallback) {
        return Integer.parseInt(str(key, Integer.toString(fallback)));
    }

    private boolean bool(String key, boolean fallback) {
        return Boolean.parseBoolean(str(key, Boolean.toString(fallback)));
    }

    private List<String> list(String key, String fallback) {
        List<String> out = new ArrayList<>();
        for (String part : str(key, fallback).split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }

    public int port() {
        return integer("port", 8099);
    }

    /**
     * Context path every app-facing endpoint hangs under, {@code /api} by default, so the routes are
     * {@code <basePath>/rest/authentication/...}. It exists because a real backend usually already
     * owns a context path: set {@code basePath} (env {@code PASSKEY_BASE_PATH}) to whatever that
     * backend uses and this server becomes a drop-in stand-in for it. Normalised to a leading slash
     * with no trailing slash; {@code basePath=/} mounts the API at the root. The {@code /demo} page,
     * the {@code /demo/api} namespace and {@code /.well-known/} are NOT affected - the first two are
     * demo surface, the last is fixed by the platforms.
     */
    public String basePath() {
        String value = str("basePath", "/api");
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        if (value.isEmpty()) {
            return "";
        }
        return value.startsWith("/") ? value : "/" + value;
    }

    public String rpId() {
        return str("rpId", "passkeydemo.noxno.ch");
    }

    public String rpName() {
        return str("rpName", "Noxno Passkey Demo");
    }

    /**
     * The canonical web origin of the relying party, {@code https://<rpId>}. It is only the
     * <em>default</em> member of {@link #acceptedOrigins()}; the set that is actually enforced
     * against clientDataJSON.origin is that one.
     */
    public String origin() {
        return "https://" + rpId();
    }

    /**
     * Every origin string accepted in clientDataJSON.origin, in full. A native authenticator writes
     * clientDataJSON itself, so its origin is whatever the app puts there - on Android that is
     * conventionally {@code android:apk-key-hash:<base64url SHA-256 of the signing certificate>},
     * on iOS the app sends the https origin of the relying party. When acceptedOrigins is set it is
     * the complete list and {@link #origin()} is <em>not</em> added implicitly; when it is unset the
     * list is exactly {@code [https://<rpId>]}.
     */
    public List<String> acceptedOrigins() {
        List<String> configured = list("acceptedOrigins", "");
        return configured.isEmpty() ? List.of(origin()) : List.copyOf(new LinkedHashSet<>(configured));
    }

    public static final String POLICY_STRICT = "strict";
    public static final String POLICY_DEMO = "demo";

    /**
     * {@code strict} (default, the compliance path) accepts only the hardware-attested formats
     * android-key and packed+Apple App Attest. {@code demo} additionally accepts fmt=none so a plain
     * browser passkey can complete the ceremony - such a credential is stored with attested=false
     * and is NOT hardware attested.
     */
    public String attestationPolicy() {
        String value = str("attestationPolicy", POLICY_STRICT).toLowerCase(Locale.ROOT);
        if (!POLICY_STRICT.equals(value) && !POLICY_DEMO.equals(value)) {
            throw new IllegalStateException(
                    "attestationPolicy must be \"strict\" or \"demo\", not \"" + value + "\"");
        }
        return value;
    }

    /** true only for attestationPolicy=demo: fmt=none is accepted, /demo/api and /demo exist. */
    public boolean demoMode() {
        return POLICY_DEMO.equals(attestationPolicy());
    }

    /**
     * Directory whose contents are served at /demo in demo mode. Not under src/ on purpose: the demo
     * page is dropped in here without touching the server sources. A bundled placeholder on the
     * classpath (resources/public) answers whenever this directory is absent.
     */
    public Path staticDir() {
        return Paths.get(str("staticDir", "public"));
    }

    public String androidPackageName() {
        return str("androidPackageName", "com.example.passkeydemo");
    }

    /** Lower-case hex SHA-256 digests of the accepted Android signing certificates. */
    public Set<String> androidSigningDigests() {
        Set<String> out = new LinkedHashSet<>();
        for (String value : list("androidSigningDigests", "")) {
            out.add(value.toLowerCase(Locale.ROOT).replace(":", ""));
        }
        return out;
    }

    public List<String> iosAppIds() {
        return list("iosAppIds", "ABCDE12345.com.example.passkeydemo");
    }

    // ------------------------------------------------------------ domain association (.well-known)

    /**
     * Whether {@code /.well-known/apple-app-site-association} and {@code /.well-known/assetlinks.json}
     * are served (default true). They are served in strict AND demo mode - they describe app
     * identity, not the demo - and {@code serveWellKnown=false} is the only thing that turns them off.
     *
     * <p>What they buy, stated plainly: they bind this domain to the relying party's mobile apps
     * for PLATFORM passkeys, i.e. credentials held by iCloud Keychain / Google Password Manager. Those SYNC across the
     * user's devices and return attestation "none", which is BSI trust level "normal". The attested,
     * device-bound design (Secure Enclave / StrongBox, android-key resp. packed + Apple App Attest)
     * reaches "substantiell" and needs NO association file at all. Both can coexist on one host: these
     * files open the CONVENIENCE path, they are not a prerequisite for the compliance path.
     */
    public boolean serveWellKnown() {
        return bool("serveWellKnown", true);
    }

    /**
     * Apple Developer Team ID, the 10-character prefix of an Application Identifier. Used to qualify
     * every {@link #iosAppIds()} entry that does not already carry a team id, so the
     * apple-app-site-association webcredentials list is always {@code TEAMID.bundleid}.
     */
    public String appleTeamId() {
        return str("appleTeamId", "ABCDE12345");
    }

    /**
     * SHA-256 certificate digests published in assetlinks.json, defaulting to
     * {@link #androidSigningDigests()} so the two can only differ deliberately.
     *
     * <p>They are separate keys because the two lists have different blast radii.
     * androidSigningDigests is a server-side ACCEPTANCE list, checked per registration against the
     * attestationApplicationId extension; this one is a PUBLIC GRANT, fetched and cached by Google
     * for the whole internet, that lets any app signed by a listed certificate receive this domain's
     * platform passkeys. A debug signing certificate belongs in the first list (so local builds can
     * enrol) and must never be in the second on a production host: the Android debug keystore is
     * unencrypted and uses the well-known password "android".
     *
     * <p>Same normalisation as androidSigningDigests: lower-case hex, colons stripped. The
     * assetlinks.json spelling (UPPER-CASE, colon separated) is produced by
     * {@link WellKnownController#toAssetLinksFingerprint(String)}.
     */
    public Set<String> androidWebCredentialDigests() {
        List<String> configured = list("androidWebCredentialDigests", "");
        if (configured.isEmpty()) {
            return androidSigningDigests();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String value : configured) {
            out.add(value.toLowerCase(Locale.ROOT).replace(":", ""));
        }
        return out;
    }

    public Set<String> appAttestEnvironments() {
        return new LinkedHashSet<>(list("appAttestEnvironments", "appattest,appattestdevelop"));
    }

    public boolean allowSoftwareAttestationRoot() {
        return bool("allowSoftwareAttestationRoot", true);
    }

    /** "log" or "enforce" - what to do when the Android root of trust is not Verified+locked. */
    public String verifiedBootPolicy() {
        return str("verifiedBootPolicy", "log");
    }

    public long unlockWindowSeconds() {
        return Long.parseLong(str("unlockWindowSeconds", "604800"));
    }

    public long ceremonyTtlSeconds() {
        return Long.parseLong(str("ceremonyTtlSeconds", "300"));
    }

    public String googleRootsUrl() {
        return str("googleRootsUrl", "https://android.googleapis.com/attestation/root");
    }

    public String googleStatusUrl() {
        return str("googleStatusUrl", "https://android.googleapis.com/attestation/status");
    }

    public Path cacheDir() {
        return Paths.get(str("cacheDir", "cache"));
    }

    public Path vectorsDir() {
        return Paths.get(str("vectorsDir", "vectors"));
    }

    public Path usersFile() {
        return Paths.get(str("usersFile", "users.json"));
    }

    public int rateLimitPerMinute() {
        return integer("rateLimitPerMinute", 60);
    }

    /** X-Admin-Token of POST passkey/admin/reset (hotline recovery). Never an empty string. */
    public String adminToken() {
        return str("adminToken", "change-me");
    }

    public String appleAppAttestRootPem() {
        String path = str("appleAppAttestRootPemPath", "");
        if (path.isEmpty()) {
            return APPLE_APP_ATTEST_ROOT_PEM;
        }
        try {
            return Files.readString(Paths.get(path));
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read appleAppAttestRootPemPath " + path, e);
        }
    }
}
