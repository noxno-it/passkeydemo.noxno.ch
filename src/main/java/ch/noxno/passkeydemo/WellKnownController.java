package ch.noxno.passkeydemo;

import io.javalin.Javalin;
import io.javalin.http.Context;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;

/**
 * The two domain-association files of the relying-party host, generated from the same config that
 * drives attestation so they can never drift from it:
 * {@code GET /.well-known/apple-app-site-association} and {@code GET /.well-known/assetlinks.json}.
 *
 * <p><b>What these files actually do.</b> They bind this domain to the relying party's mobile apps
 * for PLATFORM
 * passkeys - credentials held by iCloud Keychain and Google Password Manager. Platform passkeys
 * SYNC across every device of the user's Apple / Google account and return attestation "none", so
 * under BSI they reach trust level "normal" and never "substantiell". The attested, device-bound
 * design (key in the Secure Enclave / StrongBox, android-key resp. packed + Apple App Attest, the
 * app itself acting as the authenticator) reaches "substantiell" and needs NO association file at
 * all. Both paths can be live on one host at the same time: publishing these files opens the
 * CONVENIENCE path with open eyes, it is not a prerequisite for and not a step towards the
 * compliance path. {@code serveWellKnown=false} turns them off.
 *
 * <p><b>Both files are served in strict AND in demo mode.</b> They describe app identity, not the
 * demo; only {@code serveWellKnown} gates them.
 *
 * <p><b>The classic silent failures, all of them on the Apple side.</b>
 * <ul>
 * <li>{@code apple-app-site-association} has NO file extension. Nothing may append one, and nothing
 *     may serve it as {@code text/plain} or {@code application/octet-stream} - the Content-Type must
 *     be exactly {@code application/json}, which is why it is set by hand here.</li>
 * <li>It must be reachable over HTTPS with NO redirect of ANY kind - not http-&gt;https, not
 *     apex-&gt;www, not a trailing-slash normalisation. Apple's CDN does not follow redirects for
 *     this file and simply reports the domain as unverified. A reverse proxy in front of this server
 *     is the usual culprit: the {@code /.well-known/} location must proxy_pass straight through.</li>
 * <li>No authentication, no bearer token, no rate limiting. These two handlers deliberately do not
 *     call {@link RateLimiter}; the limiter in this server is invoked per handler, never as a global
 *     before-filter, so nothing covers these paths implicitly.</li>
 * <li>An empty fingerprint or app list is valid JSON and breaks the platform silently, so an empty
 *     list is logged as a WARN at startup.</li>
 * </ul>
 */
public final class WellKnownController {

    private static final Logger LOG = LoggerFactory.getLogger(WellKnownController.class);

    public static final String AASA_PATH = "/.well-known/apple-app-site-association";
    public static final String ASSETLINKS_PATH = "/.well-known/assetlinks.json";

    /** The Digital Asset Links relation that grants an app the domain's platform passkeys. */
    public static final String LOGIN_CREDS_RELATION = "delegate_permission/common.get_login_creds";

    /**
     * Also required, and the reason this is not a one-relation document.
     *
     * <p>Google's own guidance: "until we complete migrating our logic to accept it, please include
     * both delegate_permission/common.handle_all_urls and delegate_permission/common.get_login_creds".
     * Play Services' app-facing passkey path still matches on handle_all_urls, so a statement listing
     * only get_login_creds is rejected for EVERY rpId with the maddeningly misleading
     * "RP ID cannot be validated" - even though
     * assetlinks:check?relation=delegate_permission/common.get_login_creds answers {"linked": true}.
     * A browser never hits this, because a privileged browser authenticates by origin and skips
     * Digital Asset Links entirely; only the native app path fails. Verified the hard way.
     */
    public static final String HANDLE_ALL_URLS_RELATION = "delegate_permission/common.handle_all_urls";

    /** Both documents are JSON; apple-app-site-association has no extension to infer it from. */
    public static final String CONTENT_TYPE = "application/json";

    /** An Apple Team ID is exactly 10 upper-case alphanumeric characters. */
    private static final int APPLE_TEAM_ID_LENGTH = 10;

    // ---------------------------------------------------------------- wire shapes

    /**
     * {@code {"webcredentials":{"apps":["TEAMID.bundleid", ...]}}} - exactly this. No applinks and
     * no appclips section: this host associates credentials, not universal links.
     */
    public static final class Aasa {
        public final WebCredentials webcredentials;

        Aasa(List<String> apps) {
            this.webcredentials = new WebCredentials(apps);
        }
    }

    public static final class WebCredentials {
        public final List<String> apps;

        WebCredentials(List<String> apps) {
            this.apps = apps;
        }
    }

    /** One entry of the assetlinks.json ARRAY. Field names are the contract - do not rename. */
    public static final class AssetLink {
        public final List<String> relation = List.of(HANDLE_ALL_URLS_RELATION, LOGIN_CREDS_RELATION);
        public final AssetLinkTarget target;

        AssetLink(String packageName, List<String> fingerprints) {
            this.target = new AssetLinkTarget(packageName, fingerprints);
        }
    }

    /** Field names are the Digital Asset Links contract - snake_case on purpose, do not rename. */
    public static final class AssetLinkTarget {
        public final String namespace = "android_app";
        public final String package_name;
        public final List<String> sha256_cert_fingerprints;

        AssetLinkTarget(String packageName, List<String> fingerprints) {
            this.package_name = packageName;
            this.sha256_cert_fingerprints = fingerprints;
        }
    }

    // ---------------------------------------------------------------- controller

    private final Config config;
    private final ObjectMapper mapper;

    /** Rendered once in {@link #register(Javalin)} so a malformed digest fails at boot, not per request. */
    private String aasaBody;
    private String assetLinksBody;

    public WellKnownController(Config config, ObjectMapper mapper) {
        this.config = config;
        this.mapper = mapper;
    }

    /** Registers both routes unless serveWellKnown=false, in which case both paths answer 404. */
    public void register(Javalin app) {
        if (!config.serveWellKnown()) {
            LOG.info("serveWellKnown=false - {} and {} are NOT served, both answer 404. Platform "
                    + "passkeys (iCloud Keychain / Google Password Manager) cannot be associated with "
                    + "{} without them; the attested device-bound path does not need them.",
                    AASA_PATH, ASSETLINKS_PATH, config.rpId());
            return;
        }

        List<String> appleAppIds = appleAppIds();
        List<String> fingerprints = assetLinksFingerprints();
        aasaBody = mapper.writeValueAsString(new Aasa(appleAppIds));
        assetLinksBody = mapper.writeValueAsString(List.of(new AssetLink(config.androidPackageName(), fingerprints)));

        app.get(AASA_PATH, this::serveAasa);
        app.get(ASSETLINKS_PATH, this::serveAssetLinks);

        LOG.info("serving {} as {} for webcredentials apps {}", AASA_PATH, CONTENT_TYPE, appleAppIds);
        LOG.info("serving {} as {} for android_app {} with {} SHA-256 fingerprint(s) {}",
                ASSETLINKS_PATH, CONTENT_TYPE, config.androidPackageName(), fingerprints.size(), fingerprints);
        LOG.info("these two files enable PLATFORM passkeys (synced, attestation \"none\", BSI trust level "
                + "\"normal\"). They are the convenience path and are independent of the attested, "
                + "device-bound path, which needs no association file. attestationPolicy={}",
                config.attestationPolicy());

        if (appleAppIds.isEmpty()) {
            LOG.warn("iosAppIds is empty - {} publishes an EMPTY webcredentials.apps list. iOS then "
                    + "silently refuses to associate any app with {}. Fill in iosAppIds.",
                    AASA_PATH, config.rpId());
        }
        if (fingerprints.isEmpty()) {
            LOG.warn("androidWebCredentialDigests and androidSigningDigests are both empty - {} publishes "
                    + "an EMPTY sha256_cert_fingerprints list. That is valid JSON and breaks Android "
                    + "passkeys SILENTLY: Google Password Manager simply never offers a credential for {}. "
                    + "Fill in the Play App Signing SHA-256 (Play Console -> Setup -> App signing).",
                    ASSETLINKS_PATH, config.rpId());
        }
    }

    /**
     * No rate limiter and no token on purpose - Apple's CDN fetches this anonymously, and a 403 or a
     * 429 is indistinguishable from "domain not associated" for the user.
     */
    private void serveAasa(Context ctx) {
        ctx.status(200).contentType(CONTENT_TYPE).result(aasaBody);
    }

    /** No rate limiter and no token on purpose - Google's asset-link fetcher is anonymous too. */
    private void serveAssetLinks(Context ctx) {
        ctx.status(200).contentType(CONTENT_TYPE).result(assetLinksBody);
    }

    // ---------------------------------------------------------------- rendering

    /** The iosAppIds list, every entry qualified with appleTeamId if it does not carry a team id yet. */
    List<String> appleAppIds() {
        String teamId = config.appleTeamId();
        List<String> out = new ArrayList<>();
        for (String entry : config.iosAppIds()) {
            out.add(qualify(entry, teamId));
        }
        return out;
    }

    /** androidWebCredentialDigests in the assetlinks.json spelling. */
    List<String> assetLinksFingerprints() {
        List<String> out = new ArrayList<>();
        for (String digest : config.androidWebCredentialDigests()) {
            out.add(toAssetLinksFingerprint(digest));
        }
        return out;
    }

    /**
     * Prefixes {@code teamId.} unless {@code appId} already starts with an Apple Team ID. An entry
     * that carries a DIFFERENT team id is published unchanged and logged as a WARN - one of the two
     * settings is then wrong, and silently rewriting it would hide that.
     */
    static String qualify(String appId, String teamId) {
        if (teamId.isEmpty()) {
            LOG.warn("appleTeamId is empty - publishing iosAppIds entry {} unchanged", appId);
            return appId;
        }
        if (appId.startsWith(teamId + ".")) {
            return appId;
        }
        int dot = appId.indexOf('.');
        String head = dot < 0 ? appId : appId.substring(0, dot);
        if (looksLikeTeamId(head)) {
            LOG.warn("iosAppIds entry {} starts with team id {} but appleTeamId is {} - publishing it "
                    + "unchanged. One of the two is wrong.", appId, head, teamId);
            return appId;
        }
        return teamId + "." + appId;
    }

    private static boolean looksLikeTeamId(String head) {
        if (head.length() != APPLE_TEAM_ID_LENGTH) {
            return false;
        }
        for (int i = 0; i < head.length(); i++) {
            char c = head.charAt(i);
            boolean upperAlnum = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!upperAlnum) {
                return false;
            }
        }
        return true;
    }

    /**
     * Converts a SHA-256 certificate digest to the assetlinks.json spelling: UPPER-CASE hex with a
     * colon between every byte, e.g. {@code AB:CD:EF:...}. This differs from the lower-case,
     * unseparated spelling {@link Config#androidSigningDigests()} normalises to for the attestation
     * comparison, so the conversion has to happen here; both input spellings are accepted.
     *
     * @throws IllegalStateException when the value is not 64 hex characters - a placeholder left in
     *     application.properties must fail loudly at boot rather than be published as broken JSON
     */
    public static String toAssetLinksFingerprint(String digest) {
        String hex = digest.replace(":", "").replace(" ", "").trim().toUpperCase(Locale.ROOT);
        if (hex.length() != 64 || !isHex(hex)) {
            throw new IllegalStateException("Not a SHA-256 certificate digest: \"" + digest
                    + "\". Expected 64 hex characters, optionally colon separated, e.g. the value of "
                    + "\"SHA256:\" from keytool -list -v, or Play Console -> Setup -> App signing.");
        }
        StringBuilder out = new StringBuilder(95);
        for (int i = 0; i < hex.length(); i += 2) {
            if (i > 0) {
                out.append(':');
            }
            out.append(hex, i, i + 2);
        }
        return out.toString();
    }

    private static boolean isHex(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return true;
    }
}
