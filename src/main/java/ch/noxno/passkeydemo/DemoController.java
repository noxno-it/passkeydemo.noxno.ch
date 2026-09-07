package ch.noxno.passkeydemo;

import io.javalin.Javalin;
import io.javalin.http.Context;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Browser demo namespace, mounted at /demo/api and ONLY when attestationPolicy=demo. In strict mode
 * these routes are never registered, so every one of them answers 404.
 *
 * <p>It exists so a plain web page can drive a complete WebAuthn ceremony without a native app: no
 * bearer token, no password, no App Attest, an in-memory username-only user model, and its own
 * ceremony and credential stores that are entirely separate from the compliance endpoints under
 * {@link Config#basePath()}. A ceremonyId minted here is unusable there and vice versa.
 *
 * <p>The verification itself is not forked: {@link WebAuthnVerifier} does exactly the same work as
 * for the app. What differs is only what the ceremony can prove. A browser is not a native app and
 * cannot emit android-key or an Apple App Attest object, so it returns attestation "none": the
 * ceremony is demonstrated, the attestation is not. Every response therefore carries attested=false
 * together with the reason.
 */
public final class DemoController {

    private static final Logger LOG = LoggerFactory.getLogger(DemoController.class);

    public static final String BASE = "/demo/api";

    static final String NOTE_NONE =
            "fmt=none: the WebAuthn ceremony succeeded, but nothing attests the hardware holding the key. "
            + "Browsers (iCloud Keychain / Google Password Manager) can only ever produce this. "
            + "BSI trust level: normal at best - never substantiell.";
    static final String NOTE_PACKED_WITHOUT_APP_ATTEST =
            "fmt=packed self-attestation without an Apple App Attest object. The demo endpoints do not "
            + "verify App Attest, so this is not counted as hardware attestation here. Only "
            + "passkey/register/verify with a deviceAttestation block can grade packed as attested.";

    /** username -> 32 random bytes, the WebAuthn user handle of that demo account. */
    private final Map<String, byte[]> userHandles = new ConcurrentHashMap<>();

    private final Config config;
    private final tools.jackson.databind.ObjectMapper mapper;
    private final WebAuthnVerifier webAuthn;
    private final AndroidKeyAttestationPolicy androidPolicy;
    private final RateLimiter rateLimiter;
    private final CeremonyStore ceremonies;
    private final CredentialStore credentials;

    public DemoController(Config config, tools.jackson.databind.ObjectMapper mapper, WebAuthnVerifier webAuthn,
            AndroidKeyAttestationPolicy androidPolicy, RateLimiter rateLimiter) {
        this.config = config;
        this.mapper = mapper;
        this.webAuthn = webAuthn;
        this.androidPolicy = androidPolicy;
        this.rateLimiter = rateLimiter;
        this.ceremonies = new CeremonyStore(config.ceremonyTtlSeconds());
        this.credentials = new CredentialStore();
    }

    /** Call only when config.demoMode() is true - Main guards this. */
    public void register(Javalin app) {
        app.get(BASE + "/status", this::status);
        app.post(BASE + "/register/options", this::registerOptions);
        app.post(BASE + "/register/verify", this::registerVerify);
        app.post(BASE + "/login/options", this::loginOptions);
        app.post(BASE + "/login/verify", this::loginVerify);
        app.get(BASE + "/list", this::list);
        app.post(BASE + "/reset", this::reset);
    }

    /** The demo credential store, so tests can look at what a ceremony actually produced. */
    public CredentialStore credentials() {
        return credentials;
    }

    // ---------------------------------------------------------------- endpoints

    private void status(Context ctx) {
        Dto.DemoStatusResponse response = new Dto.DemoStatusResponse();
        response.attestationPolicy = config.attestationPolicy();
        response.rpId = config.rpId();
        response.rpName = config.rpName();
        response.acceptedOrigins = List.copyOf(config.acceptedOrigins());
        response.noneAccepted = config.demoMode();
        json(ctx, 200, response);
    }

    private void registerOptions(Context ctx) {
        rateLimiter.check(ctx.ip());
        String username = requireUsername(read(ctx, Dto.DemoOptionsRequest.class).username);
        CeremonyStore.Ceremony ceremony = ceremonies.create(CeremonyStore.Type.REGISTER, username);

        Dto.CreationOptions options = new Dto.CreationOptions();
        // strict wants a verifiable statement; demo accepts fmt=none, so asking for
        // "direct" there would only make security keys fail for no benefit.
        options.attestation = config.demoMode() ? "none" : "direct";
        options.rp.id = config.rpId();
        options.rp.name = config.rpName();
        options.user.id = Base64Url.encode(userHandle(username));
        options.user.name = username;
        options.user.displayName = username;
        options.challenge = Base64Url.encode(ceremony.challenge);
        // no authenticatorAttachment: a laptop platform authenticator, a phone over hybrid and a
        // security key are all allowed, because the point is the ceremony, not the hardware
        options.authenticatorSelection.authenticatorAttachment = null;
        for (CredentialStore.Credential credential : credentials.activeByUser(username)) {
            Dto.CredentialDescriptor descriptor = new Dto.CredentialDescriptor();
            descriptor.id = credential.credentialId;
            // no transports hint: a browser credential may live on a phone (hybrid) or a security key
            descriptor.transports = null;
            options.excludeCredentials.add(descriptor);
        }

        Dto.DemoRegisterOptionsResponse response = new Dto.DemoRegisterOptionsResponse();
        response.ceremonyId = ceremony.ceremonyId;
        response.publicKey = options;
        response.attestationPolicy = config.attestationPolicy();
        response.note = "attestation=direct is requested on purpose - watch the browser answer with fmt=none.";
        json(ctx, 200, response);
    }

    private void registerVerify(Context ctx) {
        rateLimiter.check(ctx.ip());
        Dto.DemoVerifyRequest request = read(ctx, Dto.DemoVerifyRequest.class);
        CeremonyStore.Ceremony ceremony = ceremonies.require(request.ceremonyId, CeremonyStore.Type.REGISTER);
        if (request.credential == null) {
            throw ApiException.attestationRejected("credential fehlt");
        }
        String username = ceremony.username;

        WebAuthnVerifier.RegistrationResult result =
                webAuthn.verifyRegistration(mapper.writeValueAsString(request.credential), ceremony.challenge);
        String credentialId = Base64Url.encode(result.credentialId);
        if (credentials.exists(credentialId)) {
            throw ApiException.attestationRejected("dieser Passkey ist bereits registriert");
        }

        // grade honestly: only android-key can be attested at a demo endpoint, because the demo
        // endpoints deliberately do not carry an Apple App Attest object
        boolean attested = false;
        String note;
        String securityLevel;
        if (WebAuthnVerifier.FORMAT_ANDROID_KEY.equals(result.format)) {
            AndroidKeyAttestationPolicy.Result android = androidPolicy.verify(result.x5c, result.clientDataHash);
            attested = true;
            note = null;
            securityLevel = android.securityLevel;
        } else if (WebAuthnVerifier.FORMAT_PACKED.equals(result.format)) {
            note = NOTE_PACKED_WITHOUT_APP_ATTEST;
            securityLevel = "unattested";
        } else {
            note = NOTE_NONE;
            securityLevel = "none";
        }

        Instant now = Instant.now();
        String deviceName = request.deviceName == null || request.deviceName.isBlank()
                ? "Browser-Demo" : request.deviceName.trim();
        CredentialStore.Credential credential = new CredentialStore.Credential(credentialId, result.credentialId,
                username, result.record, "web", result.format, result.attestationObjectBytes,
                result.clientDataJsonBytes, securityLevel, deviceName, now);
        credential.aaguid = result.aaguid;
        credential.attested = attested;
        credential.deviceBound = result.deviceBound;
        credential.attestationNote = note;
        credential.fullLoginAt = now;
        credentials.add(credential);
        ceremonies.consume(ceremony);
        LOG.warn("DEMO register user={} credentialId={} fmt={} attested={} deviceBound={} aaguid={}",
                username, credentialId, result.format, attested, result.deviceBound, result.aaguid);

        Dto.DemoVerifyResponse response = new Dto.DemoVerifyResponse();
        response.attestationPolicy = config.attestationPolicy();
        response.username = username;
        response.credentialId = credentialId;
        response.deviceName = deviceName;
        response.attestationFmt = result.format;
        response.aaguid = result.aaguid;
        response.attested = attested;
        response.deviceBound = result.deviceBound;
        response.backupEligible = result.backupEligible;
        response.backupState = result.backupState;
        response.signCount = result.record.getCounter();
        response.attestationNote = note;
        response.createdAt = now.toString();
        json(ctx, 200, response);
    }

    private void loginOptions(Context ctx) {
        rateLimiter.check(ctx.ip());
        String username = UserStore.normalise(read(ctx, Dto.DemoOptionsRequest.class).username);
        CeremonyStore.Ceremony ceremony =
                ceremonies.create(CeremonyStore.Type.LOGIN, username.isEmpty() ? null : username);

        Dto.RequestOptions options = new Dto.RequestOptions();
        options.challenge = Base64Url.encode(ceremony.challenge);
        options.rpId = config.rpId();
        if (!username.isEmpty()) {
            for (CredentialStore.Credential credential : credentials.activeByUser(username)) {
                Dto.CredentialDescriptor descriptor = new Dto.CredentialDescriptor();
                descriptor.id = credential.credentialId;
                descriptor.transports = null;
                options.allowCredentials.add(descriptor);
            }
        }

        Dto.DemoAssertionOptionsResponse response = new Dto.DemoAssertionOptionsResponse();
        response.ceremonyId = ceremony.ceremonyId;
        response.publicKey = options;
        response.attestationPolicy = config.attestationPolicy();
        response.note = "An assertion never carries attestation, in the app or in a browser. "
                + "Whether this credential is hardware attested was decided at registration.";
        json(ctx, 200, response);
    }

    private void loginVerify(Context ctx) {
        rateLimiter.check(ctx.ip());
        Dto.DemoVerifyRequest request = read(ctx, Dto.DemoVerifyRequest.class);
        CeremonyStore.Ceremony ceremony = ceremonies.require(request.ceremonyId, CeremonyStore.Type.LOGIN);
        ceremonies.consume(ceremony);
        if (request.credential == null || request.credential.get("id") == null) {
            throw ApiException.credentialUnknown();
        }
        CredentialStore.Credential credential = credentials.byId(request.credential.get("id").asString())
                .orElseThrow(ApiException::credentialUnknown);
        if (ceremony.username != null && !ceremony.username.equals(credential.username)) {
            throw ApiException.credentialUnknown();
        }
        rateLimiter.check("demo-credential:" + credential.credentialId);

        WebAuthnVerifier.AssertionResult assertion = webAuthn.verifyAssertion(
                mapper.writeValueAsString(request.credential), ceremony.challenge, credential.record,
                credential.deviceBound);
        // discoverable credentials return a userHandle; when present it must be this account's
        byte[] expected = userHandle(credential.username);
        if (assertion.userHandle != null && !Base64Url.constantTimeEquals(assertion.userHandle, expected)) {
            throw ApiException.credentialUnknown();
        }
        credential.record.setCounter(assertion.signCount);
        credential.lastUsedAt = Instant.now();
        LOG.warn("DEMO login user={} credentialId={} fmt={} attested={} signCount={}",
                credential.username, credential.credentialId, credential.attestationFmt, credential.attested,
                assertion.signCount);

        Dto.DemoVerifyResponse response = new Dto.DemoVerifyResponse();
        response.attestationPolicy = config.attestationPolicy();
        response.username = credential.username;
        response.credentialId = credential.credentialId;
        response.deviceName = credential.deviceName;
        response.attestationFmt = credential.attestationFmt;
        response.aaguid = credential.aaguid;
        response.attested = credential.attested;
        response.deviceBound = credential.deviceBound;
        response.backupEligible = assertion.data.getAuthenticatorData().isFlagBE();
        response.backupState = assertion.data.getAuthenticatorData().isFlagBS();
        response.signCount = assertion.signCount;
        response.attestationNote = credential.attestationNote;
        response.createdAt = credential.createdAt.toString();
        json(ctx, 200, response);
    }

    private void list(Context ctx) {
        String username = UserStore.normalise(ctx.queryParam("username"));
        List<Dto.RemoteCredential> out = new ArrayList<>();
        for (CredentialStore.Credential credential : credentials.activeByUser(username)) {
            Dto.RemoteCredential remote = new Dto.RemoteCredential();
            remote.credentialId = credential.credentialId;
            remote.deviceName = credential.deviceName;
            remote.platform = credential.platform;
            remote.securityLevel = credential.securityLevel;
            remote.createdAt = credential.createdAt.toString();
            remote.lastUsedAt = credential.lastUsedAt == null ? null : credential.lastUsedAt.toString();
            remote.attested = credential.attested;
            remote.deviceBound = credential.deviceBound;
            remote.attestationFmt = credential.attestationFmt;
            remote.attestationNote = credential.attestationNote;
            out.add(remote);
        }
        json(ctx, 200, out);
    }

    /** Wipes every demo credential of one account so the same authenticator can enrol again. */
    private void reset(Context ctx) {
        rateLimiter.check(ctx.ip());
        String username = requireUsername(read(ctx, Dto.DemoOptionsRequest.class).username);
        int removed = 0;
        for (CredentialStore.Credential credential : credentials.activeByUser(username)) {
            credentials.remove(credential.credentialId);
            removed++;
        }
        userHandles.remove(username);
        LOG.warn("DEMO reset user={} removedCredentials={}", username, removed);
        json(ctx, 200, Map.of("username", username, "removed", removed));
    }

    // ---------------------------------------------------------------- helpers

    private String requireUsername(String raw) {
        String username = UserStore.normalise(raw);
        if (username.isEmpty()) {
            throw new ApiException(ApiException.CREDENTIAL_UNKNOWN, "username fehlt.");
        }
        if (username.length() > 64) {
            throw new ApiException(ApiException.CREDENTIAL_UNKNOWN, "username ist zu lang.");
        }
        return username;
    }

    private byte[] userHandle(String username) {
        return userHandles.computeIfAbsent(username, key -> Base64Url.random(32));
    }

    private <T> T read(Context ctx, Class<T> type) {
        try {
            return mapper.readValue(ctx.body(), type);
        } catch (RuntimeException e) {
            throw new ApiException(ApiException.ATTESTATION_REJECTED, "Die Anfrage ist nicht lesbar.", e);
        }
    }

    private void json(Context ctx, int status, Object body) {
        ctx.status(status).contentType("application/json").result(mapper.writeValueAsString(body));
    }
}
