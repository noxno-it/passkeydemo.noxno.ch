package ch.noxno.passkeydemo;

import io.javalin.Javalin;
import io.javalin.http.Context;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Every HTTP endpoint of the reference server, mounted under {@link Config#basePath()}. */
public final class PasskeyController {

    private static final Logger LOG = LoggerFactory.getLogger(PasskeyController.class);

    /** Fixed part of the route, appended to the configurable {@link Config#basePath()}. */
    public static final String API_SUFFIX = "/rest/authentication";

    /** The full route prefix of every endpoint below: {@code <basePath>/rest/authentication}. */
    public static String base(Config config) {
        return config.basePath() + API_SUFFIX;
    }

    /** Missing or unknown bearer token or X-Admin-Token - outside the passkey error contract, answered with 401. */
    public static final class UnauthorizedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public UnauthorizedException(String message) {
            super(message);
        }
    }

    private final Config config;
    private final String base;
    private final ObjectMapper mapper;
    private final UserStore users;
    private final CeremonyStore ceremonies;
    private final CredentialStore credentials;
    private final WebAuthnVerifier webAuthn;
    private final AndroidKeyAttestationPolicy androidPolicy;
    private final AppAttestVerifier appAttest;
    private final RateLimiter rateLimiter;
    private final VectorStore vectors;

    public PasskeyController(Config config, ObjectMapper mapper, UserStore users, CeremonyStore ceremonies,
            CredentialStore credentials, WebAuthnVerifier webAuthn, AndroidKeyAttestationPolicy androidPolicy,
            AppAttestVerifier appAttest, RateLimiter rateLimiter, VectorStore vectors) {
        this.config = config;
        this.base = base(config);
        this.mapper = mapper;
        this.users = users;
        this.ceremonies = ceremonies;
        this.credentials = credentials;
        this.webAuthn = webAuthn;
        this.androidPolicy = androidPolicy;
        this.appAttest = appAttest;
        this.rateLimiter = rateLimiter;
        this.vectors = vectors;
    }

    public void register(Javalin app) {
        app.post(base + "/passkey/register/options", this::registerOptions);
        app.post(base + "/passkey/register/verify", this::registerVerify);
        app.post(base + "/passkey/login/options", ctx -> assertionOptions(ctx, CeremonyStore.Type.LOGIN));
        app.post(base + "/passkey/login/verify", this::loginVerify);
        app.post(base + "/passkey/unlock/options", ctx -> assertionOptions(ctx, CeremonyStore.Type.UNLOCK));
        app.post(base + "/passkey/unlock/verify", this::unlockVerify);
        app.get(base + "/passkey/list", this::list);
        app.post(base + "/passkey/remove", this::remove);
        app.post(base + "/passkey/admin/reset", this::adminReset);

        app.post(base, this::legacyLogin);
        app.put(base + "/check", this::check);
        app.post(base + "/logout", this::logout);
        app.get(base + "/retrieveChallenge", this::retrieveChallenge);
        app.post(base + "/password", ctx -> json(ctx, 200, new Object()));
    }

    // ---------------------------------------------------------------- passkey

    private void registerOptions(Context ctx) {
        rateLimiter.check(ctx.ip());
        UserStore.User user = requireUser(ctx);
        Dto.RegisterOptionsRequest request = read(ctx, Dto.RegisterOptionsRequest.class);
        users.requireByPassword(user.username, request.password);
        LOG.info("legacy device challenge {} accepted without verification (reference server)", request.challengeId);

        byte[] userHandle = users.userHandle(user);
        CeremonyStore.Ceremony ceremony = ceremonies.create(CeremonyStore.Type.REGISTER, user.username);

        Dto.CreationOptions options = new Dto.CreationOptions();
        // strict wants a verifiable statement; demo accepts fmt=none, so asking for
        // "direct" there would only make security keys fail for no benefit.
        options.attestation = config.demoMode() ? "none" : "direct";
        options.rp.id = config.rpId();
        options.rp.name = config.rpName();
        options.user.id = Base64Url.encode(userHandle);
        options.user.name = user.username;
        options.user.displayName = user.username;
        options.challenge = Base64Url.encode(ceremony.challenge);
        for (CredentialStore.Credential credential : credentials.activeByUser(user.username)) {
            Dto.CredentialDescriptor descriptor = new Dto.CredentialDescriptor();
            descriptor.id = credential.credentialId;
            options.excludeCredentials.add(descriptor);
        }

        Dto.RegisterOptionsResponse response = new Dto.RegisterOptionsResponse();
        response.ceremonyId = ceremony.ceremonyId;
        response.publicKey = options;
        response.appAttestChallenge = Base64Url.encode(ceremony.appAttestChallenge);
        json(ctx, 200, response);
    }

    private void registerVerify(Context ctx) {
        rateLimiter.check(ctx.ip());
        UserStore.User user = requireUser(ctx);
        String rawBody = ctx.body();
        Dto.RegisterVerifyRequest request = read(ctx, Dto.RegisterVerifyRequest.class);
        CeremonyStore.Ceremony ceremony = ceremonies.require(request.ceremonyId, CeremonyStore.Type.REGISTER);
        if (!user.username.equals(ceremony.username)) {
            throw ApiException.ceremonyExpired();
        }
        if (request.credential == null) {
            throw ApiException.attestationRejected("credential fehlt");
        }
        String credentialJson = mapper.writeValueAsString(request.credential);
        WebAuthnVerifier.RegistrationResult result = webAuthn.verifyRegistration(credentialJson, ceremony.challenge);
        String credentialId = Base64Url.encode(result.credentialId);
        if (credentials.exists(credentialId)) {
            throw ApiException.attestationRejected("dieser Passkey ist bereits registriert");
        }

        String platform;
        String securityLevel;
        boolean attested;
        String attestationNote = null;
        AppAttestVerifier.AttestationResult appAttestResult = null;
        if (WebAuthnVerifier.FORMAT_NONE.equals(result.format)) {
            // only reachable with attestationPolicy=demo; WebAuthnVerifier rejects fmt=none in strict mode
            platform = "web";
            securityLevel = "none";
            attested = false;
            attestationNote = "fmt=none: WebAuthn-Zeremonie erfolgreich, aber keine Hardware-Attestierung. "
                    + "Nur die native App liefert android-key bzw. packed + Apple App Attest.";
            LOG.warn("DEMO MODE: enrolling an UNATTESTED credential for user={} via the compliance endpoint "
                    + "(fmt=none, deviceBound={}). This credential does NOT meet BSI trust level substantiell.",
                    user.username, result.deviceBound);
        } else if (WebAuthnVerifier.FORMAT_ANDROID_KEY.equals(result.format)) {
            AndroidKeyAttestationPolicy.Result android = androidPolicy.verify(result.x5c, result.clientDataHash);
            platform = "android";
            securityLevel = android.securityLevel;
            attested = true;
            LOG.info("android-key accepted: securityLevel={} attestationVersion={} deviceLocked={} verifiedBootState={}",
                    android.securityLevel, android.attestationVersion, android.deviceLocked, android.verifiedBootState);
        } else {
            if (request.deviceAttestation == null || !"ios".equals(request.deviceAttestation.platform)
                    || request.deviceAttestation.keyId == null || request.deviceAttestation.attestationObject == null) {
                throw ApiException.attestationRejected("für iOS ist eine App-Attest-Bestätigung erforderlich");
            }
            appAttestResult = appAttest.verifyAttestation(request.deviceAttestation.keyId,
                    request.deviceAttestation.attestationObject, result.attestationObjectBytes,
                    ceremony.appAttestChallenge);
            platform = "ios";
            securityLevel = "secure_enclave";
            attested = true;
            LOG.info("packed + App Attest accepted: environment={} appId={}",
                    appAttestResult.environment, appAttestResult.appId);
        }

        Instant now = Instant.now();
        CredentialStore.Credential credential = new CredentialStore.Credential(credentialId, result.credentialId,
                user.username, result.record, platform, result.format, result.attestationObjectBytes,
                result.clientDataJsonBytes, securityLevel,
                request.deviceName == null ? platform : request.deviceName, now);
        // result.aaguid is data.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid(),
        // already checked against the expected AAGUID constant for the format by WebAuthnVerifier
        credential.aaguid = result.aaguid;
        credential.attested = attested;
        credential.deviceBound = result.deviceBound;
        credential.attestationNote = attestationNote;
        credential.fullLoginAt = now;
        if (appAttestResult != null) {
            credential.appAttestDevice = appAttestResult.device;
            credential.appAttestKeyId = request.deviceAttestation.keyId;
            credential.appAttestAppId = appAttestResult.appId;
            credential.appAttestEnvironment = appAttestResult.environment;
            // AppleAppAttestAttestationStatement.getReceipt(), persisted for the receipt exchange (spec 6.5)
            credential.appAttestReceipt = appAttestResult.receipt;
        }
        credentials.add(credential);
        user.passkeyRequired = true;
        ceremonies.consume(ceremony);
        vectors.record(platform, "register", config.rpId(), ceremony.challenge, ceremony.appAttestChallenge, rawBody);
        LOG.info("audit enrolled user={} credentialId={} platform={} fmt={} attested={} deviceBound={} "
                + "aaguid={} securityLevel={}",
                user.username, credentialId, platform, result.format, attested, result.deviceBound,
                result.aaguid, securityLevel);

        Dto.RegisterVerifyResponse response = new Dto.RegisterVerifyResponse();
        response.credentialId = credentialId;
        response.deviceName = credential.deviceName;
        response.platform = platform;
        response.createdAt = now.toString();
        json(ctx, 200, response);
    }

    private void assertionOptions(Context ctx, CeremonyStore.Type type) {
        rateLimiter.check(ctx.ip());
        CeremonyStore.Ceremony ceremony = ceremonies.create(type, null);
        Dto.RequestOptions options = new Dto.RequestOptions();
        options.challenge = Base64Url.encode(ceremony.challenge);
        options.rpId = config.rpId();
        Dto.AssertionOptionsResponse response = new Dto.AssertionOptionsResponse();
        response.ceremonyId = ceremony.ceremonyId;
        response.publicKey = options;
        response.appAttestChallenge = Base64Url.encode(ceremony.appAttestChallenge);
        json(ctx, 200, response);
    }

    private void loginVerify(Context ctx) {
        rateLimiter.check(ctx.ip());
        String rawBody = ctx.body();
        Dto.LoginVerifyRequest request = read(ctx, Dto.LoginVerifyRequest.class);
        CeremonyStore.Ceremony ceremony = ceremonies.require(request.ceremonyId, CeremonyStore.Type.LOGIN);
        ceremonies.consume(ceremony);
        UserStore.User user = users.requireByPassword(request.username, request.password);
        CredentialStore.Credential credential = requireCredential(request.credential);
        if (!credential.username.equals(user.username)) {
            throw ApiException.credentialUnknown();
        }
        verifyAssertion(credential, user, request.credential, request.deviceAssertion, ceremony);

        Instant now = Instant.now();
        credential.lastUsedAt = now;
        credential.fullLoginAt = now;
        vectors.record(credential.platform, "login", config.rpId(), ceremony.challenge, ceremony.appAttestChallenge,
                rawBody);
        LOG.info("audit login user={} credentialId={} osVersion={} appVersion={}",
                user.username, credential.credentialId, request.osVersion, request.appVersion);
        json(ctx, 200, loginResponse(user));
    }

    private void unlockVerify(Context ctx) {
        rateLimiter.check(ctx.ip());
        String rawBody = ctx.body();
        Dto.UnlockVerifyRequest request = read(ctx, Dto.UnlockVerifyRequest.class);
        CeremonyStore.Ceremony ceremony = ceremonies.require(request.ceremonyId, CeremonyStore.Type.UNLOCK);
        ceremonies.consume(ceremony);
        CredentialStore.Credential credential = requireCredential(request.credential);
        UserStore.User user = users.find(credential.username).orElseThrow(ApiException::credentialUnknown);
        if (credential.fullLoginAt == null || Duration.between(credential.fullLoginAt, Instant.now())
                .getSeconds() > config.unlockWindowSeconds()) {
            throw ApiException.fullLoginRequired();
        }
        verifyAssertion(credential, user, request.credential, request.deviceAssertion, ceremony);

        credential.lastUsedAt = Instant.now();
        vectors.record(credential.platform, "unlock", config.rpId(), ceremony.challenge, ceremony.appAttestChallenge,
                rawBody);
        LOG.info("audit unlock user={} credentialId={} osVersion={} appVersion={}",
                user.username, credential.credentialId, request.osVersion, request.appVersion);
        json(ctx, 200, loginResponse(user));
    }

    private void verifyAssertion(CredentialStore.Credential credential, UserStore.User user, JsonNode credentialNode,
            Dto.DeviceAssertion deviceAssertion, CeremonyStore.Ceremony ceremony) {
        rateLimiter.check("credential:" + credential.credentialId);
        String credentialJson = mapper.writeValueAsString(credentialNode);
        WebAuthnVerifier.AssertionResult assertion = webAuthn.verifyAssertion(credentialJson,
                ceremony.challenge, credential.record, credential.deviceBound);
        byte[] expectedUserHandle = users.userHandle(user);
        if (assertion.userHandle == null
                || !Base64Url.constantTimeEquals(assertion.userHandle, expectedUserHandle)) {
            throw ApiException.credentialUnknown();
        }
        credential.record.setCounter(assertion.signCount);

        if ("ios".equals(credential.platform)) {
            if (deviceAssertion == null || !"ios".equals(deviceAssertion.platform) || deviceAssertion.assertion == null) {
                throw ApiException.attestationRejected("für iOS ist eine App-Attest-Assertion erforderlich");
            }
            byte[] clientDataHash = AppAttestVerifier.assertionClientDataHash(
                    assertion.authenticatorDataBytes, assertion.clientDataJsonBytes, ceremony.appAttestChallenge);
            long counter = appAttest.verifyAssertion(credential, deviceAssertion.assertion, clientDataHash);
            LOG.info("App Attest assertion counter is now {}", counter);
        }
    }

    private void list(Context ctx) {
        UserStore.User user = requireUser(ctx);
        List<Dto.RemoteCredential> out = new ArrayList<>();
        for (CredentialStore.Credential credential : credentials.activeByUser(user.username)) {
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

    private void remove(Context ctx) {
        UserStore.User user = requireUser(ctx);
        Dto.RemoveRequest request = read(ctx, Dto.RemoveRequest.class);
        users.requireByPassword(user.username, request.password);
        CredentialStore.Credential credential = credentials.byId(request.credentialId)
                .orElseThrow(ApiException::credentialUnknown);
        if (!credential.username.equals(user.username)) {
            throw ApiException.credentialUnknown();
        }
        credentials.remove(credential.credentialId);
        if (credentials.activeByUser(user.username).isEmpty()) {
            user.passkeyRequired = false;
        }
        LOG.info("audit removed user={} credentialId={}", user.username, credential.credentialId);
        json(ctx, 200, new Object());
    }

    /**
     * Hotline recovery (spec 4.5, 6): clears passkeyRequired and revokes every credential of the
     * account so the password alone logs in again and a new passkey can be enrolled.
     */
    private void adminReset(Context ctx) {
        rateLimiter.check(ctx.ip());
        requireAdminToken(ctx);
        Dto.AdminResetRequest request = read(ctx, Dto.AdminResetRequest.class);
        UserStore.User user = users.find(request.username)
                .orElseThrow(() -> new ApiException(ApiException.CREDENTIAL_UNKNOWN, "Dieses Konto ist nicht bekannt."));
        Instant now = Instant.now();
        List<CredentialStore.Credential> revoked = credentials.activeByUser(user.username);
        for (CredentialStore.Credential credential : revoked) {
            credential.revokedAt = now;
        }
        user.passkeyRequired = false;
        LOG.info("audit recovery_reset user={} actor=hotline:x-admin-token revokedCredentials={}",
                user.username, revoked.size());
        json(ctx, 200, new Object());
    }

    // ---------------------------------------------------------------- legacy

    private void legacyLogin(Context ctx) {
        rateLimiter.check(ctx.ip());
        Dto.LegacyLoginRequest request = read(ctx, Dto.LegacyLoginRequest.class);
        UserStore.User user = users.find(request.username).orElse(null);
        if (user != null && !credentials.activeByUser(user.username).isEmpty()) {
            throw ApiException.passkeyRequired();
        }
        UserStore.User authenticated = users.requireByPassword(request.username, request.password);
        LOG.info("audit legacy login user={} osVersion={} appVersion={} challengeId={}",
                authenticated.username, request.osVersion, request.appVersion, request.challengeId);
        json(ctx, 200, loginResponse(authenticated));
    }

    private void check(Context ctx) {
        requireUser(ctx);
        ctx.status(200).contentType("text/plain").result("OK");
    }

    private void logout(Context ctx) {
        String token = bearerToken(ctx);
        users.revokeToken(token);
        json(ctx, 200, new Object());
    }

    private void retrieveChallenge(Context ctx) {
        Dto.CryptoChallengeResponse response = new Dto.CryptoChallengeResponse();
        response.identifier = Base64Url.encode(Base64Url.random(8));
        response.nonce = Base64Url.encode(Base64Url.random(32));
        Instant validTill = Instant.now().plusSeconds(300);
        response.validTill = validTill.toString();
        response.validTillFormated = validTill.toString();
        LOG.info("retrieveChallenge for device id {} (signature accepted without verification)",
                ctx.queryParam("id"));
        json(ctx, 200, response);
    }

    // ---------------------------------------------------------------- helpers

    private Dto.LoginResponse loginResponse(UserStore.User user) {
        Dto.LoginResponse response = new Dto.LoginResponse();
        response.token = users.issueToken(user);
        return response;
    }

    private CredentialStore.Credential requireCredential(JsonNode credentialNode) {
        if (credentialNode == null || credentialNode.get("id") == null) {
            throw ApiException.credentialUnknown();
        }
        String credentialId = credentialNode.get("id").asString();
        CredentialStore.Credential credential = credentials.byId(credentialId)
                .orElseThrow(ApiException::credentialUnknown);
        if (credential.revokedAt != null) {
            throw ApiException.credentialUnknown();
        }
        return credential;
    }

    private String bearerToken(Context ctx) {
        String header = ctx.header("authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        return header.substring(7).trim();
    }

    private UserStore.User requireUser(Context ctx) {
        String token = bearerToken(ctx);
        return users.byToken(token).orElseThrow(
                () -> new UnauthorizedException("Die Sitzung ist abgelaufen. Bitte melde Dich erneut an."));
    }

    /** X-Admin-Token must equal config adminToken (constant-time); an empty configured token never matches. */
    private void requireAdminToken(Context ctx) {
        String expected = config.adminToken();
        String given = ctx.header("X-Admin-Token");
        if (expected.isEmpty() || given == null
                || !Base64Url.constantTimeEquals(Base64Url.utf8(expected), Base64Url.utf8(given))) {
            throw new UnauthorizedException("X-Admin-Token fehlt oder ist falsch.");
        }
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
