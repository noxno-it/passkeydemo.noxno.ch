package ch.noxno.passkeydemo;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.staticfiles.Location;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;

/** Boots the reference server on http://localhost:&lt;port&gt;&lt;basePath&gt;/ (basePath defaults to /api). */
public final class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    /** Everything main() wires, exposed so PasskeyControllerTest can drive the HTTP layer with the real stores. */
    public static final class Wiring {
        public final Config config;
        public final ObjectMapper mapper;
        public final UserStore users;
        public final CeremonyStore ceremonies;
        public final CredentialStore credentials;
        public final WebAuthnVerifier webAuthn;
        public final Javalin app;
        /** null unless attestationPolicy=demo. */
        public final DemoController demo;

        Wiring(Config config, ObjectMapper mapper, UserStore users, CeremonyStore ceremonies,
                CredentialStore credentials, WebAuthnVerifier webAuthn, Javalin app, DemoController demo) {
            this.config = config;
            this.mapper = mapper;
            this.users = users;
            this.ceremonies = ceremonies;
            this.credentials = credentials;
            this.webAuthn = webAuthn;
            this.app = app;
            this.demo = demo;
        }
    }

    private Main() {
    }

    public static void main(String[] args) {
        // application.properties at the project root, resolved against the working directory
        Path configFile = Paths.get(args.length > 0 ? args[0] : "application.properties");
        Config config = Config.load(configFile);
        Wiring wiring = wire(config);
        wiring.app.start(config.port());
        LOG.info("passkey reference server on http://localhost:{}{}/ "
                + "(rpId={}, attestationPolicy={}, acceptedOrigins={})",
                config.port(), PasskeyController.base(config), config.rpId(), config.attestationPolicy(),
                config.acceptedOrigins());
        if (config.demoMode()) {
            LOG.info("browser demo: http://localhost:{}/demo/ and {}", config.port(), DemoController.BASE);
        }
    }

    /** Builds every component and the (not yet started) Javalin app. */
    public static Wiring wire(Config config) {
        boolean demoMode = config.demoMode();
        if (demoMode) {
            warnAboutDemoMode(config);
        }
        ObjectMapper mapper = Json.mapper();

        UserStore users = new UserStore(config.usersFile(), mapper);
        CeremonyStore ceremonies = new CeremonyStore(config.ceremonyTtlSeconds());
        CredentialStore credentials = new CredentialStore();
        GoogleRoots googleRoots = new GoogleRoots(config, mapper);
        WebAuthnVerifier webAuthn = new WebAuthnVerifier(config, googleRoots);
        AndroidKeyAttestationPolicy androidPolicy = new AndroidKeyAttestationPolicy(config);
        AppAttestVerifier appAttest = new AppAttestVerifier(config);
        RateLimiter rateLimiter = new RateLimiter(config.rateLimitPerMinute());
        VectorStore vectors = new VectorStore(config.vectorsDir(), mapper);

        PasskeyController controller = new PasskeyController(config, mapper, users, ceremonies, credentials,
                webAuthn, androidPolicy, appAttest, rateLimiter, vectors);
        DemoController demo = demoMode
                ? new DemoController(config, mapper, webAuthn, androidPolicy, rateLimiter) : null;
        // strict AND demo: the two association files describe app identity, not the demo
        WellKnownController wellKnown = new WellKnownController(config, mapper);

        Javalin app = Javalin.create(javalin -> {
            if (demoMode) {
                staticFiles(javalin, config);
            }
        });
        app.before(Main::cors);
        app.options("/*", ctx -> ctx.status(204));
        controller.register(app);
        wellKnown.register(app);
        if (demo != null) {
            demo.register(app);
        }

        app.exception(ApiException.class, (e, ctx) -> {
            LOG.warn("403 {}: {}", e.getCode(), e.getMessage());
            error(ctx, 403, e.getCode(), e.getMessage(), mapper);
        });
        app.exception(PasskeyController.UnauthorizedException.class, (e, ctx) -> {
            LOG.warn("401 {}", e.getMessage());
            error(ctx, 401, "TOKEN_INVALID", e.getMessage(), mapper);
        });
        app.exception(Exception.class, (e, ctx) -> {
            LOG.error("500 unhandled", e);
            error(ctx, 500, "INTERNAL", "Interner Serverfehler.", mapper);
        });
        return new Wiring(config, mapper, users, ceremonies, credentials, webAuthn, app, demo);
    }

    /**
     * Serves the demo page at /demo, demo mode only. staticDir (default ./public) wins when it
     * exists; the placeholder bundled in resources/public answers otherwise, so /demo is never a 404
     * even before the demo page has been dropped in.
     */
    private static void staticFiles(io.javalin.config.JavalinConfig javalin, Config config) {
        Path dir = config.staticDir();
        if (Files.isDirectory(dir)) {
            LOG.info("serving /demo from staticDir {}", dir.toAbsolutePath());
            javalin.staticFiles.add(files -> {
                files.hostedPath = "/demo";
                files.directory = dir.toAbsolutePath().toString();
                files.location = Location.EXTERNAL;
            });
        } else {
            LOG.info("staticDir {} does not exist - serving the bundled placeholder at /demo",
                    dir.toAbsolutePath());
        }
        javalin.staticFiles.add(files -> {
            files.hostedPath = "/demo";
            files.directory = "/public";
            files.location = Location.CLASSPATH;
        });
    }

    private static void warnAboutDemoMode(Config config) {
        LOG.warn("################################################################################");
        LOG.warn("## attestationPolicy=demo - THIS IS NOT A COMPLIANT CONFIGURATION             ##");
        LOG.warn("## 1. Attestation format \"none\" is accepted. A browser passkey (iCloud        ##");
        LOG.warn("##    Keychain / Google Password Manager) can enrol WITHOUT any hardware      ##");
        LOG.warn("##    attestation. Such credentials are stored with attested=false and reach  ##");
        LOG.warn("##    BSI trust level \"normal\" at best, NEVER \"substantiell\".                 ##");
        LOG.warn("## 2. Syncable passkeys (BE/BS set) are tolerated for fmt=none, so the key is ##");
        LOG.warn("##    not device bound and may exist on other devices of the same account.    ##");
        LOG.warn("## 3. The /demo/api namespace is OPEN: no bearer token, no password.          ##");
        LOG.warn("## 4. Static files are served at /demo.                                       ##");
        LOG.warn("## A browser demo shows the passkey CEREMONY. It can never show attestation - ##");
        LOG.warn("## only a native app produces android-key or Apple App Attest.                ##");
        LOG.warn("## Set attestationPolicy=strict for anything but a demonstration.             ##");
        LOG.warn("################################################################################");
        LOG.warn("demo mode active: rpId={} acceptedOrigins={} staticDir={}",
                config.rpId(), config.acceptedOrigins(), config.staticDir().toAbsolutePath());
    }

    private static void cors(Context ctx) {
        ctx.header("Access-Control-Allow-Origin", "*");
        ctx.header("Access-Control-Allow-Headers", "authorization,content-type,accept,x-admin-token");
        ctx.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    }

    private static void error(Context ctx, int status, String code, String message, ObjectMapper mapper) {
        Dto.ErrorBody body = new Dto.ErrorBody();
        body.message = message;
        body.errors = List.of(code);
        ctx.status(status).contentType("application/json").result(mapper.writeValueAsString(body));
    }
}
