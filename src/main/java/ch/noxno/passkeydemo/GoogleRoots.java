package ch.noxno.passkeydemo;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The two Google hardware attestation roots (RSA-4096 "SERIALNUMBER=f92009e853b6b045" and the
 * EC P-384 "Key Attestation CA1" that signs RKP chains since 2026-02-01) plus the revocation list,
 * both fetched from Google and cached on disk. Exposes them as a webauthn4j TrustAnchorRepository
 * and as the DefaultCertPathTrustworthinessVerifier used for fmt=android-key.
 */
public final class GoogleRoots {

    private static final Logger LOG = LoggerFactory.getLogger(GoogleRoots.class);
    private static final Duration MAX_AGE = Duration.ofHours(24);
    private static final String SOFTWARE_ROOT_CN = "Android Keystore Software Attestation Root";

    private final Config config;
    private final ObjectMapper mapper;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    private volatile List<X509Certificate> roots = List.of();
    private volatile Map<String, String> revocation = Map.of();
    private volatile Instant loadedAt = Instant.EPOCH;

    public GoogleRoots(Config config, ObjectMapper mapper) {
        this.config = config;
        this.mapper = mapper;
    }

    public synchronized void refreshIfStale() {
        if (!roots.isEmpty() && Duration.between(loadedAt, Instant.now()).compareTo(MAX_AGE) < 0) {
            return;
        }
        String rootsJson = fetchWithCache(config.googleRootsUrl(), config.cacheDir().resolve("google-roots.json"));
        String statusJson = fetchWithCache(config.googleStatusUrl(), config.cacheDir().resolve("google-status.json"));
        if (rootsJson != null) {
            roots = parseRoots(rootsJson);
        }
        if (statusJson != null) {
            revocation = parseStatus(statusJson);
        }
        loadedAt = Instant.now();
        LOG.info("Google attestation data: {} root(s), {} revocation entries", roots.size(), revocation.size());
    }

    private String fetchWithCache(String url, Path cacheFile) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(15)).GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                Files.createDirectories(cacheFile.getParent());
                Files.writeString(cacheFile, response.body());
                return response.body();
            }
            LOG.warn("GET {} returned HTTP {}", url, response.statusCode());
        } catch (Exception e) {
            LOG.warn("GET {} failed ({}), falling back to cache", url, e.toString());
        }
        try {
            if (Files.isRegularFile(cacheFile)) {
                return Files.readString(cacheFile);
            }
        } catch (Exception e) {
            LOG.warn("cache {} unreadable: {}", cacheFile, e.toString());
        }
        return null;
    }

    private List<X509Certificate> parseRoots(String json) {
        List<X509Certificate> parsed = new ArrayList<>();
        JsonNode array = mapper.readTree(json);
        for (JsonNode pem : array) {
            parsed.add(parseCertificate(pem.asString()));
        }
        return List.copyOf(parsed);
    }

    private Map<String, String> parseStatus(String json) {
        Map<String, String> parsed = new HashMap<>();
        JsonNode entries = mapper.readTree(json).get("entries");
        if (entries != null) {
            Iterator<Map.Entry<String, JsonNode>> it = entries.properties().iterator();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> entry = it.next();
                JsonNode status = entry.getValue().get("status");
                parsed.put(entry.getKey().toLowerCase(Locale.ROOT),
                        status == null ? "REVOKED" : status.asString());
            }
        }
        return Map.copyOf(parsed);
    }

    public static X509Certificate parseCertificate(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot parse certificate PEM", e);
        }
    }

    public List<X509Certificate> roots() {
        refreshIfStale();
        return roots;
    }

    /** null when the serial is not listed, otherwise "REVOKED" or "SUSPENDED". */
    public String revocationStatus(BigInteger serial) {
        return revocation.get(serial.toString(16).toLowerCase(Locale.ROOT));
    }

    /** The Google roots as webauthn4j trust anchors - the same set whichever AAGUID is asked for. */
    public TrustAnchorRepository trustAnchorRepository() {
        return new Repository();
    }

    /**
     * new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository) - PKIX chain building,
     * signatures and validity - plus the Google-specific rules of spec 6.4: the revocation list,
     * expiry tolerance for legacy factory chains and the test-only software root.
     */
    public DefaultCertPathTrustworthinessVerifier certPathVerifier() {
        return new Verifier(trustAnchorRepository());
    }

    static boolean isLegacyRsaRoot(X509Certificate root) {
        String subject = root.getSubjectX500Principal()
                .getName(X500Principal.RFC2253, Map.of("2.5.4.5", "SERIALNUMBER"));
        return "RSA".equals(root.getPublicKey().getAlgorithm())
                && subject.toLowerCase(Locale.ROOT).contains("f92009e853b6b045");
    }

    static boolean isSoftwareRoot(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().getName().contains(SOFTWARE_ROOT_CN);
    }

    private final class Repository implements TrustAnchorRepository {

        @Override
        public Set<TrustAnchor> find(AAGUID aaguid) {
            return anchors();
        }

        @Override
        public Set<TrustAnchor> find(byte[] attestationCertificateKeyIdentifier) {
            return anchors();
        }

        private Set<TrustAnchor> anchors() {
            refreshIfStale();
            Set<TrustAnchor> out = new LinkedHashSet<>();
            for (X509Certificate root : roots) {
                out.add(new TrustAnchor(root, null));
            }
            return out;
        }
    }

    private final class Verifier extends DefaultCertPathTrustworthinessVerifier {

        Verifier(TrustAnchorRepository repository) {
            super(repository);
            // Android chains carry the root itself as the last x5c element
            setFullChainProhibited(false);
            // Google publishes a JSON status list, not CRL/OCSP - checked below instead
            setRevocationCheckEnabled(false);
        }

        @Override
        public void verify(AAGUID aaguid, CertificateBaseAttestationStatement attestationStatement, Instant timestamp) {
            List<X509Certificate> chain = attestationStatement.getX5c();
            if (chain == null || chain.isEmpty()) {
                throw new BadAttestationStatementException("android-key attestation without x5c");
            }
            refreshIfStale();
            for (X509Certificate certificate : chain) {
                String status = revocationStatus(certificate.getSerialNumber());
                if (status != null) {
                    throw new BadAttestationStatementException("android-key certificate "
                            + certificate.getSerialNumber().toString(16) + " is " + status);
                }
            }
            X509Certificate top = chain.get(chain.size() - 1);
            X509Certificate anchor = findAnchor(top);
            if (anchor == null && config.allowSoftwareAttestationRoot() && isSoftwareRoot(top)) {
                // test only (emulators): signatures are checked, validity is not - the AOSP software
                // root and intermediate expire in January 2026
                for (int i = 0; i < chain.size() - 1; i++) {
                    verifySignature(chain.get(i), chain.get(i + 1));
                }
                verifySignature(top, top);
                LOG.warn("accepting the AOSP software attestation root because allowSoftwareAttestationRoot=true");
                return;
            }
            boolean legacyFactoryChain = anchor != null && isLegacyRsaRoot(anchor) && !hasProvisioningInfo(chain);
            Instant at = timestamp;
            if (legacyFactoryChain) {
                // Google keeps trusting pre-RKP factory chains after their expiry: validate them at the
                // moment the chain was issued instead of now
                at = latestNotBefore(chain);
                LOG.info("legacy factory chain under the RSA root - validity checked at {}", at);
            }
            super.verify(aaguid, attestationStatement, at);
        }

        private X509Certificate findAnchor(X509Certificate top) {
            for (X509Certificate root : roots) {
                if (root.getPublicKey().equals(top.getPublicKey())
                        && root.getSubjectX500Principal().equals(top.getSubjectX500Principal())) {
                    return root;
                }
            }
            for (X509Certificate root : roots) {
                if (root.getSubjectX500Principal().equals(top.getIssuerX500Principal())) {
                    try {
                        top.verify(root.getPublicKey());
                        return root;
                    } catch (Exception ignored) {
                        // try the next root
                    }
                }
            }
            return null;
        }

        private void verifySignature(X509Certificate child, X509Certificate issuer) {
            try {
                child.verify(issuer.getPublicKey());
            } catch (Exception e) {
                throw new BadAttestationStatementException("android-key chain signature invalid at "
                        + child.getSubjectX500Principal(), e);
            }
        }

        private boolean hasProvisioningInfo(List<X509Certificate> chain) {
            for (X509Certificate certificate : chain) {
                if (certificate.getExtensionValue(AndroidKeyAttestationPolicy.PROVISIONING_INFO_OID) != null) {
                    return true;
                }
            }
            return false;
        }

        private Instant latestNotBefore(List<X509Certificate> chain) {
            Instant latest = Instant.EPOCH;
            for (X509Certificate certificate : chain) {
                Instant notBefore = certificate.getNotBefore().toInstant();
                if (notBefore.isAfter(latest)) {
                    latest = notBefore;
                }
            }
            return latest;
        }
    }
}
