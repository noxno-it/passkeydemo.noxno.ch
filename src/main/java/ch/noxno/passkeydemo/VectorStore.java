package ch.noxno.passkeydemo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;

/**
 * Every successful ceremony is written to vectors/&lt;platform&gt;-&lt;timestamp&gt;.json so real device
 * attestations become replayable test vectors. The envelope carries the challenges, because a
 * request body alone cannot be re-verified.
 */
public final class VectorStore {

    private static final Logger LOG = LoggerFactory.getLogger(VectorStore.class);
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmssSSS'Z'");

    private final Path dir;
    private final ObjectMapper mapper;

    public VectorStore(Path dir, ObjectMapper mapper) {
        this.dir = dir;
        this.mapper = mapper;
    }

    public void record(String platform, String kind, String rpId, byte[] challenge, byte[] appAttestChallenge,
            String rawRequestJson) {
        try {
            Files.createDirectories(dir);
            Map<String, Object> envelope = new LinkedHashMap<>();
            envelope.put("kind", kind);
            envelope.put("platform", platform);
            envelope.put("recordedAt", ZonedDateTime.now(ZoneOffset.UTC).toString());
            envelope.put("rpId", rpId);
            envelope.put("challenge", Base64Url.encode(challenge));
            envelope.put("appAttestChallenge", Base64Url.encode(appAttestChallenge));
            envelope.put("request", mapper.readTree(rawRequestJson));
            String stamp = ZonedDateTime.now(ZoneOffset.UTC).format(STAMP);
            Path file = dir.resolve(platform + "-" + stamp + ".json");
            Files.writeString(file, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(envelope));
            LOG.info("vector written: {}", file.toAbsolutePath());
        } catch (IOException | RuntimeException e) {
            LOG.warn("could not write vector for {} {}: {}", platform, kind, e.toString());
        }
    }
}
