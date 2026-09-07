package ch.noxno.passkeydemo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/** Reads the envelopes written by VectorStore: vectors/&lt;platform&gt;-&lt;timestamp&gt;.json. */
final class VectorFiles {

    static final Path DIR = Paths.get("vectors");

    private VectorFiles() {
    }

    static List<JsonNode> load(String platform, String kind) throws IOException {
        List<JsonNode> out = new ArrayList<>();
        if (!Files.isDirectory(DIR)) {
            return out;
        }
        ObjectMapper mapper = Json.mapper();
        try (Stream<Path> files = Files.list(DIR)) {
            for (Path file : files.sorted().toList()) {
                String name = file.getFileName().toString();
                if (!name.startsWith(platform + "-") || !name.endsWith(".json")) {
                    continue;
                }
                JsonNode envelope = mapper.readTree(Files.readString(file));
                JsonNode kindNode = envelope.get("kind");
                if (kindNode != null && kind.equals(kindNode.asString())) {
                    out.add(envelope);
                }
            }
        }
        return out;
    }
}
