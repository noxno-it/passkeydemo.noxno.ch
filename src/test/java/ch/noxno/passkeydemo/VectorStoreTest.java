package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;

class VectorStoreTest {

    @Test
    void writesAnEnvelopeThatCarriesTheChallenges(@TempDir Path dir) throws Exception {
        VectorStore store = new VectorStore(dir, Json.mapper());
        byte[] challenge = Base64Url.random(32);
        byte[] appAttestChallenge = Base64Url.random(32);

        store.record("android", "register", "passkeys.example.org", challenge, appAttestChallenge,
                "{\"ceremonyId\":\"c-1\",\"deviceName\":\"Test Device\"}");

        List<Path> files;
        try (Stream<Path> stream = Files.list(dir)) {
            files = stream.toList();
        }
        assertEquals(1, files.size());
        String name = files.get(0).getFileName().toString();
        assertTrue(name.startsWith("android-") && name.endsWith(".json"), "unexpected vector name " + name);

        JsonNode envelope = Json.mapper().readTree(Files.readString(files.get(0)));
        assertEquals("register", envelope.get("kind").asString());
        assertEquals("android", envelope.get("platform").asString());
        assertEquals(Base64Url.encode(challenge), envelope.get("challenge").asString());
        assertEquals(Base64Url.encode(appAttestChallenge), envelope.get("appAttestChallenge").asString());
        assertEquals("Test Device", envelope.get("request").get("deviceName").asString());
    }
}
