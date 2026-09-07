package ch.noxno.passkeydemo;

import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** The one Jackson 3 mapper of the server. webauthn4j 0.31.10 uses Jackson 3 (tools.jackson), not 2.x. */
public final class Json {

    private Json() {
    }

    public static ObjectMapper mapper() {
        return JsonMapper.builder()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .build();
    }
}
