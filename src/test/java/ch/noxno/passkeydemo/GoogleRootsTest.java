package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/** Network test: ./gradlew test -Dpasskey.network.tests=true */
@EnabledIfSystemProperty(named = "passkey.network.tests", matches = "true")
class GoogleRootsTest {

    @Test
    void loadsBothGoogleRootsAndTheRevocationList() {
        Config config = Config.defaults();
        GoogleRoots roots = new GoogleRoots(config, Json.mapper());

        List<X509Certificate> loaded = roots.roots();
        assertTrue(loaded.size() >= 2, "expected at least the RSA and the EC root, got " + loaded.size());

        long legacy = loaded.stream().filter(GoogleRoots::isLegacyRsaRoot).count();
        assertEquals(1, legacy, "exactly one root must be the legacy RSA root f92009e853b6b045");
        assertTrue(loaded.stream().anyMatch(root -> "EC".equals(root.getPublicKey().getAlgorithm())),
                "the RKP era EC root Key Attestation CA1 must be trusted as well");

        assertNull(roots.revocationStatus(new BigInteger("1")), "leaf serial 1 must not be on the status list");
        AAGUID appAndroid = new AAGUID("2b9c7d6e-5f4a-4c3b-8a2d-1e0f9c8b7a6d");
        assertEquals(loaded.size(), roots.trustAnchorRepository().find(appAndroid).size(),
                "every root must be offered to webauthn4j as a trust anchor");
    }
}
