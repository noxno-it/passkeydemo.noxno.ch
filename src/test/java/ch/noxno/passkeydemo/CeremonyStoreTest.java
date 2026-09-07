package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class CeremonyStoreTest {

    @Test
    void challengesAre32BytesAndUnique() {
        CeremonyStore store = new CeremonyStore(300);
        CeremonyStore.Ceremony first = store.create(CeremonyStore.Type.LOGIN, null);
        CeremonyStore.Ceremony second = store.create(CeremonyStore.Type.LOGIN, null);

        assertEquals(32, first.challenge.length);
        assertEquals(32, first.appAttestChallenge.length);
        assertNotEquals(Base64Url.encode(first.challenge), Base64Url.encode(second.challenge));
    }

    @Test
    void expiredCeremonyIsRejected() {
        CeremonyStore store = new CeremonyStore(0);
        CeremonyStore.Ceremony ceremony = store.create(CeremonyStore.Type.LOGIN, null);

        ApiException failure = assertThrows(ApiException.class,
                () -> store.require(ceremony.ceremonyId, CeremonyStore.Type.LOGIN));
        assertEquals(ApiException.CEREMONY_EXPIRED, failure.getCode());
    }

    @Test
    void consumedCeremonyIsRejected() {
        CeremonyStore store = new CeremonyStore(300);
        CeremonyStore.Ceremony ceremony = store.create(CeremonyStore.Type.LOGIN, null);
        store.consume(store.require(ceremony.ceremonyId, CeremonyStore.Type.LOGIN));

        ApiException failure = assertThrows(ApiException.class,
                () -> store.require(ceremony.ceremonyId, CeremonyStore.Type.LOGIN));
        assertEquals(ApiException.CEREMONY_CONSUMED, failure.getCode());
    }

    @Test
    void registerCeremonySurvivesAFailedAttemptSoAppAttestCanRetry() {
        CeremonyStore store = new CeremonyStore(300);
        CeremonyStore.Ceremony ceremony = store.create(CeremonyStore.Type.REGISTER, "demo@example.com");

        // a failed register/verify does not consume the ceremony (Apple serverUnavailable retry)
        CeremonyStore.Ceremony again = store.require(ceremony.ceremonyId, CeremonyStore.Type.REGISTER);
        assertEquals(ceremony.ceremonyId, again.ceremonyId);
        assertEquals(Base64Url.encode(ceremony.appAttestChallenge), Base64Url.encode(again.appAttestChallenge));

        store.consume(again);
        assertThrows(ApiException.class, () -> store.require(ceremony.ceremonyId, CeremonyStore.Type.REGISTER));
    }

    @Test
    void wrongCeremonyTypeIsRejected() {
        CeremonyStore store = new CeremonyStore(300);
        CeremonyStore.Ceremony ceremony = store.create(CeremonyStore.Type.LOGIN, null);

        ApiException failure = assertThrows(ApiException.class,
                () -> store.require(ceremony.ceremonyId, CeremonyStore.Type.UNLOCK));
        assertEquals(ApiException.CEREMONY_EXPIRED, failure.getCode());
    }
}
