package ch.noxno.passkeydemo;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ceremonies live 5 minutes (ceremonyTtlSeconds) and are single-use.
 * login/unlock are consumed on the first verify attempt; register is consumed only on success,
 * so an Apple serverUnavailable retry with the same App Attest challenge still works.
 */
public final class CeremonyStore {

    public enum Type {
        REGISTER, LOGIN, UNLOCK
    }

    public static final class Ceremony {
        public final String ceremonyId;
        public final Type type;
        public final String username;
        public final byte[] challenge;
        public final byte[] appAttestChallenge;
        public final Instant createdAt;
        public final Instant expiresAt;
        public volatile Instant consumedAt;

        Ceremony(String ceremonyId, Type type, String username, byte[] challenge, byte[] appAttestChallenge,
                Instant createdAt, Instant expiresAt) {
            this.ceremonyId = ceremonyId;
            this.type = type;
            this.username = username;
            this.challenge = challenge;
            this.appAttestChallenge = appAttestChallenge;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }
    }

    private final Map<String, Ceremony> ceremonies = new ConcurrentHashMap<>();
    private final Duration ttl;

    public CeremonyStore(long ttlSeconds) {
        this.ttl = Duration.ofSeconds(ttlSeconds);
    }

    public Ceremony create(Type type, String username) {
        Instant now = Instant.now();
        Ceremony ceremony = new Ceremony(UUID.randomUUID().toString(), type, username,
                Base64Url.random(32), Base64Url.random(32), now, now.plus(ttl));
        ceremonies.put(ceremony.ceremonyId, ceremony);
        return ceremony;
    }

    /** Throws CEREMONY_EXPIRED / CEREMONY_CONSUMED; never returns a stale ceremony. */
    public Ceremony require(String ceremonyId, Type type) {
        Ceremony ceremony = ceremonyId == null ? null : ceremonies.get(ceremonyId);
        if (ceremony == null || ceremony.type != type) {
            throw ApiException.ceremonyExpired();
        }
        if (Instant.now().isAfter(ceremony.expiresAt)) {
            ceremonies.remove(ceremonyId);
            throw ApiException.ceremonyExpired();
        }
        if (ceremony.consumedAt != null) {
            throw ApiException.ceremonyConsumed();
        }
        return ceremony;
    }

    public void consume(Ceremony ceremony) {
        ceremony.consumedAt = Instant.now();
    }

    public void purgeExpired() {
        Instant now = Instant.now();
        ceremonies.values().removeIf(c -> now.isAfter(c.expiresAt));
    }

    public int size() {
        return ceremonies.size();
    }
}
