package ch.noxno.passkeydemo;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Simple token bucket per key (client IP or credentialId). O.Auth_7 / TR-03188 rate limiting. */
public final class RateLimiter {

    private static final class Bucket {
        double tokens;
        long lastRefillNanos;

        Bucket(double tokens, long lastRefillNanos) {
            this.tokens = tokens;
            this.lastRefillNanos = lastRefillNanos;
        }
    }

    private final double capacity;
    private final double refillPerSecond;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter(int permitsPerMinute) {
        this.capacity = permitsPerMinute;
        this.refillPerSecond = permitsPerMinute / 60.0;
    }

    public boolean tryAcquire(String key) {
        long now = System.nanoTime();
        Bucket bucket = buckets.computeIfAbsent(key, k -> new Bucket(capacity, now));
        synchronized (bucket) {
            double elapsedSeconds = (now - bucket.lastRefillNanos) / 1_000_000_000.0;
            bucket.lastRefillNanos = now;
            bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSeconds * refillPerSecond);
            if (bucket.tokens < 1.0) {
                return false;
            }
            bucket.tokens -= 1.0;
            return true;
        }
    }

    /** Throws RATE_LIMITED (HTTP 403) when the bucket is empty. */
    public void check(String key) {
        if (!tryAcquire(key)) {
            throw ApiException.rateLimited();
        }
    }
}
