package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RateLimiterTest {

    @Test
    void spendsTheBucketAndThenRejects() {
        RateLimiter limiter = new RateLimiter(3);
        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertTrue(limiter.tryAcquire("1.2.3.4"));

        ApiException failure = assertThrows(ApiException.class, () -> limiter.check("1.2.3.4"));
        assertEquals(ApiException.RATE_LIMITED, failure.getCode());
    }

    @Test
    void bucketsAreIndependentPerKey() {
        RateLimiter limiter = new RateLimiter(1);
        assertTrue(limiter.tryAcquire("1.2.3.4"));
        assertTrue(limiter.tryAcquire("5.6.7.8"));
    }
}
