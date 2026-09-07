package ch.noxno.passkeydemo;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UserStoreTest {

    private UserStore users;

    @BeforeEach
    void setUp(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("users.json");
        Files.writeString(file, "[{\"username\":\"Demo@Example.com\",\"password\":\"Test123!\"}]",
                StandardCharsets.UTF_8);
        users = new UserStore(file, Json.mapper());
    }

    @Test
    void findsUsersCaseInsensitively() {
        assertTrue(users.find("demo@example.com").isPresent());
        assertTrue(users.find("  DEMO@EXAMPLE.COM ").isPresent());
        assertTrue(users.find("nobody@example.com").isEmpty());
    }

    @Test
    void wrongPasswordAndUnknownUserFailIdentically() {
        ApiException wrongPassword = assertThrows(ApiException.class,
                () -> users.requireByPassword("demo@example.com", "nope"));
        ApiException unknownUser = assertThrows(ApiException.class,
                () -> users.requireByPassword("nobody@example.com", "Test123!"));

        assertEquals(ApiException.PASSWORD_INVALID, wrongPassword.getCode());
        assertEquals(wrongPassword.getMessage(), unknownUser.getMessage());
    }

    @Test
    void userHandleIs32RandomBytesAndStable() {
        UserStore.User user = users.requireByPassword("demo@example.com", "Test123!");

        byte[] first = users.userHandle(user);
        assertEquals(32, first.length);
        assertArrayEquals(first, users.userHandle(user));
    }

    @Test
    void tokensResolveUntilTheyAreRevoked() {
        UserStore.User user = users.requireByPassword("demo@example.com", "Test123!");

        String token = users.issueToken(user);
        assertEquals("demo@example.com", users.byToken(token).orElseThrow().username);

        users.revokeToken(token);
        assertTrue(users.byToken(token).isEmpty());
        assertTrue(users.byToken(null).isEmpty());
    }
}
