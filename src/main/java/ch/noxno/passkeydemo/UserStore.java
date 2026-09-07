package ch.noxno.passkeydemo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/** In-memory accounts, seeded from users.json ([{"username": "...", "password": "..."}]). */
public final class UserStore {

    public static final class User {
        public final String username;
        public final String password;
        public volatile byte[] userHandle;
        public volatile boolean passkeyRequired;

        User(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    private final Map<String, User> usersByName = new ConcurrentHashMap<>();
    private final Map<String, String> tokens = new ConcurrentHashMap<>();

    public UserStore(Path usersFile, ObjectMapper mapper) {
        if (!Files.isRegularFile(usersFile)) {
            throw new IllegalStateException("users.json not found at " + usersFile.toAbsolutePath());
        }
        List<Dto.SeedUser> seed;
        try {
            seed = mapper.readValue(Files.readString(usersFile), new TypeReference<List<Dto.SeedUser>>() {
            });
        } catch (Exception e) {
            throw new IllegalStateException("Cannot parse " + usersFile.toAbsolutePath(), e);
        }
        for (Dto.SeedUser entry : seed) {
            String key = normalise(entry.username);
            usersByName.put(key, new User(key, entry.password));
        }
    }

    public static String normalise(String username) {
        return username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    }

    public Optional<User> find(String username) {
        return Optional.ofNullable(usersByName.get(normalise(username)));
    }

    /** Same generic failure for unknown user and wrong password (NRM-7, no account enumeration). */
    public User requireByPassword(String username, String password) {
        User user = usersByName.get(normalise(username));
        if (user == null || password == null
                || !Base64Url.constantTimeEquals(Base64Url.utf8(user.password), Base64Url.utf8(password))) {
            throw ApiException.passwordInvalid();
        }
        return user;
    }

    /** Server-random 32 bytes, created on first register/options, never derived from PII (NRM-6). */
    public byte[] userHandle(User user) {
        synchronized (user) {
            if (user.userHandle == null) {
                user.userHandle = Base64Url.random(32);
            }
            return user.userHandle;
        }
    }

    public String issueToken(User user) {
        String token = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        tokens.put(token, user.username);
        return token;
    }

    public Optional<User> byToken(String token) {
        if (token == null) {
            return Optional.empty();
        }
        String username = tokens.get(token);
        return username == null ? Optional.empty() : Optional.ofNullable(usersByName.get(username));
    }

    public void revokeToken(String token) {
        if (token != null) {
            tokens.remove(token);
        }
    }
}
