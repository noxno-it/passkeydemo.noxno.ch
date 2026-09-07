# syntax=docker/dockerfile:1
#
# Passkey demo relying party - container image for https://passkeydemo.noxno.ch
#
#   docker build -t passkey-demo:local .
#
# Build context is THIS directory (the repository root), nothing above it.
# Requires BuildKit (the default since Docker 23) because of the heredoc that writes the
# entrypoint. On an older daemon, prefix the build with DOCKER_BUILDKIT=1.
#
# WHAT THIS SERVER IS: a reference/demo relying party. Read the SECURITY section of
# DEPLOY.md before you point a DNS name at it. It keeps credentials in memory,
# compares passwords in clear text and must never see production sensitive personal data.

# ---------------------------------------------------------------- build stage
# Pinned to the exact Gradle version in gradle/wrapper/gradle-wrapper.properties.
# Keep the two in sync when the wrapper is bumped.
FROM gradle:9.3.1-jdk21 AS build

WORKDIR /home/gradle/src

# Dependency layer first so a source-only change does not re-download the world.
COPY --chown=gradle:gradle settings.gradle.kts build.gradle.kts ./
RUN gradle --no-daemon --console=plain dependencies --configuration runtimeClasspath > /dev/null 2>&1 || true

COPY --chown=gradle:gradle src ./src

# installDist, not `jar`: build.gradle.kts applies the `application` plugin and produces
# NO fat jar, so the runtime needs build/install/<name>/lib/*.jar on the classpath.
# Add `test` in front of installDist to gate the image on the suite (62 tests: 56 pass / 6 skips).
RUN gradle --no-daemon --console=plain installDist

# The browser demo page served at /demo when attestationPolicy=demo. `staticDir`
# (default ./public) is part of the build context - see .dockerignore, which keeps it in
# on purpose. mkdir -p afterwards is a no-op safety net so the COPY into the runtime stage
# never fails if the directory is ever empty. A bundled placeholder page also lives on the
# classpath in src/main/resources/public and answers whenever /app/public has no index.html.
COPY --chown=gradle:gradle public ./public
RUN mkdir -p /home/gradle/src/public

# -------------------------------------------------------------- runtime stage
FROM eclipse-temurin:21-jre-jammy AS runtime

# curl is only here for HEALTHCHECK; tzdata so TZ=Europe/Berlin resolves.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 passkey \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin passkey

WORKDIR /app

COPY --from=build /home/gradle/src/build/install/passkey-reference-server/lib /app/lib
COPY --from=build /home/gradle/src/public /app/public
# users.json is git-ignored (it holds credentials); the example ships instead and the
# entrypoint falls back to it, so a fresh clone builds without hand-seeding a user store.
COPY application.properties users.json.example /app/
RUN cp -n /app/users.json.example /app/users.json

# /app/data is the only path the server writes to (Google attestation-root cache and
# recorded test vectors). Created here and chowned so that an EMPTY named volume mounted
# over it inherits uid 10001 - Docker seeds a fresh named volume from the image, ownership
# included. A BIND mount does not get that treatment: chown -R 10001:10001 it on the host.
RUN mkdir -p /app/data/cache /app/data/vectors \
    && chown -R 10001:10001 /app/data /app/public

# Container defaults. Everything with a PASSKEY_ prefix is written into the effective
# application.properties by the entrypoint and therefore WINS over the baked-in file.
# The four path/port values below pin the container layout on purpose - override the port
# with PASSKEY_PORT (never by editing the properties file) so HEALTHCHECK stays correct.
ENV PASSKEY_PORT=8099 \
    PASSKEY_CACHE_DIR=/app/data/cache \
    PASSKEY_VECTORS_DIR=/app/data/vectors \
    PASSKEY_USERS_FILE=/app/users.json \
    PASSKEY_STATIC_DIR=/app/public \
    LANG=C.UTF-8

# API context path. Kept as an ENV rather than left to application.properties so HEALTHCHECK below
# can build the same URL the routes are mounted on. Change BOTH together, or change only this.
ENV PASSKEY_BASE_PATH=/api

# Small-VPS JVM: container-aware heap cap, SerialGC (cheapest on 1-2 vCPU with a heap in
# the low hundreds of MB), die instead of thrashing on OOM so the restart policy takes over,
# and slf4j-simple with timestamps on stdout - the shipped default is bare stderr.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0 \
-XX:+UseSerialGC \
-XX:+ExitOnOutOfMemoryError \
-XX:+HeapDumpOnOutOfMemoryError \
-XX:HeapDumpPath=/tmp \
-Dfile.encoding=UTF-8 \
-Dstdout.encoding=UTF-8 \
-Dorg.slf4j.simpleLogger.logFile=System.out \
-Dorg.slf4j.simpleLogger.showDateTime=true \
-Dorg.slf4j.simpleLogger.dateTimeFormat=yyyy-MM-dd'T'HH:mm:ss.SSSXXX"

# Appended after JAVA_OPTS; use this to add flags without restating the whole list.
ENV JAVA_EXTRA_OPTS=""

RUN <<'ENTRYPOINT' cat > /usr/local/bin/passkey-entrypoint.sh
#!/bin/sh
# Renders /tmp/runtime.properties = baked application.properties + PASSKEY_* overrides,
# runs a safety preflight, then execs the JVM as PID 1's child.
#
# Why a rendered file and not real env support: Config.java reads java.util.Properties from
# one file and knows nothing about the environment. Duplicate keys are legal there and the
# LAST occurrence wins, so appending overrides after the base file is all it takes.
set -eu

BASE_PROPS="${PASSKEY_BASE_PROPERTIES:-/app/application.properties}"
RUNTIME_PROPS="${PASSKEY_RUNTIME_PROPERTIES:-/tmp/runtime.properties}"

: > "$RUNTIME_PROPS"
if [ -f "$BASE_PROPS" ]; then
    cat "$BASE_PROPS" >> "$RUNTIME_PROPS"
    printf '\n' >> "$RUNTIME_PROPS"
fi

# override <propertyKey> <ENV_VAR_NAME> - appended only when the variable is SET
# (an explicitly empty value is meaningful, e.g. adminToken= disables the reset endpoint).
override() {
    _key="$1"
    _var="$2"
    eval "_isset=\${$_var+set}"
    if [ "${_isset:-}" = "set" ]; then
        eval "_val=\${$_var}"
        printf '%s=%s\n' "$_key" "$_val" >> "$RUNTIME_PROPS"
    fi
}

override port                         PASSKEY_PORT
override basePath                     PASSKEY_BASE_PATH
override rpId                         PASSKEY_RP_ID
override rpName                       PASSKEY_RP_NAME
override acceptedOrigins              PASSKEY_ACCEPTED_ORIGINS
override attestationPolicy            PASSKEY_ATTESTATION_POLICY
override staticDir                    PASSKEY_STATIC_DIR
override androidPackageName           PASSKEY_ANDROID_PACKAGE_NAME
override androidSigningDigests        PASSKEY_ANDROID_SIGNING_DIGESTS
override iosAppIds                    PASSKEY_IOS_APP_IDS
override appAttestEnvironments        PASSKEY_APP_ATTEST_ENVIRONMENTS
override allowSoftwareAttestationRoot PASSKEY_ALLOW_SOFTWARE_ATTESTATION_ROOT
override verifiedBootPolicy           PASSKEY_VERIFIED_BOOT_POLICY
override unlockWindowSeconds          PASSKEY_UNLOCK_WINDOW_SECONDS
override ceremonyTtlSeconds           PASSKEY_CEREMONY_TTL_SECONDS
override rateLimitPerMinute           PASSKEY_RATE_LIMIT_PER_MINUTE
override adminToken                   PASSKEY_ADMIN_TOKEN
override googleRootsUrl               PASSKEY_GOOGLE_ROOTS_URL
override googleStatusUrl              PASSKEY_GOOGLE_STATUS_URL
override cacheDir                     PASSKEY_CACHE_DIR
override vectorsDir                   PASSKEY_VECTORS_DIR
override usersFile                    PASSKEY_USERS_FILE
override appleAppAttestRootPemPath    PASSKEY_APPLE_ROOT_PEM_PATH
override serveWellKnown               PASSKEY_SERVE_WELL_KNOWN
override appleTeamId                  PASSKEY_APPLE_TEAM_ID
override androidWebCredentialDigests  PASSKEY_ANDROID_WEB_CREDENTIAL_DIGESTS

# Escape hatch for a key this entrypoint does not know yet: raw properties lines.
#   PASSKEY_EXTRA_PROPERTIES=$'someNewKey=value\nother=value'
if [ -n "${PASSKEY_EXTRA_PROPERTIES:-}" ]; then
    printf '%s\n' "$PASSKEY_EXTRA_PROPERTIES" >> "$RUNTIME_PROPS"
fi

# Effective value of a key = last occurrence, mirroring java.util.Properties.
effective() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$RUNTIME_PROPS" 2>/dev/null | tail -n 1 \
        | sed -e "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//" || true
}

RP_ID="$(effective rpId)"
POLICY="$(effective attestationPolicy)"
SOFT_ROOT="$(effective allowSoftwareAttestationRoot)"
BOOT_POLICY="$(effective verifiedBootPolicy)"
ADMIN="$(effective adminToken)"
PORT="$(effective port)"

# One line per key with the value that actually wins, in first-appearance order.
echo "--- effective configuration (${RUNTIME_PROPS}) ---"
awk '
    /^[[:space:]]*(#|!)/ { next }
    index($0, "=") == 0  { next }
    {
        k = substr($0, 1, index($0, "=") - 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
        if (k == "") next
        eff[k] = substr($0, index($0, "=") + 1)
        if (!(k in seen)) { seen[k] = 1; keys[++n] = k }
    }
    END {
        for (i = 1; i <= n; i++) {
            k = keys[i]
            printf "%s=%s\n", k, (k == "adminToken" ? "********" : eff[k])
        }
    }
' "$RUNTIME_PROPS"
echo "--- end configuration ---"

# Hard stop on the one default that hands the account-recovery endpoint to the internet.
# Config.java falls back to "change-me" when the key is absent entirely.
if [ -z "${ADMIN}" ] && ! grep -qE "^[[:space:]]*adminToken[[:space:]]*=" "$RUNTIME_PROPS"; then
    ADMIN="change-me"
fi
if [ "${ADMIN}" = "change-me" ]; then
    if [ "${PASSKEY_ALLOW_INSECURE_DEFAULTS:-}" = "1" ] || [ "${PASSKEY_ALLOW_INSECURE_DEFAULTS:-}" = "true" ]; then
        echo "WARNING: adminToken is still \"change-me\" and PASSKEY_ALLOW_INSECURE_DEFAULTS is set." >&2
        echo "WARNING: anyone who can reach this server can reset any account. LOCAL USE ONLY." >&2
    else
        echo "FATAL: adminToken is still the shipped default \"change-me\"." >&2
        echo "FATAL: set PASSKEY_ADMIN_TOKEN to a long random secret (openssl rand -hex 32)," >&2
        echo "FATAL: or PASSKEY_ADMIN_TOKEN= (empty) to disable passkey/admin/reset entirely," >&2
        echo "FATAL: or PASSKEY_ALLOW_INSECURE_DEFAULTS=1 for a throwaway local container." >&2
        exit 78
    fi
fi
if [ -z "${ADMIN}" ]; then
    echo "NOTE: adminToken is empty - POST passkey/admin/reset always answers 401 (endpoint disabled)."
fi

# Loud, non-fatal: the settings that decide whether this demo is worth anything to an auditor.
[ "${POLICY:-strict}" = "demo" ] && cat >&2 <<'WARN'
WARNING: attestationPolicy=demo. fmt=none is accepted, so a plain BROWSER passkey can
WARNING: complete the ceremony. Such a credential is stored unattested and sits at BSI
WARNING: trust level "normal", NOT "substantiell". Only a native app can produce
WARNING: android-key or packed + Apple App Attest. A browser can never produce attestation.
WARN
[ "${SOFT_ROOT:-true}" = "true" ] && \
    echo "WARNING: allowSoftwareAttestationRoot=true - the AOSP software attestation root (emulators) is accepted. Set PASSKEY_ALLOW_SOFTWARE_ATTESTATION_ROOT=false for a real demo." >&2
[ "${BOOT_POLICY:-log}" != "enforce" ] && \
    echo "WARNING: verifiedBootPolicy=${BOOT_POLICY:-log} - an unlocked bootloader is logged, not rejected. Set PASSKEY_VERIFIED_BOOT_POLICY=enforce for a real demo." >&2

echo "starting on port ${PORT:-8099}, rpId=${RP_ID:-<default>}, origin=https://${RP_ID:-<default>}"

CP="/app/lib/*"
# shellcheck disable=SC2086
exec java ${JAVA_OPTS:-} ${JAVA_EXTRA_OPTS:-} -cp "$CP" ch.noxno.passkeydemo.Main "$RUNTIME_PROPS"
ENTRYPOINT

RUN chmod 0555 /usr/local/bin/passkey-entrypoint.sh

USER 10001:10001

EXPOSE 8099

# retrieveChallenge is the only unauthenticated GET that answers 200, and it is the one
# rate-limiter-free endpoint - a health probe every 30s can never eat a client's budget.
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
    CMD curl -fsS -o /dev/null \
        "http://127.0.0.1:${PASSKEY_PORT:-8099}${PASSKEY_BASE_PATH:-/api}/rest/authentication/retrieveChallenge" \
        || exit 1

ENTRYPOINT ["/usr/local/bin/passkey-entrypoint.sh"]
