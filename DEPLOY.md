# Deploying the passkey demo relying party at https://passkeydemo.noxno.ch

A runbook for putting this server on a small VPS behind nginx and TLS,
either as a container (`Dockerfile` + `docker-compose.yml`) or as a plain systemd service
(`deploy/passkey-demo.service`). Every command below is meant to be run as-is on the server.

Read [SECURITY](#13-security) before you point DNS at anything. Short version: this is a
reference/demo relying party. Credentials live in RAM, passwords are compared in clear text,
and it must never hold production sensitive personal data.

---

## 0. What a browser at passkeydemo.noxno.ch can and cannot show

This matters more than any command in this file, so it comes first.

**The passkey CEREMONY works in a browser.** Once `passkeydemo.noxno.ch` serves HTTPS, Chrome, Safari
and Firefox can run `navigator.credentials.create()` / `.get()` against this server, and with
`attestationPolicy=demo` the credential is accepted and stored. That is a real, watchable
WebAuthn registration and login.

**ATTESTATION does not.** A browser passkey — iCloud Keychain, Google Password Manager, a
Windows Hello key — returns attestation format `"none"`. There is no hardware statement to
verify, so the server stores such credentials with `attested=false`. Under BSI TR-03161 that
is trust level *normal*, never *substantiell*.

Attestation is obtainable **only from a native app**, where the app itself is the
WebAuthn authenticator, the key sits in the Secure Enclave / StrongBox-or-TEE, and the
platform emits:

| Platform | WebAuthn attestation format | Additional proof |
|---|---|---|
| Android | `android-key`, chain up to a Google attestation root | — |
| iOS | `packed` (self attestation) | Apple App Attest object bound to the credential |

So plan the demo as two halves and say so out loud:

1. **Browser at `https://passkeydemo.noxno.ch/demo/`** — shows the ceremony, the challenge, the
   credential, the login. Server logs will say `fmt=none`, `attested=false`. This half proves
   the protocol, not the hardware.
2. **A native app pointed at `https://passkeydemo.noxno.ch/api/`** — shows the same
   ceremony *with* `android-key` / App Attest, `attested=true` and a `securityLevel` of
   `TRUSTED_ENVIRONMENT` or `STRONGBOX` in the log line. This half is the one an auditor cares
   about.

### The two `.well-known` files: hosted here, and what they are actually for

`passkeydemo.noxno.ch` **does** serve both domain-association files. The server generates them from
`application.properties` at boot and answers them in **strict and demo mode alike**; `serveWellKnown`
(default `true`) is the only switch, and `false` makes both paths answer `404`.

| URL | Grants | To |
|---|---|---|
| `/.well-known/apple-app-site-association` | `webcredentials` for every `iosAppIds` entry, e.g. `<TEAM_ID>.<BUNDLE_ID>` | iCloud Keychain, inside the iOS app |
| `/.well-known/assetlinks.json` | `delegate_permission/common.get_login_creds` for `<PACKAGE_NAME>` + its signing certificates | Google Password Manager, inside the Android app |

What they buy is a **platform** passkey — held by the OS vendor, not by the app:

| | Platform passkey (these files) | The app as the authenticator |
|---|---|---|
| Key lives in | iCloud Keychain / Google Password Manager | Secure Enclave / StrongBox-or-TEE |
| Syncs to the user's other devices | **yes** | **no** — `BE=0 && BS=0` enforced |
| Attestation format | `none` | `packed` + Apple App Attest / `android-key` |
| BSI trust level | **normal** | **substantiell** |
| Needs these two files | **yes** | **no** |
| Accepted by this server under | `attestationPolicy=demo`, stored `attested=false` | `attestationPolicy=strict` |
| Setup work | §7a here, `PLATFORM-SETUP.md` §1.5 and §2.10 | `PLATFORM-SETUP.md` §1–§2 |

**Hosting them changes nothing about attestation.** The attested design never fetches anything from
`passkeydemo.noxno.ch` — it uses the hostname purely as the `rpId` string hashed into `authenticatorData`.
Host these files because the convenience path is worth having on its own terms, not because the
compliance path needs them; it does not. Just never let the two blur together in the demo narrative:
a synced platform passkey is not the attested credential, and the server's own log says so on every
enrolment.

---

## 1. Prerequisites

* A VPS with a public IPv4 (and ideally IPv6) address. 1 vCPU / 1 GB RAM is enough to **run**
  the server — the JVM is capped at 768 MB. It is **not** enough to **build** it: Gradle plus
  javac want ~2 GB. On a 1 GB box either build elsewhere and ship the image
  (`docker save` / `docker load`) or the `lib/` directory, or add swap first.
* Ubuntu 24.04 LTS or 22.04 LTS (the commands below assume `apt`). Debian 12 works too, but
  `openjdk-21-jre-headless` lives in `bookworm-backports` there — the Docker route avoids that
  question entirely.
* Root or `sudo`.
* **Outbound HTTPS to `android.googleapis.com`.** The server fetches the Google hardware
  attestation roots and the revocation list from there and caches them for 24 h. Without that
  fetch and without a warm cache, `android-key` verification has no roots to build a chain to.
* Docker route only: Docker Engine 23+ (BuildKit is the default there and the `Dockerfile`
  needs it) and the compose plugin.

```bash
sudo apt update
sudo apt install -y nginx certbot            # both routes
sudo apt install -y openjdk-21-jre-headless  # systemd route only
```

---

## 2. DNS

> The demo host is a **subdomain record inside the existing parent zone**, not a new hosted zone
> for the subdomain (a separate zone would need `NS` delegation records in the parent and buys
> nothing here).
>
> Nothing further in this runbook works until that record resolves: certbot cannot complete the
> HTTP-01 challenge (§4), Apple's CDN cannot fetch the AASA and Google's Digital Asset Links checker
> cannot fetch `assetlinks.json` (§7a).

Create the records at the authoritative DNS for the parent zone (`noxno.ch` here):

| Type | Name | Value | TTL |
|---|---|---|---|
| `A` | `passkeydemo` | the VPS IPv4 address | 300 |
| `AAAA` | `passkeydemo` | the VPS IPv6 address (omit the record entirely if the VPS has none) | 300 |

Do **not** create an `AAAA` record you cannot serve: Let's Encrypt prefers IPv6 and the
challenge will fail against a dead address.

Wait for propagation before running certbot:

```bash
dig +short A    passkeydemo.noxno.ch
dig +short AAAA passkeydemo.noxno.ch
# both must return the VPS addresses, from the server itself and from outside
```

`rpId=passkeydemo.noxno.ch` is baked into every enrolled credential's `authenticatorData.rpIdHash`.
Changing the hostname later invalidates every passkey already enrolled — pick it once.

---

## 3. Firewall

Only 80 and 443 face the internet. The application port (8099) stays on loopback: both the
container and the systemd unit bind `127.0.0.1:8099`, and nginx is the only thing that talks
to it.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status verbose
```

Verify from **outside** the box that 8099 is not reachable:

```bash
nc -z -w3 passkeydemo.noxno.ch 8099 && echo "EXPOSED - fix this" || echo "closed, good"
```

> Docker note: `docker compose` publishes `127.0.0.1:8099:8099`. Never change that to
> `8099:8099` — Docker writes its own iptables rules and would punch straight through ufw,
> putting a plain-HTTP relying party on the internet.

---

## 4. TLS certificate

The shipped nginx config references `/etc/letsencrypt/live/passkeydemo.noxno.ch/…`, which does not
exist yet, so `nginx -t` fails if you install it first. Bootstrap over plain HTTP, issue, then
install the real config.

**4a. HTTP-only bootstrap**

```bash
sudo mkdir -p /var/www/certbot
sudo tee /etc/nginx/sites-available/passkeydemo.noxno.ch >/dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name passkeydemo.noxno.ch;
    location ^~ /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 404; }
}
EOF
sudo ln -sf /etc/nginx/sites-available/passkeydemo.noxno.ch /etc/nginx/sites-enabled/passkeydemo.noxno.ch
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

**4b. Issue the certificate**

```bash
sudo certbot certonly --webroot -w /var/www/certbot \
     -d passkeydemo.noxno.ch \
     --agree-tos -m <OPS_EMAIL> --no-eff-email \
     --deploy-hook 'systemctl reload nginx'
```

Add `--dry-run` first if you want a rehearsal — Let's Encrypt rate-limits failed real attempts.
Certificates land in `/etc/letsencrypt/live/passkeydemo.noxno.ch/`. The `certbot.timer` installed by
the package renews them; `--deploy-hook` makes nginx pick up the new file.

```bash
systemctl list-timers certbot.timer      # must be active
sudo certbot renew --dry-run             # must succeed
```

**4c. Install the real config**

```bash
sudo cp deploy/nginx-passkey-demo.conf /etc/nginx/sites-available/passkeydemo.noxno.ch
sudo nginx -t && sudo systemctl reload nginx
```

`nginx -t` was verified clean against nginx 1.24 (Ubuntu 24.04) and 1.27. On 1.25+ you will see
`the "listen ... http2" directive is deprecated` — harmless, HTTP/2 is still enabled. If you
prefer the modern spelling on 1.25+, replace the two `listen … ssl http2;` lines with
`listen 443 ssl;` / `listen [::]:443 ssl;` and add `http2 on;` — but that syntax does **not**
exist on 1.24, which is what Ubuntu 24.04 ships.

---

## 5. Runtime A — Docker (recommended)

Ship this repository's directory to the server (clone it there, or rsync it as below). The build
context is this directory and nothing above it.

```bash
# from the developer machine
rsync -a --delete \
      --exclude build/ --exclude .gradle/ --exclude cache/ --exclude vectors/ --exclude .env \
      ./ root@passkeydemo.noxno.ch:/opt/passkey-src/

# on the server
cd /opt/passkey-src

# adminToken is mandatory: the container refuses to start on the shipped "change-me"
printf 'PASSKEY_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 32)" | sudo tee .env >/dev/null
sudo chmod 600 .env

sudo docker compose up -d --build
sudo docker compose ps                 # STATUS must reach "healthy"
sudo docker compose logs -f
```

The build context is this directory only. First build pulls `gradle:9.3.1-jdk21` and
`eclipse-temurin:21-jre-jammy` and takes a few minutes; later rebuilds reuse the dependency
layer.

**How configuration works in the container.** `Config.java` reads `java.util.Properties` from
one file and knows nothing about the environment, so the image's entrypoint renders
`/tmp/runtime.properties` = the baked `application.properties` **plus** one line per `PASSKEY_*`
variable that is set. Duplicate keys are legal in a properties file and the last one wins, so
the environment always beats the file. On start the container prints the effective
configuration with `adminToken` masked — read that block, it is the ground truth:

```
--- effective configuration (/tmp/runtime.properties) ---
port=8099
rpId=passkeydemo.noxno.ch
attestationPolicy=strict
allowSoftwareAttestationRoot=false
verifiedBootPolicy=enforce
adminToken=********
cacheDir=/app/data/cache
...
--- end configuration ---
```

Every variable is listed and commented in `docker-compose.yml`. Anything the entrypoint does
not know yet can be appended raw via `PASSKEY_EXTRA_PROPERTIES`.

**The complete `PASSKEY_*` map.** Every key in `application.properties` ships with an EXAMPLE
value; these are the variables that replace them at runtime. The `override <key> <ENV_VAR>` block
in the Dockerfile entrypoint is the authoritative list — this table mirrors it.

| Environment variable | Property key | What a real deployment must supply |
|---|---|---|
| `PASSKEY_PORT` | `port` | usually left at 8099 (the image's HEALTHCHECK follows it) |
| `PASSKEY_BASE_PATH` | `basePath` | the context path the API is mounted under; must match the nginx `location ^~ …/rest/authentication` prefix |
| `PASSKEY_RP_ID` | `rpId` | **required** — the host serving the demo page and the association files |
| `PASSKEY_RP_NAME` | `rpName` | the name shown in the platform passkey prompt |
| `PASSKEY_ACCEPTED_ORIGINS` | `acceptedOrigins` | **required** — `https://<rpId>` plus each `android:apk-key-hash:<…>` |
| `PASSKEY_ATTESTATION_POLICY` | `attestationPolicy` | `strict` in production, `demo` only while demoing in a browser |
| `PASSKEY_STATIC_DIR` | `staticDir` | pinned to `/app/public` in the image |
| `PASSKEY_ANDROID_PACKAGE_NAME` | `androidPackageName` | **required for Android** — `<PACKAGE_NAME>` |
| `PASSKEY_ANDROID_SIGNING_DIGESTS` | `androidSigningDigests` | **required for Android** — SHA-256 of every accepted signing certificate |
| `PASSKEY_IOS_APP_IDS` | `iosAppIds` | **required for iOS** — `<TEAM_ID>.<BUNDLE_ID>`, comma separated |
| `PASSKEY_APPLE_TEAM_ID` | `appleTeamId` | **required for iOS** — `<TEAM_ID>` |
| `PASSKEY_APP_ATTEST_ENVIRONMENTS` | `appAttestEnvironments` | drop `appattestdevelop` once on TestFlight/App Store |
| `PASSKEY_SERVE_WELL_KNOWN` | `serveWellKnown` | `true` unless the platform-passkey path is deliberately off |
| `PASSKEY_ANDROID_WEB_CREDENTIAL_DIGESTS` | `androidWebCredentialDigests` | **public grant** — `<PLAY_APP_SIGNING_SHA256>` (and the upload key), never a debug key |
| `PASSKEY_ALLOW_SOFTWARE_ATTESTATION_ROOT` | `allowSoftwareAttestationRoot` | `false` in production |
| `PASSKEY_VERIFIED_BOOT_POLICY` | `verifiedBootPolicy` | `enforce` in production |
| `PASSKEY_UNLOCK_WINDOW_SECONDS` | `unlockWindowSeconds` | policy decision |
| `PASSKEY_CEREMONY_TTL_SECONDS` | `ceremonyTtlSeconds` | policy decision |
| `PASSKEY_RATE_LIMIT_PER_MINUTE` | `rateLimitPerMinute` | raise behind a proxy — see the box in §6 |
| `PASSKEY_ADMIN_TOKEN` | `adminToken` | **required** — the container refuses to start on `change-me` |
| `PASSKEY_GOOGLE_ROOTS_URL` | `googleRootsUrl` | leave at the Google URL |
| `PASSKEY_GOOGLE_STATUS_URL` | `googleStatusUrl` | leave at the Google URL |
| `PASSKEY_CACHE_DIR` | `cacheDir` | pinned to `/app/data/cache` in the image |
| `PASSKEY_VECTORS_DIR` | `vectorsDir` | pinned to `/app/data/vectors` in the image |
| `PASSKEY_USERS_FILE` | `usersFile` | pinned to `/app/users.json` in the image |
| `PASSKEY_APPLE_ROOT_PEM_PATH` | `appleAppAttestRootPemPath` | unset = the Apple root compiled into `Config.java` |
| `PASSKEY_EXTRA_PROPERTIES` | *(raw lines)* | escape hatch for a key the entrypoint does not map yet |
| `PASSKEY_BASE_PROPERTIES` / `PASSKEY_RUNTIME_PROPERTIES` | *(entrypoint paths)* | where the base file is read from and the merged file written |
| `PASSKEY_ALLOW_INSECURE_DEFAULTS` | *(entrypoint only)* | `1` downgrades the `change-me` refusal to a warning — throwaway local containers only |

The container runs as uid 10001 with a read-only root filesystem, all capabilities dropped and
`no-new-privileges`. Its only writable paths are the `passkey-demo-data` volume mounted at
`/app/data` and a 64 MB tmpfs at `/tmp`.

## 5'. Runtime B — systemd (no Docker)

```bash
# build once, on the server or on a build host with JDK 21
./gradlew installDist                       # -> build/install/passkey-reference-server/lib/

sudo useradd --system --home-dir /opt/passkey-demo --shell /usr/sbin/nologin passkey
sudo mkdir -p /opt/passkey-demo /etc/passkey-demo
sudo cp -r build/install/passkey-reference-server/lib /opt/passkey-demo/lib
sudo cp application.properties users.json DEPLOY.md /opt/passkey-demo/
sudo mkdir -p /opt/passkey-demo/public          # the /demo page (attestationPolicy=demo only)
sudo cp public/index.html /opt/passkey-demo/public/   # omit to fall back to the bundled placeholder

sudo chown -R root:passkey /opt/passkey-demo
sudo chmod 750 /opt/passkey-demo
sudo chmod 640 /opt/passkey-demo/application.properties /opt/passkey-demo/users.json

sudo cp deploy/passkey-demo.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Then edit `/opt/passkey-demo/application.properties` (section 6) and point the writable paths
at the state directory the unit creates:

```properties
cacheDir=/var/lib/passkey-demo/cache
vectorsDir=/var/lib/passkey-demo/vectors
usersFile=/opt/passkey-demo/users.json
staticDir=/opt/passkey-demo/public
```

```bash
java -version                        # must print 21.x - the unit uses /usr/bin/java
sudo systemctl enable --now passkey-demo
sudo systemctl status passkey-demo
```

Two things to know about this route:

* **There is no `java -jar`.** `build.gradle.kts` applies the `application` plugin, which
  produces a thin jar with an empty manifest — no `Main-Class`, no `Class-Path`. The runnable
  artefact is the whole `lib/` directory, hence
  `-cp /opt/passkey-demo/lib/* ch.noxno.passkeydemo.Main`. The trailing `*` is the
  JVM's own classpath wildcard; systemd passes it through literally because it never globs.
* **No environment overrides.** Unlike the container, the systemd route has no entrypoint to
  render them. Every setting lives in `/opt/passkey-demo/application.properties`, which
  therefore holds the `adminToken` — keep it `chmod 640 root:passkey`.
  `/etc/passkey-demo/passkey-demo.env` is only for `JAVA_OPTS`, `TZ` and `LANG`.

The unit was checked with `systemd-analyze verify` (clean) and its exact `ExecStart` argv was
run on Ubuntu 24.04 with `openjdk-21-jre-headless` (server up, health 200).

---

## 6. Configuration: what MUST change before exposure

`application.properties` lives at the repository root —
`./application.properties` in the repo, `/app/application.properties` in the image, `/opt/passkey-demo/application.properties`
under systemd. It is read from the path given as the first argument to `Main`, or from the
working directory when no argument is given.

The shipped file is tuned for a **developer laptop with an emulator**. Four of its defaults are
actively dangerous on a public host.

| Key | Shipped | Set it to | Why |
|---|---|---|---|
| `adminToken` | `change-me` | `openssl rand -hex 32`, or empty | `POST passkey/admin/reset` clears `passkeyRequired` and revokes every credential of any account. With the default, anyone who can reach the host owns every account. Empty disables the endpoint (it then always answers 401). **The container refuses to start on `change-me`.** |
| `allowSoftwareAttestationRoot` | `true` | `false` | `true` accepts the AOSP *software* attestation root, i.e. an emulator with no hardware key at all — and skips validity checking for it, because that root expired in January 2026. Leaving it on makes the whole attestation story unfalsifiable. |
| `verifiedBootPolicy` | `log` | `enforce` | `log` only writes a line when the device reports an unlocked bootloader or a non-`Verified` boot state. `enforce` rejects it. Trust level *substantiell* wants the rejection. |
| `androidSigningDigests` | *(empty)* | the real digests | **Empty means "accept any signing certificate and just log it"** (`androidSigningDigests is empty - accepting signing certificate … unchecked`). Until this is filled in, a re-signed clone of the APK passes attestation. |
| `attestationPolicy` | `strict` | `strict`; `demo` only while demoing in a browser | `demo` additionally accepts `fmt=none`, opens the unauthenticated `/demo/api` namespace and serves `/demo`. Credentials enrolled that way are stored `attested=false`. |
| `iosAppIds` | `ABCDE12345.com.example.passkeydemo` (EXAMPLE) | set `PASSKEY_IOS_APP_IDS` to the real `<TEAM_ID>.<BUNDLE_ID>` list | An App Attest object is bound to `TEAMID.bundleId`; a wrong entry rejects every iOS enrolment. |
| `appAttestEnvironments` | `appattest,appattestdevelop` | drop `appattestdevelop` once the demo runs on TestFlight/App Store | `appattestdevelop` is the Xcode-build environment and is not a production signal. |
| `rpId` | `passkeydemo.noxno.ch` | leave it for this host | Hashed into every credential — changing it invalidates all of them. |
| `basePath` | `/api` | the context path of the backend this server stands in for | Every app-facing route hangs under it (`<basePath>/rest/authentication/…`). It must match the `location ^~ /api/rest/authentication` prefix in `deploy/nginx-passkey-demo.conf` and the `PASSKEY_BASE_PATH` the image's HEALTHCHECK uses; change all three together. |
| `androidPackageName` | `com.example.passkeydemo` (EXAMPLE) | set `PASSKEY_ANDROID_PACKAGE_NAME` to the real `<PACKAGE_NAME>` | It is the `package_name` published in `assetlinks.json` and the package checked against `attestationApplicationId`. A wrong value silently kills Android platform passkeys. |
| `acceptedOrigins` | `https://passkeydemo.noxno.ch` | add the Android origin once the signing cert is known | A native Android authenticator writes `android:apk-key-hash:<base64url SHA-256 of the signing certificate>` into `clientDataJSON.origin`, not an https URL. Without that entry, Android enrolment fails on the origin check. |
| `rateLimitPerMinute` | `60` | `600` | See the box below. |
| `serveWellKnown` | `true` | `true` | Serves `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`, in strict **and** demo mode. `false` makes both answer 404 and silently kills the platform-passkey path (§0). |
| `androidWebCredentialDigests` | **empty** (so it falls back to `androidSigningDigests`, also empty) | upload key + Play App Signing **only** | This is the list published in `assetlinks.json`: a public grant, not a server-side check. Empty is the safe default — the server WARNs at boot and publishes `"sha256_cert_fingerprints":[]`, which breaks Android platform passkeys visibly rather than granting them to a debug certificate silently. Never put a debug key here. On Docker use `PASSKEY_ANDROID_WEB_CREDENTIAL_DIGESTS`. |
| `appleTeamId` | `ABCDE12345` (EXAMPLE) | set `PASSKEY_APPLE_TEAM_ID` to the real `<TEAM_ID>` | Only used to qualify `iosAppIds` entries that carry no team id before they go into the AASA. |

Getting the Android signing digest (colons and upper case are fine — the server lowercases and
strips them):

```bash
keytool -list -v -keystore release.jks -alias <alias> | grep 'SHA256:'
# or, straight from the built artefact:
apksigner verify --print-certs app-release.apk | grep -i 'SHA-256 digest'
```

> **Rate limiting behind a proxy — verified caveat.** The server's own limiter keys on
> `ctx.ip()`, the TCP peer address. It does **not** read `X-Forwarded-For`. Measured against
> this build with `rateLimitPerMinute=5`: 12 requests carrying 12 different `X-Forwarded-For`
> values produced 5 × `PASSWORD_INVALID` and then 7 × `RATE_LIMITED`. Behind nginx every
> client is `127.0.0.1`, so `rateLimitPerMinute` becomes one **global** budget — at the
> shipped 60/min a single busy demo would lock everyone out. Raise it (600 is a sane demo
> value) and let nginx do the per-IP work: `deploy/nginx-passkey-demo.conf` defines
> `limit_req_zone … rate=2r/s` with `burst=20 nodelay` on the authentication prefix, which was
> measured returning 21 × 200 then 9 × 429 for 30 rapid requests from one address.

---

## 7. Verify it is alive

`GET …/retrieveChallenge` is the health probe: it is the only unauthenticated `GET` that
answers `200`, and it is the one endpoint that does **not** consume a rate-limit token, so
probing it every 30 s can never eat a client's budget. The Docker `HEALTHCHECK` uses exactly
this URL.

```bash
# 1. loopback, straight at the app
curl -fsS http://127.0.0.1:8099/api/rest/authentication/retrieveChallenge | head -c 120

# 2. through nginx and TLS, from anywhere
curl -fsS https://passkeydemo.noxno.ch/api/rest/authentication/retrieveChallenge

# 3. redirect and headers
curl -sI  http://passkeydemo.noxno.ch/          | grep -i '^location'
curl -sI  https://passkeydemo.noxno.ch/         | grep -i 'strict-transport-security'

# 4. certificate
echo | openssl s_client -servername passkeydemo.noxno.ch -connect passkeydemo.noxno.ch:443 2>/dev/null \
  | openssl x509 -noout -subject -dates -issuer
```

Expected: a JSON body `{"identifier":…,"nonce":…,"validTill":…}`, a `301` to
`https://passkeydemo.noxno.ch/`, and `strict-transport-security: max-age=63072000; includeSubDomains`.

With `attestationPolicy=demo` there is also `https://passkeydemo.noxno.ch/demo/` (the page) and
`https://passkeydemo.noxno.ch/demo/api/status` (a JSON summary of the running policy).

Container health:

```bash
sudo docker compose ps                                            # healthy / unhealthy
sudo docker inspect --format '{{.State.Health.Status}}' passkey-demo
```

---

## 7a. Verify the two `.well-known` files

Both files fail **silently** when they are wrong: the phone simply never offers a passkey, with no
error on the device and nothing in this server's log, because the check happens between the phone and
Apple's or Google's infrastructure. So verify them from outside, deliberately, in this order.

**1. Served, correct content type, no redirect.** This is the whole Apple contract in one command:

```bash
for u in https://passkeydemo.noxno.ch/.well-known/apple-app-site-association \
         https://passkeydemo.noxno.ch/.well-known/assetlinks.json; do
  curl -sS -o /dev/null -w "%{http_code}  redirects=%{num_redirects}  type=%{content_type}  $u\n" "$u"
done
```

Required output, for both lines:

```
200  redirects=0  type=application/json
```

Any other three values is a finding:

* **`redirects` is not `0`** — Apple does **not** follow redirects for the AASA and treats a `301`,
  `302`, `307` or `308` as "this domain is not associated". Note `curl` only reports a redirect it
  followed, and it follows none without `-L`; the command above therefore reports `0` even when the
  server *did* answer a redirect. That is why the `%{http_code}` must also read exactly `200` — read
  both numbers, not one.
* **`type` is not `application/json`** — most often `application/octet-stream`, which is what nginx
  answers when the file is served **from disk**: `apple-app-site-association` has no file extension,
  so `mime.types` cannot guess it. Proxied to this server the header is correct
  (`WellKnownController` sets it explicitly); see the note in `deploy/nginx-passkey-demo.conf`.
* **`404`** — either `serveWellKnown=false` (check the boot log) or nginx is not routing
  `/.well-known/` to the backend.

Full headers when you need to see why:

```bash
curl -sS -D- -o /dev/null https://passkeydemo.noxno.ch/.well-known/apple-app-site-association
```

There must be **no `location:` header at all**. A `301` on `http://…/.well-known/…` is fine and
expected — the `:80` server redirects everything except the ACME token to HTTPS, and neither Apple
nor Google ever requests the plain-HTTP URL. What must not exist is a redirect on the **https** URL.

**2. The content is what you meant to publish.**

```bash
curl -sS https://passkeydemo.noxno.ch/.well-known/apple-app-site-association | python3 -m json.tool
curl -sS https://passkeydemo.noxno.ch/.well-known/assetlinks.json            | python3 -m json.tool
```

Expected (this is the exact body observed from this build on 2026-09-06, pretty-printed):

```json
{
    "webcredentials": {
        "apps": [
            "<TEAM_ID>.<BUNDLE_ID>",
            "<TEAM_ID>.<BUNDLE_ID>.dev"
        ]
    }
}
```

```json
[
    {
        "relation": ["delegate_permission/common.get_login_creds"],
        "target": {
            "namespace": "android_app",
            "package_name": "<PACKAGE_NAME>",
            "sha256_cert_fingerprints": ["<PLAY_APP_SIGNING_SHA256, colon separated>"]
        }
    }
]
```

An **empty** `apps` or `sha256_cert_fingerprints` array is valid JSON and is the failure that costs
the most time — the server warns about both at boot, so read the startup log:

```bash
sudo docker compose logs passkey | grep -i 'well-known\|webcredentials\|sha256_cert'
```

**3. What Apple's CDN actually holds.** A non-developer device never reads your host; it reads
Apple's CDN copy.

```bash
curl -sS https://app-site-association.cdn-apple.com/a/v1/passkeydemo.noxno.ch | python3 -m json.tool
```

* A `404` there means Apple has not fetched your domain yet. It is populated on demand; give it time
  after the first install attempt.
* The CDN holds a copy on the order of a day, so **a file you just fixed can stay stale on device**
  long after your own `curl` returns the new one. During development switch the iPhone to
  *Settings → Developer → Associated Domains Development*, which makes it bypass the CDN and fetch
  from the host. On a Mac, `swcutil dl -d passkeydemo.noxno.ch` shows what the system resolved.
* Reinstalling the app re-triggers the fetch; changing the file alone does not.

**4. Google's Digital Asset Links checker.** This one is genuinely valuable because Google fetches
your host **from Google's side**, so it also proves the file is reachable from the public internet —
which the curls above do not, if you ran them on the server itself.

```bash
curl -sS 'https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https://passkeydemo.noxno.ch&relation=delegate_permission/common.get_login_creds' \
  | python3 -m json.tool
```

Success is a `statements` array carrying your `package_name` and fingerprint, plus a `maxAge`. A
failure comes back as `debugString` / `errorCode` naming what Google saw
(`ERROR_FETCHING_STATEMENT_FILE`, a wrong content type, a redirect). If the endpoint asks for an API
key, use the web form instead: <https://developers.google.com/digital-asset-links/tools/generator>.

> These four checks can only be run once the host actually resolves (§2).
> Steps 1 and 2 *were* run against the server directly on 2026-09-06 and produced
> `200 redirects=0 type=application/json` and the two bodies shown above. Steps 3 and 4 need the live
> host and remain unverified.

---

## 8. Logs

Both routes log to stdout with ISO-8601 timestamps (`slf4j-simple` is configured through
`JAVA_OPTS`; its own default is bare stderr with no timestamps at all).

```bash
# Docker
sudo docker compose logs -f --tail=200
sudo docker compose logs --since 30m passkey

# systemd
sudo journalctl -u passkey-demo -f
sudo journalctl -u passkey-demo --since '30 min ago' -o short-iso

# nginx
sudo tail -f /var/log/nginx/passkeydemo.noxno.ch.access.log   # includes rt= and urt= timings
sudo tail -f /var/log/nginx/passkeydemo.noxno.ch.error.log
```

Lines worth grepping during a demo:

| Grep | Meaning |
|---|---|
| `android-key accepted: securityLevel=…` | a real hardware-attested Android enrolment |
| `androidSigningDigests is empty` | the signing certificate was **not** checked — fix the config |
| `DEMO MODE: enrolling an UNATTESTED credential` | a browser passkey, `fmt=none`, `attested=false` |
| `attestationPolicy=demo` banner | the server is not in the compliance configuration |
| `audit recovery_reset user=… actor=hotline:x-admin-token` | somebody used the admin reset |
| `403 RATE_LIMITED` | the app-level (global, see §6) limiter fired |
| `429` in the nginx access log | the per-IP `limit_req` fired |

Docker log rotation is configured in `docker-compose.yml` (`json-file`, 10 MB × 5). Journald
rotation follows `/etc/systemd/journald.conf`.

---

## 9. Backups

**There is no credential database to back up, and pretending otherwise would be wrong.**
`CredentialStore` is an in-memory map with no persistence: every restart forgets every enrolled
passkey, and every user then falls back to password-only login until they enrol again. Plan
demos around that — do not restart between enrolment and login.

What *is* worth preserving:

| Path (Docker) | Path (systemd) | What it is | Losing it costs |
|---|---|---|---|
| `/app/data/vectors` | `/var/lib/passkey-demo/vectors` | one JSON per successful register/login/unlock, with the raw request and the challenges | real device traffic that the vector-gated tests replay — **the valuable artefact** |
| `/app/data/cache` | `/var/lib/passkey-demo/cache` | Google attestation roots + revocation list | nothing, if the box has egress; it is re-fetched |
| `/app/application.properties` | `/opt/passkey-demo/application.properties` | config, **contains `adminToken` on the systemd route** | the deployment configuration |
| `/app/users.json` | `/opt/passkey-demo/users.json` | seed accounts, **clear-text passwords** | the demo accounts |

```bash
# Docker: snapshot the named volume
sudo docker run --rm -v passkey-demo-data:/data:ro -v /var/backups:/out alpine \
     tar czf /out/passkey-data-$(date +%F-%H%M).tar.gz -C /data .

# Docker: restore into a fresh volume
sudo docker compose down
sudo docker run --rm -v passkey-demo-data:/data -v /var/backups:/in alpine \
     sh -c 'rm -rf /data/* && tar xzf /in/passkey-data-YYYY-MM-DD-HHMM.tar.gz -C /data'
sudo docker compose up -d

# systemd
sudo tar czf /var/backups/passkey-state-$(date +%F-%H%M).tar.gz \
     /var/lib/passkey-demo /opt/passkey-demo/application.properties /opt/passkey-demo/users.json
```

Treat those tarballs as secrets: they contain `adminToken` and clear-text demo passwords.
`chmod 600`, and do not push them anywhere the demo audience can read.

To pull recorded vectors back to a developer machine for the test suite:

```bash
sudo docker cp passkey-demo:/app/data/vectors ./vectors      # Docker
rsync -a root@passkeydemo.noxno.ch:/var/lib/passkey-demo/vectors/ ./vectors/   # systemd
```

---

## 10. Updating

```bash
# Docker: re-ship the sources, then rebuild
# --exclude .env is load-bearing: --delete would otherwise remove the admin token and
# the next `docker compose up` would refuse to start.
rsync -a --delete \
      --exclude build/ --exclude .gradle/ --exclude cache/ --exclude vectors/ --exclude .env \
      ./ root@passkeydemo.noxno.ch:/opt/passkey-src/
ssh root@passkeydemo.noxno.ch 'cd /opt/passkey-src && docker compose up -d --build && docker compose ps'

# systemd (from the source directory on the build host or the server)
cd /opt/passkey-src
./gradlew installDist
sudo systemctl stop passkey-demo
sudo rm -rf /opt/passkey-demo/lib
sudo cp -r build/install/passkey-reference-server/lib /opt/passkey-demo/lib
sudo chown -R root:passkey /opt/passkey-demo/lib
sudo systemctl start passkey-demo
```

Both restart the JVM, which wipes every enrolled credential (§9). Announce it.

If `gradle/wrapper/gradle-wrapper.properties` is bumped to a new Gradle version, bump the
`FROM gradle:<version>-jdk21` tag in the `Dockerfile` to match — they are pinned together on
purpose so the container build and a local `./gradlew installDist` produce the same thing.

---

## 11. Running the demo

**Compliance configuration (default).** `attestationPolicy=strict`,
`allowSoftwareAttestationRoot=false`, `verifiedBootPolicy=enforce`, signing digests filled in.
Only the native app can enrol. A browser hitting the passkey endpoints is rejected with
`ATTESTATION_REJECTED` — which is itself a good thing to show.

**Browser walkthrough.** Restart with `PASSKEY_ATTESTATION_POLICY=demo` (Docker:
`PASSKEY_ATTESTATION_POLICY=demo docker compose up -d`; systemd: edit the properties file and
`systemctl restart`). `https://passkeydemo.noxno.ch/demo/` then runs a full ceremony from the browser.
Both the startup banner and every enrolment log line will say the credential is unattested —
leave those on screen rather than hiding them, they are the honest half of the story.

Switch back to `strict` afterwards. Do not leave `demo` running: `/demo/api` needs neither a
bearer token nor a password.

**Native app.** Point the app at `https://passkeydemo.noxno.ch/api/` (trailing slash
required; the value includes the context path). Then enrol on a real device and show
`android-key accepted: securityLevel=STRONGBOX …` or the iOS App Attest path in the log.
The Apple and Android side of that setup — App Attest capability, team id, signing digests,
`acceptedOrigins` — is the walkthrough that follows this deployment.

---

## 12. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `FATAL: adminToken is still the shipped default "change-me"`, container exits with code 78 | Intended. Put `PASSKEY_ADMIN_TOKEN=…` in `.env`. For a throwaway local container only: `PASSKEY_ALLOW_INSECURE_DEFAULTS=1`. |
| `docker compose` refuses: `required variable PASSKEY_ADMIN_TOKEN is missing a value` | Same thing, one layer earlier. Create `.env`. |
| `nginx -t` fails with `cannot load certificate … no such file` | The certificate is not issued yet. Go back to §4a. |
| `nginx -t` fails with `unknown directive "http2"` | nginx ≤ 1.24. Keep the shipped `listen … ssl http2;` form. |
| `502 Bad Gateway` | The app is not listening on `127.0.0.1:8099`. `ss -ltnp \| grep 8099`, then the app logs. |
| `504 Gateway Time-out` | Upstream alive but slow — usually the first `android-key` verification while `android.googleapis.com` is unreachable. Check egress. |
| `429` from nginx | The per-IP `limit_req` fired. Expected under a load test; raise `rate=`/`burst=` in the nginx config if a genuine demo trips it. |
| `403 {"errors":["RATE_LIMITED"]}` from the app | The **global** app-level bucket (§6). Raise `rateLimitPerMinute`. |
| `403 ATTESTATION_REJECTED` from a browser | Correct behaviour in `strict` mode. A browser cannot produce attestation. |
| `403` on Android with `origin … ist nicht erlaubt` | Add the `android:apk-key-hash:…` value to `acceptedOrigins`. |
| iOS enrolment rejected | `iosAppIds` must be exactly `TEAMID.bundleId`, and `appAttestEnvironments` must include the environment the build actually uses (`appattestdevelop` for Xcode builds). |
| `Google attestation data: 0 root(s)` in the log | No egress to `android.googleapis.com` and no warm cache. Fix the firewall, then restart. |
| JVM dies at startup with SIGSYS (systemd) | The seccomp filter. Comment out the `SystemCallFilter` / `SystemCallErrorNumber` lines in the unit and report it. |
| Unit stays `failed` after repeated restarts | The start limit tripped. Fix the config, then `sudo systemctl reset-failed passkey-demo`. |
| `Permission denied` writing `cache/` or `vectors/` with a **bind** mount | A bind mount does not inherit the image's ownership. `sudo chown -R 10001:10001 <hostdir>`. Named volumes get it right automatically. |
| `404` on `/.well-known/apple-app-site-association` | Either `serveWellKnown=false` (the boot log says so explicitly) or nginx is not routing `/.well-known/` to the backend. §7a. |
| `content_type` is `application/octet-stream` on the AASA | The file is being served **from disk** by nginx, not proxied: it has no extension, so `mime.types` cannot guess it. Proxy it, or add `default_type application/json;` to that location. Apple rejects the wrong type. |
| A `301`/`302` on `https://…/.well-known/apple-app-site-association` | Apple does not follow redirects for this file and reads it as "not associated". Find the `rewrite`/`return` that produced it. A redirect on the **http** URL is fine. |
| iOS offers no passkey, everything above is green | Apple's CDN still holds the old copy (up to ~a day), or the app has no `webcredentials:passkeydemo.noxno.ch` entitlement — and that entitlement is lost on every `cap add ios`. `PLATFORM-SETUP.md` §1.5. |
| Android offers no passkey, everything above is green | `sha256_cert_fingerprints` does not contain the certificate the **installed** build is signed with — for a Play install that is Google's re-signing certificate, not the upload key. `PLATFORM-SETUP.md` §2.10. |
| Everyone's passkeys stopped working after a restart | Expected. Credentials are in RAM (§9). |

---

## 13. SECURITY

**This is a reference and demonstration server. It is not, and must not be treated as, a
production authentication service.**

* **State is in memory.** `CredentialStore` is a `ConcurrentHashMap`; bearer tokens are random
  strings in another map. A restart, a crash or an OOM kill discards every enrolled passkey and
  every session.
* **There is no real password handling.** Passwords are compared **in clear text** against
  `users.json`. No hashing, no salt, no lockout, no throttling beyond the rate limiter. The
  shipped file contains working demo accounts; anyone who reads it can log in.
* **The legacy device challenge is not verified.** `challengeId` / `challengeResponse` are
  accepted and logged, never checked, and `GET retrieveChallenge` returns a fresh nonce that
  nothing validates.
* **`passkey/admin/reset` is account takeover behind one static header.** With
  `X-Admin-Token`, it clears `passkeyRequired` and revokes every credential of any named
  account. Use a 32-byte random token, or set `adminToken=` empty to disable the endpoint.
* **`attestationPolicy=demo` is not a compliant configuration.** It accepts `fmt=none`,
  tolerates syncable (non-device-bound) passkeys, and exposes `/demo/api` with no
  authentication at all. Use it for a demo, in front of people, and switch back.
* **`allowSoftwareAttestationRoot=true` makes the attestation claim meaningless** — it accepts
  the AOSP software root, i.e. an emulator, and does not check that root's validity because it
  expired in January 2026.
* **No confirmation e-mails, no persisted audit table, no App Attest receipt exchange with
  Apple.** A production backend implementation owes all three; this server logs
  audit lines to stdout and nothing else.
* **CORS is `Access-Control-Allow-Origin: *`.** Any web origin can call the API. nginx
  deliberately does not add CORS headers of its own — duplicates would break browsers — so
  this cannot be tightened at the proxy without changing the application.

**Therefore:**

1. **Never put real sensitive personal data, real accounts or real credentials on this host.** It is not a
   production system and carries none of the TR-03161 controls that one owes.
2. Keep it on a **separate VPS** from anything that does. No shared database, no shared
   secrets, no VPN route into a production network.
3. Treat `application.properties`, `users.json`, `.env` and every backup tarball as secrets:
   `chmod 600`, never in a public repository, never in a screen share.
4. **Take the host down when the demo is over.** `docker compose down` /
   `systemctl disable --now passkey-demo`, and remove the DNS record. A forgotten demo relying
   party with a clear-text user file and an admin reset endpoint is exactly the finding you do
   not want in the audit.
