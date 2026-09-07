# Passkey reference server — endpoint contract

A runnable WebAuthn relying party with in-memory stores. It exists so a mobile app, its WebAuthn
plugin and real devices can be verified end to end before a production backend implements the same
contract. It is a test tool: nothing is persisted, restarting it forgets every credential.


## Two config profiles, and why rpId cannot be shared

| Profile | File | rpId | Use |
|---|---|---|---|
| Public browser demo | `application.properties` | the demo host, e.g. `passkeydemo.noxno.ch` | the deployed host and its `/demo/` page |
| App-facing dev | a second properties file, e.g. `application-app-dev.properties` | the app's own product domain, e.g. `test.example.org` | pointing the native app at this server |

They cannot share one value. A **browser** requires `rpId` to be a registrable suffix of the page
origin, so a demo page served from the demo host can only use that domain. The **app** is its own
authenticator and has no such constraint, so it uses the real product domain.

`rpId` must equal the `rpId` the app is configured with. A mismatch fails in the app's own passkey
service before the plugin is called at all.

**Changing `rpId` later invalidates every enrolled passkey, with no migration path.** It is baked
into three places at enrolment: the Keystore alias (`keyTag(rpId, userHandle)`), the `rpIdHash`
(`sha256(rpId)`) inside every `authenticatorData`, and the `origin` (`https://<rpId>`) in
clientDataJSON. The private key is non-exportable from the TEE, so it cannot be re-signed under a
new `rpId` — every user must re-enrol. Pick the production value once, and pick the real domain.


## Run

```bash
./gradlew run
```

Serves `http://localhost:8099<basePath>/`, where `basePath` defaults to `/api` — so
`http://localhost:8099/api/`. Point the app's passkey base URL at exactly that (the trailing slash
is required; the value includes the context path). Set `basePath` (env `PASSKEY_BASE_PATH`) to the
context path of the backend this server stands in for and the URL follows. Accounts come from
`users.json`. Every tunable lives in `application.properties` at the project root; it is loaded from
the working directory,
so start the server from that directory or pass another file as the first argument
(`./gradlew run --args=/path/to/other.properties`).

The default port is 8099 because 8080 is occupied on the development machine by another project. If
8099 is taken as well, set another `port=` in `application.properties` and use it everywhere below.

## Test

```bash
./gradlew test                                  # 56 pass, 6 skip
./gradlew test -Dpasskey.network.tests=true     # also fetches the live Google roots
```

The skipped tests are `GoogleRootsTest` (network) and the vector-gated ones (three in
`AndroidKeyVectorTest`, one in `WebAuthnVerifierTest`, one in `AppAttestVectorTest`), which run only
once real device traffic has been recorded (see below).

## What it verifies

Registration: strict webauthn4j — `AndroidKeyAttestationStatementVerifier`,
`PackedAttestationStatementVerifier`, a `DefaultCertPathTrustworthinessVerifier` over the Google
roots and `DefaultSelfAttestationTrustworthinessVerifier` — then `type`, challenge, origin
`https://<rpId>`, `rpIdHash`, UP and UV set, ES256, `signCount == 0`, `BE == 0 && BS == 0`,
credential not already registered, the AAGUID matching the format (`android-key` ↔
`2b9c7d6e-5f4a-4c3b-8a2d-1e0f9c8b7a6d`, `packed` ↔ `7a0e4c5e-1d3b-4b8f-9a6c-3f2e1d0c9b8a`) and the
attestation statement itself.

* `fmt=android-key` — signature over `authData‖clientDataHash` with the leaf key, leaf key equals
  `credentialPublicKey` (webauthn4j), PKIX chain up to one of the **two** Google roots fetched from
  `https://android.googleapis.com/attestation/root` and cached in `cache/`, no serial on
  `https://android.googleapis.com/attestation/status`, validity enforced at verification time except
  for legacy factory chains under the RSA root `f92009e853b6b045` without a provisioning-info
  extension, which are validated at the moment they were issued. The extension
  `1.3.6.1.4.1.11129.2.1.17` is taken from the certificate nearest the root and must be the leaf;
  `attestationChallenge == clientDataHash`; security levels TEE or StrongBox; hardware-enforced
  `origin == GENERATED`, `purpose ∋ SIGN`, `algorithm == EC`, `ecCurve == P-256`, `noAuthRequired`
  absent, `userAuthType` includes biometrics; `attestationApplicationId` package and signing digest;
  `rootOfTrust` per `verifiedBootPolicy` (`log` by default).
* `fmt=packed` — iOS self attestation, then a **mandatory** App Attest verification with
  webauthn4j-appattest against the embedded Apple App Attestation Root CA, bound to the credential by
  `clientDataHash = SHA256(SHA256(webauthnAttestationObject) ‖ appAttestChallenge)`. The aaguid picks
  the environment (`appattest` / `appattestdevelop`), `rpIdHash` picks the App ID
  (`DCServerProperty("TEAMID.bundleId", challenge)`; the 3-arg form is equivalent).
* Every other format, `none` included, and any AAGUID other than the app's own constant for the
  format is rejected with `ATTESTATION_REJECTED`.

Assertions: challenge, origin, `rpIdHash`, UP and UV, signature over
`authenticatorData‖SHA256(clientDataJSON)`, `userHandle` matches the account, sign count strictly
greater (or both zero), and on iOS an App Attest assertion whose `clientDataHash` is
`SHA256(SHA256(authenticatorData) ‖ SHA256(clientDataJSON) ‖ appAttestChallenge)` with a strictly
increasing counter. `unlock/verify` additionally requires `now − fullLoginAt ≤ unlockWindowSeconds`
and answers `FULL_LOGIN_REQUIRED` otherwise.

Ceremonies are 32 random bytes with a `ceremonyTtlSeconds` TTL (5 minutes), single use; `register`
is consumed only on success so an Apple `serverUnavailable` retry with the same challenge works. All
endpoints are rate limited per IP (`rateLimitPerMinute`), assertions additionally per credentialId.

## Domain association (`.well-known`)

The server also serves the two files that bind the `rpId` host to the relying party's mobile apps,
in **strict and demo mode alike** — they describe app identity, not the demo:

| Path | Body |
|---|---|
| `/.well-known/apple-app-site-association` | `{"webcredentials":{"apps":[…]}}`, one `TEAMID.bundleid` per `iosAppIds` entry, qualified with `appleTeamId` |
| `/.well-known/assetlinks.json` | a one-element array granting `delegate_permission/common.get_login_creds` to `androidPackageName` for every `androidWebCredentialDigests` fingerprint |

Both are rendered once at boot (a malformed digest fails at startup, not per request), served as
`Content-Type: application/json`, and answer without a rate limiter or a token — Apple's CDN and
Google's asset-link fetcher are anonymous, and a `403` or `429` is indistinguishable from "domain not
associated". `serveWellKnown=false` turns both off; they then answer `404`.

**What they buy, plainly:** they enable **platform** passkeys — credentials held by iCloud Keychain
or Google Password Manager, which sync across the user's devices and return attestation `none`, i.e.
BSI trust level *normal*. They are **not** needed by, and add nothing to, the attested device-bound
design (`android-key` / `packed` + Apple App Attest) that this server exists to verify, which needs
no domain association at all and reaches *substantiell*. Both paths can coexist on one host; pick
deliberately. `PLATFORM-SETUP.md` §0.1 has the comparison, §1.5 and §2.10 the platform-side setup,
`DEPLOY.md` §7a the verification curls.

One trap worth repeating from those documents: `androidWebCredentialDigests` is a **public grant**,
not a server-side check. It ships **empty on purpose**, so the server WARNs at boot and publishes an
empty fingerprint list: Android platform passkeys then fail visibly instead of being granted to a
debug certificate silently. Never put a debug key here — the debug keystore's password is the
documented string `android`, so anyone could sign an app that claims this domain's passkeys.
On a publicly reachable host **set** it to the upload key
and the Play App Signing certificate only.

## Hotline recovery

`POST rest/authentication/passkey/admin/reset` with the header `X-Admin-Token: <adminToken>` and the
body `{"username": "…"}` clears `passkeyRequired`, revokes every credential of the account and logs
`audit recovery_reset user=… actor=hotline:x-admin-token`. Without the header, or with a wrong token,
the answer is **401** `{"errors":["TOKEN_INVALID"]}`; an unknown account answers 403
`CREDENTIAL_UNKNOWN`. Afterwards the password alone logs in again and a new passkey can be enrolled.
Change `adminToken` from its default `change-me` before anyone else can reach the server.

## What it does NOT verify

* The legacy device challenge (`challengeId` / `challengeResponse`): accepted and logged, never
  checked. `GET rest/authentication/retrieveChallenge` returns a fresh nonce for the same reason.
* Passwords are compared against `users.json` in clear text; there is no lockout.
* `allowSoftwareAttestationRoot=true` (the shipped default) accepts the AOSP software attestation
  root so emulators can be used — signatures are checked, validity is not (that root expires in
  January 2026). Set it to `false` for anything resembling a real test.
* Bearer tokens are random strings kept in a map; a missing or unknown token — and a missing or
  wrong `X-Admin-Token` — answers **401** `{"errors":["TOKEN_INVALID"]}`. That code is outside the
  client error contract of the passkey endpoints and only exists here.
* Production-only work the reference server omits: confirmation e-mails on enrol and
  remove, a persisted `passkey_audit` table, the App Attest receipt exchange with Apple (the receipt
  itself is verified and stored in `appAttestReceipt` at enrolment) and real password/lockout
  handling.

## Negative tests

Synthetic, always run: wrong challenge, replayed counter, foreign rpId, `fmt=none`, AAGUID mismatch,
unlock window exceeded (`FULL_LOGIN_REQUIRED`), admin reset without or with a wrong token.
Vector-gated, skipped until `vectors/android-*.json` exist: a software-root chain with
`allowSoftwareAttestationRoot=false` (needs an emulator vector), a foreign package name and a foreign
signing digest.

## Test vectors

Every successful `register/verify`, `login/verify` and `unlock/verify` writes
`vectors/<platform>-<timestamp>.json`. The envelope carries `kind`, `platform`, `recordedAt`, `rpId`,
`challenge`, `appAttestChallenge` and the raw `request` body — the challenges are needed because the
request alone cannot be re-verified. `AndroidKeyVectorTest` and `AppAttestVectorTest` replay every
recorded registration; with no vectors present they are skipped.

To record vectors: run this server, point a real device at its base URL, enrol, log in,
unlock. Commit the files you want to keep as regression vectors.

## Configuration (application.properties)

The file lives at the project root and is loaded from the working directory. **Every value shipped
in it is an example**; a real deployment overrides it through the `PASSKEY_*` environment variable
named in the third column (the container entrypoint appends the overrides after the file, and the
last occurrence wins).

| Key | Shipped default (example) | Env override | Meaning |
|---|---|---|---|
| `port` | `8099` | `PASSKEY_PORT` | HTTP port |
| `basePath` | `/api` | `PASSKEY_BASE_PATH` | context path the API is mounted under: `<basePath>/rest/authentication/…`; `/` mounts at the root |
| `rpId` | `passkeydemo.noxno.ch` | `PASSKEY_RP_ID` | relying party id; hashed into every credential as `rpIdHash` — changing it invalidates them all |
| `acceptedOrigins` | `https://passkeydemo.noxno.ch` | `PASSKEY_ACCEPTED_ORIGINS` | complete list of accepted `clientDataJSON.origin` values; when unset the accepted set is exactly `[https://<rpId>]` |
| `attestationPolicy` | `strict` | `PASSKEY_ATTESTATION_POLICY` | `strict` = only `android-key` and `packed`+App Attest; `demo` additionally accepts `fmt=none` and stores it `attested=false` |
| `rpName` | `Noxno Passkey Demo` | `PASSKEY_RP_NAME` | shown in `publicKey.rp.name` |
| `androidPackageName` | `com.example.passkeydemo` | `PASSKEY_ANDROID_PACKAGE_NAME` | expected `attestationApplicationId` package — **substitute `<PACKAGE_NAME>`** |
| `androidSigningDigests` | *(empty)* | `PASSKEY_ANDROID_SIGNING_DIGESTS` | comma-separated lower-case hex SHA-256 of the signing certificates; empty means "log, do not enforce" |
| `iosAppIds` | `ABCDE12345.com.example.passkeydemo` | `PASSKEY_IOS_APP_IDS` | accepted App Attest App IDs — **substitute `<TEAM_ID>.<BUNDLE_ID>`** |
| `serveWellKnown` | `true` | `PASSKEY_SERVE_WELL_KNOWN` | serve `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`; `false` makes both answer 404 |
| `appleTeamId` | `ABCDE12345` | `PASSKEY_APPLE_TEAM_ID` | prefixed onto any `iosAppIds` entry that carries no team id, for the AASA only — **substitute `<TEAM_ID>`** |
| `androidWebCredentialDigests` | *(empty)* | `PASSKEY_ANDROID_WEB_CREDENTIAL_DIGESTS` | fingerprints published in `assetlinks.json` — a **public grant**; substitute `<PLAY_APP_SIGNING_SHA256>` and keep the debug key out of it on a public host |
| `appAttestEnvironments` | `appattest,appattestdevelop` | `PASSKEY_APP_ATTEST_ENVIRONMENTS` | accepted App Attest environments |
| `allowSoftwareAttestationRoot` | `true` | `PASSKEY_ALLOW_SOFTWARE_ATTESTATION_ROOT` | test only: accept the AOSP software attestation root |
| `verifiedBootPolicy` | `log` | `PASSKEY_VERIFIED_BOOT_POLICY` | `log` or `enforce` for `deviceLocked && verifiedBootState == Verified` |
| `unlockWindowSeconds` | `604800` | `PASSKEY_UNLOCK_WINDOW_SECONDS` | unlock window (7 days) |
| `ceremonyTtlSeconds` | `300` | `PASSKEY_CEREMONY_TTL_SECONDS` | ceremony TTL |
| `rateLimitPerMinute` | `60` | `PASSKEY_RATE_LIMIT_PER_MINUTE` | token bucket size per IP and per credentialId |
| `adminToken` | `change-me` | `PASSKEY_ADMIN_TOKEN` | `X-Admin-Token` of `passkey/admin/reset`; an empty value disables the endpoint |
| `googleRootsUrl` / `googleStatusUrl` | Google URLs | `PASSKEY_GOOGLE_ROOTS_URL` / `PASSKEY_GOOGLE_STATUS_URL` | roots and revocation list, cached in `cacheDir` |
| `cacheDir` / `vectorsDir` / `usersFile` | `cache` / `vectors` / `users.json` | `PASSKEY_CACHE_DIR` / `PASSKEY_VECTORS_DIR` / `PASSKEY_USERS_FILE` | paths |
| `staticDir` | `public` | `PASSKEY_STATIC_DIR` | directory served at `/demo` in demo mode |
| `appleAppAttestRootPemPath` | *(unset)* | `PASSKEY_APPLE_ROOT_PEM_PATH` | override the embedded Apple root PEM |
