# passkeydemo.noxno.ch

A working WebAuthn relying-party server for demonstrating **passkey login**, deployed at
<https://passkeydemo.noxno.ch>.

Java 21 · Gradle · Javalin · [webauthn4j](https://github.com/webauthn4j/webauthn4j) 0.31.10

## What this demonstrates

Registration and login with **synced platform passkeys** — the credentials held by iCloud
Keychain and Google Password Manager. Open <https://passkeydemo.noxno.ch/demo/> on any modern
browser or phone and run the full ceremony; every request and response is printed on the page so
the flow can be watched step by step.

## The one thing to be clear about

Synced platform passkeys return **attestation `none`**. The ceremony is real and the signature is
real, but nothing in the response proves *which* device or *which* app holds the key, and the
credential syncs across the user's devices via their platform account.

Under BSI TR-03161 that is trust level **"normal"**. Reaching **"substantiell"** requires a
device-bound, hardware-attested credential — `android-key` attestation on Android, Secure Enclave
plus App Attest on iOS — which a browser cannot produce and which the platform passkey APIs
deliberately do not expose.

This server can verify both. `attestationPolicy` selects which:

| Value | Accepts | Use |
|---|---|---|
| `demo` | `none`, plus `android-key` and `apple-appattest` | this demo, and anything browser-driven |
| `strict` | only `android-key` and `apple-appattest` | the device-bound path |

Every stored credential records `attested` and `attestationFmt`, and `/demo/api/list` shows them,
so a credential registered with `none` can never be mistaken for an attested one.

## Domain binding

Synced passkeys are bound to a domain, so `rpId` must equal the host serving the association
files, and both must be reachable over HTTPS with no redirect:

- `https://passkeydemo.noxno.ch/.well-known/apple-app-site-association`
- `https://passkeydemo.noxno.ch/.well-known/assetlinks.json`

Both are generated from `application.properties` (`iosAppIds`, `androidPackageName`,
`androidWebCredentialDigests`) so they cannot drift from the verification settings.

**`androidWebCredentialDigests` ships empty on purpose.** It is a public grant: any app signed by
a listed certificate may receive this domain's passkeys. Empty makes the server warn at boot and
publish an empty list, so Android passkeys fail *visibly* rather than being granted to a debug
key. Fill it with the Play App Signing SHA-256 (Play Console → Setup → App signing) before an
Android app is expected to work.

## Endpoints and the base path

The app-facing API is mounted under a configurable context path:

```
<basePath>/rest/authentication/passkey/{register,login,unlock}/{options,verify}
<basePath>/rest/authentication/passkey/{list,remove}
<basePath>/rest/authentication/passkey/admin/reset
```

`basePath` defaults to **`/api`**, so out of the box that is
`/api/rest/authentication/passkey/…`. Set `basePath` in `application.properties` (or
`PASSKEY_BASE_PATH` in the container) to the context path of the backend this server stands in
for, and it becomes a drop-in replacement for it. `basePath=/` mounts the API at the root.

The browser demo namespace `/demo/api/*`, the demo page at `/demo/` and the two files under
`/.well-known/` are **not** affected by `basePath` — the first two are demo surface, the last is
fixed by Apple and Google.

## Configuration

Every value in `application.properties` is an **example**. A real deployment overrides them with
`PASSKEY_*` environment variables — the container entrypoint appends them after the baked-in file
and the last occurrence wins. Each key names its own variable in the comment above it; the full
table is in [DEPLOY.md](DEPLOY.md).

The app-identity keys (`androidPackageName`, `iosAppIds`, `appleTeamId`,
`androidSigningDigests`, `androidWebCredentialDigests`) ship with neutral placeholders
(`com.example.passkeydemo`, `ABCDE12345`, empty digest lists). Substitute the real values via the
environment before pointing a real mobile app at the server.

## Run it

```bash
./gradlew installDist
build/install/passkey-reference-server/bin/passkey-reference-server application.properties
```

Then <http://localhost:8099/demo/>. Note that WebAuthn requires a secure context: `localhost`
counts, a bare LAN IP does not.

## Deploy

See [DEPLOY.md](DEPLOY.md) for the Docker, nginx and certbot runbook, and
[PLATFORM-SETUP.md](PLATFORM-SETUP.md) for the Apple and Android app-side setup.
[REFERENCE.md](REFERENCE.md) documents the full endpoint contract.

---

Published by Noxno GmbH.
