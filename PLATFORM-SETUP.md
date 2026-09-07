# Apple & Android setup for a device-bound passkey

This is the operational guide for the **device-bound, hardware-attested** passkey design: the native
app itself is the WebAuthn authenticator, the credential key lives in the Secure Enclave (iOS) or in
StrongBox/TEE (Android), the OS gates it with biometrics, and the enrolment carries a real hardware
attestation that this server verifies.

It covers the Apple Developer portal, the Android signing certificates, and everything that must be
filled into `application.properties` before a real device can enrol. Follow it top to bottom; the
[pre-flight checklist](#pre-flight-checklist) at the end is the short version.

**Placeholders used throughout.** Substitute your own values everywhere they appear:

| Placeholder | Meaning | Where to read it |
| --- | --- | --- |
| `<RP_ID>` | the relying-party host, e.g. `passkeydemo.noxno.ch` | `rpId` in `application.properties` |
| `<TEAM_ID>` | Apple Developer Team ID, 10 characters | Apple Developer → Membership details |
| `<BUNDLE_ID>` | iOS bundle id of the build you run from Xcode | Xcode target → Signing & Capabilities |
| `<BUNDLE_ID_RELEASE>` | iOS bundle id of the TestFlight / App Store build, when it differs | your release build script |
| `<PACKAGE_NAME>` | Android application id | `android/app/build.gradle` → `applicationId` |
| `<DEBUG_KEY_SHA256>` | SHA-256 of the Android debug signing certificate | §2.2 |
| `<UPLOAD_KEY_SHA256>` | SHA-256 of the Android upload key | §2.2 |
| `<PLAY_APP_SIGNING_SHA256>` | SHA-256 of the Play App Signing certificate | Play Console → Setup → App signing |
| `<RELEASE_KEYSTORE>` / `<KEY_ALIAS>` | the release keystore file and its alias | your Android build setup |

The `<RP_ID>` host **also** hosts `apple-app-site-association` and `assetlinks.json`, which serve a
*different* kind of passkey — the synced, unattested platform kind. §0.1 explains the two paths and
what each buys; §1.5 and §2.10 are the setup for that second path and are clearly marked skippable if
you only care about attestation.

Relevant code in this server, if you want to read along:

| Concern | File |
| --- | --- |
| every tunable | `src/main/java/ch/noxno/passkeydemo/Config.java` |
| iOS App Attest | `.../AppAttestVerifier.java` |
| Android key attestation policy | `.../AndroidKeyAttestationPolicy.java` |
| Google roots + revocation | `.../GoogleRoots.java` |
| WebAuthn core, `rpId`, formats | `.../WebAuthnVerifier.java` |
| endpoints and log lines | `.../PasskeyController.java` |
| the two `.well-known` files | `.../WellKnownController.java` |

---

## 0. Two things to read before you plan any work

### 0.1 Two paths, and what the `.well-known` files on `<RP_ID>` buy

The `<RP_ID>` host serves both domain-association files, and this server generates them:

| URL | Content |
| --- | --- |
| `/.well-known/apple-app-site-association` | `{"webcredentials":{"apps":["<TEAM_ID>.<BUNDLE_ID>","<TEAM_ID>.<BUNDLE_ID_RELEASE>"]}}` |
| `/.well-known/assetlinks.json` | one `delegate_permission/common.get_login_creds` grant for `<PACKAGE_NAME>` plus its signing-certificate fingerprints |

`WellKnownController` renders both from `application.properties` at boot and serves them as
`Content-Type: application/json` in **strict and demo mode alike** — they describe app identity, not
the demo. `serveWellKnown=false` (default `true`) is the only switch that turns them off, and then
both paths answer `404`. See §1.5, §2.10 and `DEPLOY.md` §7a.

Now the part that matters more than the plumbing. **Those two files exist for a different kind of
passkey than the rest of this document.** They tell iCloud Keychain and Google Password Manager that
the native app may hold credentials for `<RP_ID>` — a **platform** passkey, stored and synced by
the OS vendor. The attested design uses no platform provider at all: the app **is** the
authenticator, it creates the key itself in the Secure Enclave / StrongBox-or-TEE, and it proves who
it is with a hardware attestation this server checks against Apple's and Google's roots.

| | Platform passkey — the convenience path | The app as the authenticator — the attested path |
| --- | --- | --- |
| Who holds the private key | iCloud Keychain / Google Password Manager | Secure Enclave (iOS), StrongBox-or-TEE (Android), created by the app |
| Syncs to the user's other devices | **Yes** — that is the feature | **No** — device-bound; `BE=0 && BS=0` is enforced at registration |
| WebAuthn attestation | `none` | iOS `packed` + an Apple App Attest object; Android `android-key` chained to a Google attestation root |
| BSI trust level | **normal** (TR-03188 SBT-6 wants *some* attestation; there is none to have) | **substantiell** |
| Needs the two `.well-known` files | **Yes**, plus Associated Domains + the `webcredentials:` entitlement (§1.5) and the right signing certificates in `assetlinks.json` (§2.10) | **No.** Nothing is ever fetched from the domain |
| Accepted by this server under | `attestationPolicy=demo`, and then stored `attested=false` | `attestationPolicy=strict` |
| Typical way it breaks | a wrong Team ID, a missing fingerprint, or any redirect on the file | a wrong `iosAppIds`, a missing entry in `androidSigningDigests` |

One sentence follows from that table, and it is the only warning this document will repeat:
**the two files enable the platform-passkey path and contribute nothing to the attested path — hosting
them moves the compliance path exactly zero steps forward.** They are still worth hosting, because
the convenience path is worth having: it is the fallback for the devices that cannot attest at all
(§2.6), and it is the low-barrier bucket a user may deliberately opt into — the one you want users to
be able to *leave*, which presupposes it exists. Host both, know which one you are demonstrating, and
never present a synced platform passkey as the attested credential.

(The browser walkthrough at `/demo/` needs **neither** file: a web page served from
`https://<RP_ID>` is its own WebAuthn relying party and associates with nothing. These files
matter only when the *native app* wants to speak for the domain.)

Practical consequence for the attested path: there, `<RP_ID>` is used as a **name only**. It is
the `rpId` string that goes into `clientDataJSON` and into the `rpIdHash` of the authenticator data.
When the app is its own authenticator nothing is fetched from that host during enrolment — it would
work against a hostname that does not even resolve. (It does of course serve the API, the demo page and,
now, these two files.)

### 0.2 A browser at `<RP_ID>` cannot produce attestation. Ever.

A browser at `https://<RP_ID>` can run a WebAuthn ceremony. It will use the platform
authenticator (Touch ID / Windows Hello / a phone over hybrid transport) and it will return
**`fmt: "none"`**. There is no browser flag, no server option and no Chrome policy that turns that
into `android-key` or into an Apple App Attest object.

The server has a switch for what to do with that, `attestationPolicy`:

- **`attestationPolicy=strict`** (the default, and the compliance path) rejects it outright:

  ```
  403 ATTESTATION_REJECTED: Der Passkey konnte nicht bestätigt werden:
      Attestierungsformat none wird nicht akzeptiert
      (attestationPolicy=strict verlangt android-key oder packed+App Attest)
  ```

- **`attestationPolicy=demo`** additionally accepts `fmt=none` so a plain browser can complete the
  ceremony for a demo. The credential is then stored as `platform=web`, `securityLevel=none`,
  **`attested=false`**, with an `attestationNote` spelling out that there is no hardware attestation,
  and both the enrolment and the credential list carry that flag. Every such enrolment logs:

  ```
  WARN  DEMO MODE: accepting fmt=none registration, NOT hardware attested. aaguid=… (unattested) …
  WARN  DEMO MODE: enrolling an UNATTESTED credential for user=… via the compliance endpoint
        (fmt=none, deviceBound=…). This credential does NOT meet BSI trust level substantiell.
  ```

Demo mode changes **nothing** about what a browser can produce. It only decides whether the server
files the unattested result away as unattested, or refuses it. Read those WARN lines as what they
are: the server telling you this credential is not the thing the design is about.

So, for the demo, state it in exactly these terms:

- **A browser demo can show the passkey *ceremony*** — challenge, user verification, assertion,
  signature check, login. That is real and worth showing. It needs `attestationPolicy=demo`, and
  what it produces is labelled `attested=false`.
- **A browser demo cannot show *attestation*.** Attestation only exists in the native app. The
  "login with attestation" story must be run from the native app on a real iPhone or a real Android
  phone, pointed at this server, with `attestationPolicy=strict`.

Do not let those two get blurred in the demo narrative. Everything in this document is about the
second one.

---

## 1. Apple

### 1.1 Enable App Attest on the App ID — on *both* of them

Apple Developer portal → **Certificates, Identifiers & Profiles → Identifiers → App IDs** → select
the App ID → **Capabilities** → tick **App Attest** → Save → then **regenerate the provisioning
profiles** for that App ID (a profile issued before the capability was added does not carry it, and
the app will fail at `generateKey`).

You need an Account Holder or Admin role to do this.

**Which App ID?** Check first whether your project has **more than one**. Many Capacitor / React
Native setups rewrite the bundle id in the release build script, so the build you run out of Xcode
and the build that reaches TestFlight carry *different* App IDs — and App Attest treats them as
completely unrelated identities:

| Where | Bundle id | App Attest App ID (`TEAMID.bundleid`) |
| --- | --- | --- |
| the Xcode project — dev builds, Debug and Release | `<BUNDLE_ID>` | `<TEAM_ID>.<BUNDLE_ID>` |
| after the release build script rewrites it — TestFlight / App Store | `<BUNDLE_ID_RELEASE>` | `<TEAM_ID>.<BUNDLE_ID_RELEASE>` |

Find out by grepping the release build script for the bundle id it writes, and by checking the
Capacitor / project config file *after* a release build — a script that rewrites it and does not
restore it leaves the working tree on the release value.

Therefore:

- **Enable App Attest on every App ID you will build**, and regenerate each set of provisioning
  profiles. If you only ever demo from Xcode you can get away with the dev App ID, but the moment
  anyone hands out a TestFlight build the release one is needed too.
- **`iosAppIds` in `application.properties` must list `TEAMID.bundleid` for every App ID you want
  accepted**, comma-separated:

  ```properties
  iosAppIds=<TEAM_ID>.<BUNDLE_ID>,<TEAM_ID>.<BUNDLE_ID_RELEASE>
  ```

  For a production backend, narrow it to the release App ID only. In the container, set
  `PASSKEY_IOS_APP_IDS` instead of editing the file.

### 1.2 Why a wrong bundle id fails *silently*

Inside the App Attest object, Apple puts `rpIdHash = SHA256("TEAMID.bundleid")` into the
authenticator data. This server does not receive the App ID as text — it recomputes the hash for
every entry of `iosAppIds` and looks for a match (`AppAttestVerifier.appIdFor`):

```java
for (String appId : config.iosAppIds()) {
    if (constantTimeEquals(rpIdHash, sha256(utf8(appId)))) return appId;
}
throw ApiException.deviceNotEligible("die App-ID der Attestierung ist nicht konfiguriert");
```

Two consequences you must internalise:

1. **One wrong character kills every attestation.** A capitalised letter in the bundle id, a stray
   space, the wrong team id — the hash simply does not match and *all* iOS enrolments fail.
   There is no partial match, no warning, no gradual degradation.
2. **The error message cannot tell you which App ID the device actually used**, because the server
   only ever sees a 32-byte hash. The log line is the generic
   `403 DEVICE_NOT_ELIGIBLE: Dieses Gerät ist für Passkeys nicht geeignet: die App-ID der Attestierung ist nicht konfiguriert`.

   The way to diagnose it is to put **both** candidates into `iosAppIds`, retry, and then read the
   *success* line, which prints the App ID that matched:

   ```
   INFO  packed + App Attest accepted: environment=appattestdevelop appId=<TEAM_ID>.<BUNDLE_ID>
   ```

   That line is the ground truth about which bundle id the build on that device really has.

Note that the WebAuthn `rpId` (`<RP_ID>`) and the App Attest App ID
(`<TEAM_ID>.<BUNDLE_ID>`) are **completely separate namespaces**. Changing `rpId` does not
change `iosAppIds`, and vice versa. They are hashed into two different fields of two different
objects.

### 1.3 The App Attest environment entitlement

The entitlement is:

```xml
<key>com.apple.developer.devicecheck.appattest-environment</key>
<string>development</string>   <!-- or: production -->
```

| Value | What Apple's attestation service does |
| --- | --- |
| `development` | Attests against the sandbox service. The resulting object carries AAGUID **`appattestdevelop`**. Rate limits are relaxed; receipts are not usable for production fraud metrics. |
| `production` | Attests against the production service. AAGUID **`appattest`**. |

**The rule that catches everyone:** TestFlight and App Store builds **always use the production
environment at runtime, regardless of what the entitlement says.** The entitlement only steers builds
you install yourself (Xcode run, direct install, ad-hoc). So the server cannot key its acceptance off
the build configuration — it must accept both AAGUIDs and record which one it got, per credential.

This server already does that. `appAttestEnvironments` is the allowlist and the default accepts both:

```properties
appAttestEnvironments=appattest,appattestdevelop
```

`AppAttestVerifier` maps the AAGUID to the environment, checks it against that list, and then puts
webauthn4j-appattest into the matching mode (`setProduction(true)` only for `appattest`). The chosen
environment is stored on the credential (`appAttestEnvironment`) and logged on success.

For a production backend, set `appAttestEnvironments=appattest` — but only once nobody enrols from an
Xcode build any more.

There is one further environment-dependent check. `AppAttestVerifier.verifyAppleExtensions` reads
`apple_validation_category_01` from the authenticator data and enforces:

| Environment | Accepted category values |
| --- | --- |
| `appattest` (production) | `2` (TestFlight) or `4` (App Store) |
| `appattestdevelop` | `3` |

If the extension is absent (older iOS), it is tolerated and logged. The practical effect: a
*Release-configuration build installed directly from Xcode with the `production` entitlement* attests
production but is neither TestFlight nor App Store, and can be rejected with

```
403 ATTESTATION_REJECTED: … apple_validation_category_01=<n> ist in der Umgebung appattest nicht erlaubt
```

So for on-device testing outside TestFlight, keep the entitlement at `development`. The generator
already does this for you — see next.

### 1.4 The entitlement must come from a generator, not from Xcode

`ios/` is a generated directory. `npx cap add ios` (and `bin/readd-platform.mjs`) recreates it from
the Capacitor template, and **anything you clicked into Xcode is gone**: the `.entitlements` file,
the `CODE_SIGN_ENTITLEMENTS` build setting, and the `NSFaceIDUsageDescription` string. If you
hand-edit these, you will lose App Attest at the least convenient moment, and the failure mode is a
`generateKey` error on device — not a build error.

`bin/generate-ios-entitlements.mjs` exists for exactly this and is already wired in. Verified state of
the working copy today:

| Thing | State |
| --- | --- |
| `bin/generate-ios-entitlements.mjs` | present |
| registered in `bin/cli.mjs` | yes — `ios-entitlements` command (`bin/cli.mjs:85`) |
| called from `bin/generate-ios-manifests.mjs` | yes (`generateIosEntitlements(options)`) |
| reached from `bin/generate-ios-build.mjs` | yes, indirectly — it runs `generate-ios-manifests.mjs --configuration=<cfg>` |
| `ios/App/App/App.entitlements` | present, currently `development` |
| `CODE_SIGN_ENTITLEMENTS = App/App.entitlements;` in `project.pbxproj` | present in both App-target configurations (lines 350 and 374) |
| `NSFaceIDUsageDescription` in `ios/App/App/Info.plist` | present, and in the `bin/generate-info-plist.mjs` template |

What the generator does each run: writes `App.entitlements` wholesale, idempotently sets
`CODE_SIGN_ENTITLEMENTS` in the two stable App-target build configurations
(`504EC3171FED79650016851F` Debug, `504EC3181FED79650016851F` Release), and idempotently adds the
Face ID usage string to `Info.plist`. It is bundle-id-agnostic: the entitlements file carries only
the environment, never an App ID, so the same generator serves both bundle ids.

Environment mapping (`appAttestEnvironmentFor`): `--configuration production` → `production`;
**everything else** — `development`, `beta`, `test`, or missing — → `development`.

Run the generator after every platform re-add, and before any archive — once for the on-device
(`development`) entitlement and once for the App Store / TestFlight (`production`) one.

Then verify, rather than assume:

```bash
cat ios/App/App/App.entitlements
grep -c CODE_SIGN_ENTITLEMENTS ios/App/App.xcodeproj/project.pbxproj   # must print 2
```

In Xcode, after a clean checkout, confirm **Signing & Capabilities** shows *App Attest* on the target.
If it does not, the provisioning profile predates the capability — regenerate it (§1.1).

### 1.5 Associated Domains and `webcredentials:` — platform-passkey path only

Skip this whole section if you only care about the attested path. Nothing here is needed for App
Attest, nothing here strengthens it, and nothing here weakens it. This is the §0.1 convenience path:
it is what lets **iCloud Keychain** create and offer a passkey for `<RP_ID>` inside the native app.
Such a credential syncs across the user's Apple devices and returns attestation `none`.

Three things must agree, and all three are separate places:

**1. The capability on the App ID.** Apple Developer portal → *Certificates, Identifiers & Profiles →
Identifiers → App IDs* → the App ID → *Capabilities* → tick **Associated Domains** → Save → then
**regenerate the provisioning profiles** (exactly the same rule as App Attest in §1.1: a profile
issued before the capability was added does not carry it). Do it for **every** App ID you build,
`<BUNDLE_ID>` and `<BUNDLE_ID_RELEASE>`.

**2. The entitlement in the build.**

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>webcredentials:<RP_ID></string>
</array>
```

`webcredentials:` is the password/passkey autofill service and the only one needed here. `applinks:`
is Universal Links — a different feature; do not add it by reflex, it only creates another file
section to keep correct.

**3. The AASA file on the host**, listing the fully qualified App IDs:

```json
{
  "webcredentials": {
    "apps": [
      "<TEAM_ID>.<BUNDLE_ID>",
      "<TEAM_ID>.<BUNDLE_ID_RELEASE>"
    ]
  }
}
```

That is exactly what this server emits — `WellKnownController` builds the list from `iosAppIds`,
prefixing `appleTeamId` (`<TEAM_ID>`) onto any entry that does not already carry a team id. Verified
against the running server: with `iosAppIds=<TEAM_ID>.<BUNDLE_ID>,<BUNDLE_ID_RELEASE>`
the response body is the JSON above, `200`, `Content-Type: application/json`. An entry that starts
with a *different* ten-character team id is published unchanged and logged as a `WARN` — deliberately,
because silently rewriting it would hide the fact that one of the two settings is wrong.

Serving requirements are Apple's, not ours: `https`, `Content-Type: application/json`, and **no
redirect of any kind** on that URL. `DEPLOY.md` §7a has the curl commands that prove all three.

#### If your entitlements file is generated, the entitlement must live in the generator

This applies to any project where `ios/` is regenerated from a template (Capacitor's `npx cap add
ios`, an Expo prebuild, or a script that writes `App.entitlements` wholesale). Two consequences:

- Ticking *Associated Domains* in Xcode's *Signing & Capabilities*: **lost** at the next platform
  re-add, along with everything else Xcode wrote into `ios/`.
- Hand-editing `App.entitlements`: **lost** at the next run of the generator, which rewrites the
  whole file.

The only durable home for `com.apple.developer.associated-domains` is inside that generator, next to
the App Attest environment key. **Until the generator emits it, treat the platform-passkey path on
iOS as not set up**, whatever Xcode is currently showing you. The failure mode on device is silent:
iOS simply never offers a passkey for `<RP_ID>`, with no error anywhere.

#### Two things that will otherwise cost you an afternoon

- **The device does not read your file directly.** iOS fetches the AASA through Apple's CDN, which
  holds a copy for roughly a day, so a file you just fixed can stay stale on device well after your
  own `curl` returns the new one. During development turn on *Settings → Developer → Associated
  Domains Development* on the iPhone, which makes it fetch from the host instead of the CDN.
  `DEPLOY.md` §7a has the CDN URL to inspect what Apple actually holds.
- **Never "fix" a failing App Attest enrolment by adding an Associated Domain**, and never fix a
  missing platform passkey by touching `iosAppIds` for attestation. The two mechanisms share the
  string `<TEAM_ID>.<BUNDLE_ID>` and nothing else: one is hashed into an App Attest object (§1.2),
  the other is published in a JSON file. A change on one side has no effect whatsoever on the other.

### 1.6 What a successful iOS enrolment looks like on the server

Two lines, in this order, on `POST …/passkey/register/verify`:

```
INFO  packed + App Attest accepted: environment=appattestdevelop appId=<TEAM_ID>.<BUNDLE_ID>
INFO  audit enrolled user=<email> credentialId=<base64url> platform=ios fmt=packed attested=true deviceBound=true aaguid=7a0e4c5e-1d3b-4b8f-9a6c-3f2e1d0c9b8a securityLevel=secure_enclave
```

`attested=true` is the word to look for. If the audit line says `attested=false` or `platform=web`,
you are looking at a browser enrolment in demo mode, not at an attested one.

Possibly preceded by, on newer iOS:

```
INFO  App Attest validation category 3 bundle version <n>
```

or, on older iOS:

```
INFO  App Attest without apple_validation_category_01 (older iOS) - tolerated
```

The response is `200` with `{"credentialId": "...", "platform": "ios", ...}`. On a subsequent login,
`…/passkey/login/verify` additionally logs `App Attest assertion counter is now <n>` — that counter
must strictly increase on every login; the server answers `COUNTER_REGRESSION` if it does not.

Note what `securityLevel=secure_enclave` means here, honestly: App Attest proves genuine Apple
hardware and an unmodified build of the app, bound to *this* credential. The biometric gating of the
credential key itself is enforced by `SecAccessControl` in the app's own (audited) source, not carried
inside the attestation. Android carries the user-auth requirement inside the attestation; iOS does
not. Say so if an evaluator asks.

### 1.7 iOS failure modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `DCAppAttestService.shared.isSupported == false` | Simulator, Mac (Catalyst / iOS-app-on-Apple-silicon), or a device without a usable Secure Enclave. | Not fixable. The app must treat this as **device not eligible at enrolment** and offer the password-only path — never let the user reach a login that then cannot be completed. **You cannot demo attestation on the Simulator.** |
| `DCError.invalidKey` at `attestKey` or `generateAssertion` | The keyId is not one Apple's service recognises for this App ID **and this environment**. Classic triggers: the entitlement changed between `generateKey` and `attestKey`; a keyId generated under a dev build being reused after moving to TestFlight (which is production); attesting the same key twice. | Discard the stored keyId, `generateKey` again, re-enrol. In the app this surfaces as `CREDENTIAL_INVALIDATED`. |
| `DCError.serverUnavailable` at `attestKey` | Apple's attestation service is temporarily unavailable. The attestation did **not** happen. | **Retry `attestKey` with the same keyId and the same `clientDataHash`** — i.e. the same App Attest challenge. This server supports it: `register/verify` consumes the ceremony **only on success** (`ceremonies.consume` runs after verification), so the challenge is still valid for the retry. This is the one documented exception to "attest each key exactly once". |
| `403 DEVICE_NOT_ELIGIBLE: … die App-ID der Attestierung ist nicht konfiguriert` | `iosAppIds` does not contain the `TEAMID.bundleid` of the build on that device. | §1.1 / §1.2. Add both, retry, read the App ID off the success line. |
| `403 DEVICE_NOT_ELIGIBLE: App-Attest-Umgebung appattest ist nicht erlaubt` (or `appattestdevelop`) | `appAttestEnvironments` is too narrow for the build in use. | Add the environment, or rebuild with the other entitlement. Remember TestFlight ignores the entitlement. |
| `403 ATTESTATION_REJECTED: App Attest: …` | webauthn4j-appattest rejected the object: chain does not reach the Apple App Attestation Root CA, nonce/`clientDataHash` binding wrong, `keyId != SHA256(credCert public key)`, counter not 0. | Almost always a client bug in the `clientDataHash` construction, which must be `SHA256(SHA256(webauthnAttestationObject) ‖ appAttestChallenge)` at registration. Re-check against `AppAttestVerifier.registrationClientDataHash`. |
| `403 ATTESTATION_REJECTED: für iOS ist eine App-Attest-Bestätigung erforderlich` | The client sent `fmt=packed` with no `deviceAttestation` block (or with `platform != "ios"`, or a missing `keyId`/`attestationObject`). | App-side. On iOS the App Attest object is mandatory, at registration **and** at every assertion. |
| `403 ATTESTATION_REJECTED: der Passkey ist nicht gerätegebunden (BE/BS gesetzt)` | A synced platform passkey (iCloud Keychain) reached the endpoint. | The credential must be created by the app's own authenticator, not by the system provider. |

---

## 2. Android

For the **attested** path nothing has to be configured in the Play Console: what the **server**
needs is the SHA-256 of every signing certificate that will produce a build the demo must accept.
(The Play Console does come into it for the platform-passkey path in §2.10, which needs the Play App
Signing fingerprint published in `assetlinks.json`.)

### 2.1 Which certificates, and why more than one

Android's key attestation embeds an `attestationApplicationId` structure listing the package name and
the SHA-256 digests of the certificates the *installed* app is signed with. `AndroidKeyAttestationPolicy`
checks the package against `androidPackageName` and the digests against `androidSigningDigests`.

Because the installed app is signed by a different key depending on how it got onto the phone, you
need all of these:

| Build | Signed by | Needed for |
| --- | --- | --- |
| Installed from Google Play | **Play App Signing certificate** (Google re-signs the AAB) | production, internal testing tracks, anything from the Play Store |
| Locally built release APK/AAB | **upload key** (`<RELEASE_KEYSTORE>`, alias `<KEY_ALIAS>`) | sideloaded release builds, pre-Play verification |
| `assembleDebug` / Android Studio run | **debug key** (`~/.android/debug.keystore`, alias `androiddebugkey`) | local development on the demo machine |

The package name is the same in all three: `<PACKAGE_NAME>`
(`android/app/build.gradle`: `applicationId "<PACKAGE_NAME>"`). Android usually has only one, even
when iOS has two (§1.1) — do not "fix" `androidPackageName` to match an iOS release bundle id.

### 2.2 Getting each digest

**Debug key** (fixed password `android` for both store and key):

```bash
keytool -list -v \
  -keystore ~/.android/debug.keystore \
  -alias androiddebugkey -storepass android -keypass android \
  | grep -i "SHA256:"
```

**Upload key** (`<RELEASE_KEYSTORE>`, alias `<KEY_ALIAS>` — whatever your release build signs with):

```bash
keytool -list -v -keystore /path/to/<RELEASE_KEYSTORE> -alias <KEY_ALIAS> | grep -i "SHA256:"
```

**Play App Signing certificate**: Play Console → your app → **Test and release → Setup → App signing**.
That page shows both *App signing key certificate* and *Upload key certificate*; take the **SHA-256
certificate fingerprint** of the **App signing key certificate**. There is no CLI for this — it is a
copy-paste from the console.

**Straight off a built artefact** (the most reliable check, because it reads what was actually
signed):

```bash
apksigner verify --print-certs app-release.apk | grep -i "SHA-256 digest"
# or, for the debug build:
apksigner verify --print-certs android/app/build/outputs/apk/debug/app-debug.apk | grep -i "SHA-256 digest"
```

`apksigner` prints lower-case hex without separators — exactly the canonical format.

### 2.3 The exact format `androidSigningDigests` expects

Canonical: **lower-case hex, 64 characters, no colons**, comma-separated for several certificates.

```properties
androidSigningDigests=<DEBUG_KEY_SHA256>,<UPLOAD_KEY_SHA256>,<PLAY_APP_SIGNING_SHA256>
```

`Config.androidSigningDigests()` normalises what it reads —
`value.toLowerCase(Locale.ROOT).replace(":", "")` — so you *may* paste `keytool`'s
`AB:CD:EF:…` uppercase-with-colons form and it will still match. Prefer the canonical form anyway so
the file stays diffable.

> If your Android build pipeline records the signing fingerprint somewhere (a generated checksum
> file, a build log), that value is a useful cross-check — but it is the digest of whichever key the
> *last* build used, not necessarily the one you want. **Verify it with `keytool` against the actual
> keystore before trusting it**; do not paste it in blind.

**The footgun:** an *empty* `androidSigningDigests` does not block anything. The policy logs a warning
and accepts whatever it got:

```
WARN  androidSigningDigests is empty - accepting signing certificate [<digest>] unchecked
```

That is genuinely useful once — it prints the digest the device actually presented, so you can copy it
straight into the property — but it must never be left empty for a demo you call "attested", because
at that moment any app signed by anyone passes the signature check.

### 2.4 The attestation chain and the two Google roots

An Android key attestation chain ends at one of Google's hardware attestation roots, fetched from
`https://android.googleapis.com/attestation/root` and cached in `cache/google-roots.json`. There are
**two** of them today (verified against the live endpoint on 2026-09-06 — the endpoint returned 2 roots
and 1742 revocation entries):

| # | Root | Key | Validity | Used by |
| --- | --- | --- | --- | --- |
| 1 | `serialNumber = f92009e853b6b045` (no CN) | RSA-4096 | 2022-03-20 → 2042-03-15 | the long-standing factory-provisioned chains |
| 2 | `CN = Key Attestation CA1, OU = Android, O = Google LLC, C = US` | EC **P-384** | 2025-07-17 → 2035-07-15 | Remote Key Provisioning (RKP) chains, active since 2026-02-01 |

A verifier that only knows the RSA root will start failing on newly provisioned devices. `GoogleRoots`
loads both and treats them as an equivalent anchor set.

Two Google-specific quirks the server already handles, so you recognise them in the log:

- **Legacy factory chains outlive their certificates.** Google keeps trusting pre-RKP chains under the
  RSA root after they expire. For a chain under root #1 with no provisioning-info extension
  (`1.3.6.1.4.1.11129.2.1.30`), validity is checked at the moment the chain was issued instead of now:
  `INFO  legacy factory chain under the RSA root - validity checked at <instant>`.
- **Revocation is a JSON status list, not CRL/OCSP.** Every certificate serial in the chain is looked
  up against `https://android.googleapis.com/attestation/status` (cached in
  `cache/google-status.json`). A hit — `REVOKED` or `SUSPENDED` — rejects the enrolment. This check is
  mandatory: it is how a known-compromised batch of device keys gets shut out.

On startup / first attestation you should see:

```
INFO  Google attestation data: 2 root(s), 1742 revocation entries
```

If it says `0 root(s)`, the host cannot reach `android.googleapis.com` and there is no cache — **no
Android enrolment can succeed** until that is fixed. The fetcher falls back to the on-disk cache when
the network fails, so a cold demo machine behind a restrictive firewall must have `cache/` pre-warmed.

### 2.5 `allowSoftwareAttestationRoot` — what it really switches off

```properties
allowSoftwareAttestationRoot=true    # shipped default; test only
```

An emulator has no hardware keystore. It produces a chain rooted in the **AOSP software attestation
root** (`CN = Android Keystore Software Attestation Root`), which Google's endpoint does not list and
which no PKIX validation against the Google roots can accept. `allowSoftwareAttestationRoot=true`
makes the server take that chain anyway, so you can develop against an emulator.

Setting it to `true` changes **three** things, and all three weaken the guarantee:

1. `GoogleRoots.Verifier` accepts the software root. Signatures along the chain are still checked;
   **certificate validity is not** — the AOSP software root and its intermediate expired in January
   2026, which is already in the past, so the emulator path only works *because* validity is skipped.
   The log says so every time:
   `WARN  accepting the AOSP software attestation root because allowSoftwareAttestationRoot=true`
2. `AndroidKeyAttestationPolicy` stops rejecting `securityLevel == SOFTWARE`, and starts merging the
   **software-enforced** authorization list into the hardware-enforced one. Key properties (`origin`,
   `purpose`, `algorithm`, `ecCurve`, `userAuthType`) may then be satisfied by claims the emulator made
   about itself.
3. `WebAuthnVerifier` sets `AndroidKeyAttestationStatementVerifier.setTeeEnforcedOnly(false)`.

> **`allowSoftwareAttestationRoot=true` means "an emulator can enrol". It MUST be `false` in any real
> deployment, and it must be `false` for a demo you present as hardware-attested.** With it `true`, the
> word "hardware" in your slides is not true. Flip it to `false` before the demo and re-test on the
> real phone — the switch also tightens the policy above, so a device that enrolled under `true` is
> not proof that it enrols under `false`.

### 2.6 Device eligibility: not every Android phone can do this

Hardware key attestation is not universally available, and there is no way to make it available. The
following **cannot** produce a hardware-attested key at all:

- **Emulators / AVDs** — software root only (see §2.5).
- **Devices without Google Mobile Services** — notably Huawei/Honor on HMS. The Keystore may exist but
  there is no Google-rooted attestation chain, so nothing this server can anchor.
- **Some unlocked OnePlus / OPPO / realme models** — after bootloader unlock, several of these stop
  producing a valid attestation chain, or produce one that fails validation.
- Older or budget devices whose Keymaster/KeyMint predates usable attestation, or where the key can
  only be created at `SOFTWARE` security level.

**The app must treat this as "device not eligible" at *enrolment*, not as a failure at login.** The
enrolment attempt fails with `DEVICE_NOT_ELIGIBLE` and the user must be told, at that point, that this
phone cannot use the passkey factor — and be left on the password-only path with a working account. A
user who is allowed to enrol and only discovers at the next login that their phone cannot attest is
locked out, and hotline recovery
(`POST …/passkey/admin/reset` with `X-Admin-Token`) is the only way back.

The relevant server errors, all `403`:

```
DEVICE_NOT_ELIGIBLE: … die Attestierung stammt nicht aus TEE oder StrongBox
DEVICE_NOT_ELIGIBLE: … Bootloader entsperrt oder Verified Boot nicht bestätigt (deviceLocked=…, verifiedBootState=…)
```

### 2.7 `verifiedBootPolicy`: `log` vs `enforce`

```properties
verifiedBootPolicy=log       # or: enforce
```

The attestation carries a `rootOfTrust` structure with `deviceLocked` (bootloader locked?) and
`verifiedBootState` (`0 = Verified`, i.e. booted with the OEM's own keys).

| Value | Behaviour when `deviceLocked && verifiedBootState == Verified` is **not** true |
| --- | --- |
| `log` | Enrolment **proceeds**. `WARN verifiedBootPolicy=log: deviceLocked=<b> verifiedBootState=<n>`. The values are still stored on the credential, so you can audit later who enrolled from an unlocked device. |
| `enforce` | Enrolment is **rejected** with `DEVICE_NOT_ELIGIBLE: Bootloader entsperrt oder Verified Boot nicht bestätigt (…)`. |

The trade-off, plainly:

- **`enforce` is the stronger posture.** A locked bootloader with Verified Boot means the running OS is
  the OEM's signed image, so the OS-level guarantees the design leans on — the biometric gate on the
  key, the app sandbox — are actually backed by something. Without it, a rooted or custom-ROM device can
  still hold a genuine hardware key while the *software* around it is fully attacker-controlled.
- **`enforce` rejects real users.** Anyone with an unlocked bootloader, a custom ROM
  (LineageOS/GrapheneOS), or a manufacturer-unlockable developer device is locked out, permanently,
  with no self-service path. Developers' own test phones are frequently in this state — including,
  quite possibly, the phone you plan to demo on.

Recommendation, and this is what the design says: **start at `log`**, watch what real enrolments report
for a while, and only move to `enforce` once you know how many of your users it would exclude. For the
demo itself, `log` is the safe choice — but if you demo with `log`, do not claim Verified Boot is being
enforced; claim it is being *recorded*.

### 2.8 What a successful Android enrolment looks like on the server

```
INFO  android-key accepted: securityLevel=strongbox attestationVersion=300 deviceLocked=true verifiedBootState=0
INFO  audit enrolled user=<email> credentialId=<base64url> platform=android fmt=android-key attested=true deviceBound=true aaguid=2b9c7d6e-5f4a-4c3b-8a2d-1e0f9c8b7a6d securityLevel=strongbox
```

`securityLevel` is `strongbox`, `tee` or `software`. **`software` is the one that must not appear in a
demo you call hardware-attested** — it means either an emulator or a device that fell back, and it can
only appear at all while `allowSoftwareAttestationRoot=true`.

### 2.9 `acceptedOrigins` — the Android-specific trap

`clientDataJSON` carries an `origin`, and webauthn4j checks it against a fixed set. For a *browser*
that origin is `https://<RP_ID>`. But **the app is its own authenticator and writes
`clientDataJSON` itself**, so on Android the conventional value is not a URL at all:

```
android:apk-key-hash:<base64url of the SHA-256 of the signing certificate, no padding>
```

`application.properties` ships `acceptedOrigins=https://<RP_ID>` — the one origin a
browser produces, and the same value you would get by leaving the key out entirely. If the Android
client sends the `apk-key-hash` form instead, webauthn4j rejects the registration **before any
attestation check runs**, and the error is a generic `403 ATTESTATION_REJECTED` naming the origin.
This is the single most likely reason a first Android enrolment fails on an otherwise perfect setup.

Two rules:

1. Find out what the client actually sends (check with whoever owns the native plugin, or decode `clientDataJSON` from a
   captured request / a `vectors/android-*.json` file) and list **every** origin in `acceptedOrigins`.
2. **When `acceptedOrigins` is set it is the complete list** — `https://<rpId>` is *not* added
   implicitly. If you add the Android origin, you must re-add the https one alongside it or iOS and
   the browser stop working:

   ```properties
   acceptedOrigins=https://<RP_ID>,android:apk-key-hash:<base64url-sha256-of-signing-cert>
   ```

The hash is the **same certificate** whose hex digest goes into `androidSigningDigests`, just encoded
differently — base64url of the raw SHA-256 rather than hex. Convert one to the other:

```bash
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android \
  | awk -F'SHA256: ' '/SHA256:/{print $2; exit}' \
  | tr -d ':\r\n' | tr 'A-F' 'a-f' | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

(The output is the base64url form of the same certificate hash. It differs per developer machine,
because the debug keystore does — which is also why every developer's debug build needs its own entry
in both properties.)

Typos here fail loudly and early, which is deliberate: an unparsable origin throws at startup
(`acceptedOrigins contains an unparsable origin: …`) rather than at the first login. An empty list
after trimming likewise refuses to boot.

### 2.10 `assetlinks.json` — platform-passkey path only, and it needs the *right* certificates

Skip this section too if you only care about the attested path: Digital Asset Links has no bearing on
`android-key` attestation, and an `android-key` enrolment succeeds against a host that serves no
`assetlinks.json` at all. This is the §0.1 convenience path — the file is what makes **Google Password
Manager** create and offer a passkey for `<RP_ID>` inside the native app. Such a credential syncs to
the user's Google account and returns attestation `none`.

This server serves it at `https://<RP_ID>/.well-known/assetlinks.json`. Verified against the
running server, the body is a JSON **array**:

```json
[
  {
    "relation": ["delegate_permission/common.get_login_creds"],
    "target": {
      "namespace": "android_app",
      "package_name": "<PACKAGE_NAME>",
      "sha256_cert_fingerprints": [
        "<PLAY_APP_SIGNING_SHA256>",
        "<UPLOAD_KEY_SHA256>"
      ]
    }
  }
]
```

`delegate_permission/common.get_login_creds` is the relation that grants credentials.
`delegate_permission/common.handle_all_urls` is App Links — a different feature, and adding it here
grants nothing towards passkeys.

#### Which certificates, and why this list is *not* `androidSigningDigests`

Android verifies the statement against the certificate the **installed** app is signed with, so the
same three-key problem as §2.1 applies: an app installed from Play carries Google's re-signing
certificate, a sideloaded release APK carries the upload key, a `assembleDebug` build carries the
debug key. A certificate that is not listed simply gets no passkeys — silently, with no error on the
device and nothing in this server's log, because the check happens entirely between the phone and
Google.

But the two lists are **not** the same list, and the server keeps them as two keys on purpose:

| | `androidSigningDigests` | `androidWebCredentialDigests` (published in `assetlinks.json`) |
| --- | --- | --- |
| What it is | a server-side **acceptance** list, checked per registration against the `attestationApplicationId` extension | a **public grant**, fetched and cached by Google for the whole internet |
| Blast radius of a wrong entry | that build's enrolments are rejected | any app signed by the listed certificate may receive this domain's platform passkeys |
| Debug key belongs in it? | **yes** — that is how local builds enrol | **no**, not on a public host |

That last row is the one to internalise. The Android debug keystore is unencrypted and its password
is the literally-documented string `android`, and every developer's is different but equally
guessable in structure — publishing its fingerprint in `assetlinks.json` on a reachable host grants
this domain's platform passkeys to anything anyone signs with a debug key. Put the debug fingerprint in
`androidSigningDigests` so local builds can enrol, and leave it out of
`androidWebCredentialDigests` anywhere the file is publicly served.

`androidWebCredentialDigests` **defaults to `androidSigningDigests`** when it is unset, which is the
convenient default for a laptop and the wrong one for a public host. Set it explicitly on the
deployed host:

```properties
# server-side acceptance: debug + upload + Play, so every build can enrol
androidSigningDigests=<DEBUG_KEY_SHA256>,<UPLOAD_KEY_SHA256>,<PLAY_APP_SIGNING_SHA256>
# public grant: NO debug key
androidWebCredentialDigests=<UPLOAD_KEY_SHA256>,<PLAY_APP_SIGNING_SHA256>
```

If both end up empty the file is still valid JSON with an empty `sha256_cert_fingerprints` array, and
Android breaks silently. The server warns about exactly that at boot:

```
WARN  androidWebCredentialDigests and androidSigningDigests are both empty - /.well-known/assetlinks.json
      publishes an EMPTY sha256_cert_fingerprints list. That is valid JSON and breaks Android passkeys
      SILENTLY: Google Password Manager simply never offers a credential for <RP_ID>.
```

#### Getting each fingerprint

| Certificate | Where it comes from | Known today? |
| --- | --- | --- |
| **Debug key** `<DEBUG_KEY_SHA256>` | `~/.android/debug.keystore`, alias `androiddebugkey`, store and key password `android` | read it off your own machine — it is per developer, and it must **never** go into the public grant |
| **Upload key** `<UPLOAD_KEY_SHA256>` | `keytool` against `<RELEASE_KEYSTORE>`, alias `<KEY_ALIAS>` — **or**, without needing the password, Play Console → your app → *Test and release → Setup → App signing* → **Upload key certificate** → SHA-256 | needs the keystore password, or Play Console access |
| **Play App Signing cert** `<PLAY_APP_SIGNING_SHA256>` | Play Console → your app → *Test and release → Setup → App signing* → **App signing key certificate** → SHA-256 certificate fingerprint. There is no CLI for this; it is a copy-paste | needs Play Console access |

```bash
# debug key
keytool -list -v -keystore ~/.android/debug.keystore \
  -alias androiddebugkey -storepass android -keypass android | grep -i 'SHA256:'

# upload key (prompts for the keystore password)
keytool -list -v -keystore /path/to/<RELEASE_KEYSTORE> -alias <KEY_ALIAS> | grep -i 'SHA256:'

# what actually signed a built artefact - the most reliable check of the three
apksigner verify --print-certs app-release.apk           | grep -i 'SHA-256 digest'
apksigner verify --print-certs app-debug.apk             | grep -i 'SHA-256 digest'
```

#### Two spellings of the same bytes

This is where the copy-paste goes wrong, so read the two lines carefully:

| File | Spelling | Length | Produced by |
| --- | --- | --- | --- |
| `assetlinks.json` → `sha256_cert_fingerprints` | **UPPER-CASE hex, a colon between every byte** — `AB:CD:EF:…:67:89` | 95 characters | `keytool -list -v` prints exactly this |
| `application.properties` → `androidSigningDigests` / `androidWebCredentialDigests` | **lower-case hex, no separators** — `abcdef01…6789` | 64 characters | `apksigner verify --print-certs` prints exactly this |

You do not have to convert by hand for the properties file — `Config` normalises whatever you paste
(`toLowerCase`, colons stripped), and `WellKnownController.toAssetLinksFingerprint` converts back to
the upper-case colon form when it renders `assetlinks.json`. But if you ever hand-write the JSON, use
the upper-case colon form; that is the spelling Digital Asset Links documents and the one `keytool`
hands you. Converting manually:

```bash
# properties/apksigner form -> assetlinks form
echo abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
  | tr 'a-z' 'A-Z' | sed 's/../&:/g; s/:$//'
# -> AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89

# keytool/assetlinks form -> properties form
echo 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89' \
  | tr -d ':' | tr 'A-Z' 'a-z'
# -> abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```
(The digest above is a made-up, well-formed example — no real signing key is involved.)

Note this is a *third* encoding of the same certificate hash. §2.9's `android:apk-key-hash:` origin is
base64url of the same 32 bytes. Three files, three spellings, one certificate.

---

## 3. Pre-flight checklist

Fill these into `application.properties` at the repository root, in this order, before the first
real-device enrolment. The file is read from the **working directory**, so start the server from that
directory (or pass another path as the first argument). In a container, set the matching `PASSKEY_*`
environment variable instead — every key below has one (see `DEPLOY.md` §5).

**Everything shipped in `application.properties` is an EXAMPLE.** The table's "Value" column says
what a real deployment must put there.

| # | Key | Value | How to tell it is wrong |
| --- | --- | --- | --- |
| 1 | `rpId` | `<RP_ID>` — the host serving the demo page and the association files | Startup line prints the wrong value. Any enrolment then dies in webauthn4j with `403 ATTESTATION_REJECTED` mentioning the origin or the rpIdHash — **before** any attestation check runs. Changing `rpId` later invalidates every passkey already enrolled. |
| 2 | `acceptedOrigins` | `https://<RP_ID>`. **Append the Android `android:apk-key-hash:…` origin as soon as the signing certificate is fixed** (§2.9), keeping the https one | An unparsable value refuses to boot. A missing entry shows up as a `403 ATTESTATION_REJECTED` naming the origin — on Android only, and before any attestation check runs. |
| 3 | `attestationPolicy` | **`strict`** — the right value for the attested demo. `demo` only for the browser walkthrough | `demo` → the boxed non-compliance banner at startup, `WARN DEMO MODE: …` on every browser enrolment, and `attested=false platform=web` in the audit line. Anything with `attested=false` is not part of the attested story. |
| 4 | `rpName` | whatever the platform prompt should read | Cosmetic only (shown in `publicKey.rp.name`). The file is read as UTF-8, so non-ASCII is safe. |
| 5 | `port` | `8099` (8080 is often taken) | Startup fails with a bind error, or you get connection refused. |
| 5a | `basePath` | `/api` by default; set it to the context path of the backend this server stands in for | The routes move with it (`<basePath>/rest/authentication/…`). A mismatch with the reverse-proxy `location` prefix is a 404 on every API call. |
| 6 | `androidPackageName` | `<PACKAGE_NAME>` | `403 ATTESTATION_REJECTED: … packageName [<what the device sent>] ist nicht erlaubt` — and that message names the correct value for you. |
| 7 | `androidSigningDigests` | lower-case hex SHA-256 of **debug key + upload key + Play App Signing cert** (§2.2), comma-separated | Empty → `WARN androidSigningDigests is empty - accepting signing certificate [<digest>] unchecked` (nothing is being verified). Wrong → `403 ATTESTATION_REJECTED: … Signaturzertifikat [<digest>] ist nicht erlaubt` — the message contains the digest you should have configured. |
| 8 | `iosAppIds` | `<TEAM_ID>.<BUNDLE_ID>,<TEAM_ID>.<BUNDLE_ID_RELEASE>` | `403 DEVICE_NOT_ELIGIBLE: … die App-ID der Attestierung ist nicht konfiguriert`. This one **cannot** tell you the right value — add both and read the App ID off the success line (§1.2). |
| 9 | `appAttestEnvironments` | `appattest,appattestdevelop` (both — TestFlight ignores the entitlement) | `403 DEVICE_NOT_ELIGIBLE: App-Attest-Umgebung <env> ist nicht erlaubt` — the message names the environment to add. |
| 10 | `allowSoftwareAttestationRoot` | **`false`** for the attested demo; `true` only while working with an emulator | `true` → `WARN accepting the AOSP software attestation root …` on every Android enrolment, and `securityLevel=software` in the audit line. If either appears in your demo run, the demo is not hardware-attested. |
| 11 | `verifiedBootPolicy` | `log` (see §2.7 before choosing `enforce`) | `log` → `WARN verifiedBootPolicy=log: deviceLocked=false verifiedBootState=…` means the phone is unlocked and you accepted it anyway. `enforce` → `403 DEVICE_NOT_ELIGIBLE: Bootloader entsperrt …`. |
| 12 | `adminToken` | anything but `change-me` | Hotline reset either works for anyone who guesses the default, or answers `401 {"errors":["TOKEN_INVALID"]}`. |
| 13 | `googleRootsUrl` / `googleStatusUrl` | the Google defaults, and the host must reach them **or** have `cache/` pre-warmed | `INFO Google attestation data: 0 root(s), 0 revocation entries` → every Android enrolment will fail. Healthy is `2 root(s), ~1700 revocation entries`. |

**What the shipped file gets wrong on purpose**, and must be fixed before any real-device run:

| Item | Shipped | Must become |
| --- | --- | --- |
| 6 `androidPackageName` | `com.example.passkeydemo` (EXAMPLE) | `<PACKAGE_NAME>` |
| 7 `androidSigningDigests` | *(empty — nothing is verified)* | the digests from §2.2 |
| 8 `iosAppIds` | `ABCDE12345.com.example.passkeydemo` (EXAMPLE) | `<TEAM_ID>.<BUNDLE_ID>` |
| 10 `allowSoftwareAttestationRoot` | `true` (emulators enrol) | `false` for the attested demo |
| 12 `adminToken` | `change-me` | anything else — the container refuses to boot otherwise |
| 2 `acceptedOrigins` | `https://passkeydemo.noxno.ch` | `https://<RP_ID>` plus the Android `apk-key-hash` origin (§2.9) |

### Domain-association keys — a separate, optional checklist

These four do **not** belong to the attested path and nothing above depends on them. Fill them in
only if the platform-passkey path (§0.1) is meant to work on `<RP_ID>`; leave them alone
otherwise. Nothing here can break an attested enrolment.

| Key | Shipped default | Value for a real deployment | How to tell it is wrong |
| --- | --- | --- | --- |
| `serveWellKnown` | `true` | `true` — both files served in strict **and** demo mode | `false` → boot line `serveWellKnown=false - … are NOT served, both answer 404`, and platform passkeys silently never appear |
| `appleTeamId` | `ABCDE12345` (EXAMPLE) | `<TEAM_ID>` | Only used to qualify `iosAppIds` entries that carry no team id. A mismatching prefix is published unchanged with a `WARN`, not rewritten |
| `iosAppIds` | one example App ID | reused from item 8 above — the same list feeds the AASA `webcredentials.apps` | empty → `WARN iosAppIds is empty - … publishes an EMPTY webcredentials.apps list` |
| `androidWebCredentialDigests` | *(empty; unset falls back to `androidSigningDigests`)* | **upload key + Play App Signing only — not the debug key** (§2.10) | both empty → `WARN … publishes an EMPTY sha256_cert_fingerprints list`; debug key present on a public host → anyone with a debug keystore can claim this domain's platform passkeys |

Boot lines that confirm the files are live:

```
INFO  serving /.well-known/apple-app-site-association as application/json for webcredentials apps
      [<TEAM_ID>.<BUNDLE_ID>, <TEAM_ID>.<BUNDLE_ID_RELEASE>]
INFO  serving /.well-known/assetlinks.json as application/json for android_app <PACKAGE_NAME>
      with 1 SHA-256 fingerprint(s) [AB:CD:EF:…:67:89]
```

`DEPLOY.md` §7a is the from-outside verification.

Then, before you touch a phone:

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
./gradlew test        # expect 62 tests: 56 passed, 6 skipped
./gradlew run
```

The startup lines are your first checkpoint — they echo the values everything else depends on:

```
INFO  WebAuthn verification: rpId=<RP_ID> attestationPolicy=strict acceptedOrigins=[https://<RP_ID>]
INFO  Google attestation data: 2 root(s), 1742 revocation entries
INFO  passkey reference server on http://localhost:8099/api/ (rpId=<RP_ID>, attestationPolicy=strict, acceptedOrigins=[https://<RP_ID>])
```

If instead you get a twelve-line boxed `## attestationPolicy=demo - THIS IS NOT A COMPLIANT
CONFIGURATION ##` banner, you are in demo mode. That banner is correct and you should not silence
it — but do not run the *attested* demo underneath it.

And the app must be pointed at the same server: its passkey base URL is
`https://<RP_ID><basePath>/` — with the shipped default, `https://<RP_ID>/api/` (trailing slash
required). Use `http://<host>:8099/api/` when talking to the reference server directly: it
terminates no TLS of its own, so a public `https://<RP_ID>` needs a reverse proxy in front.

On iOS, also confirm before the demo:

```bash
# whatever your project uses to (re)generate the entitlements file
cat ios/App/App/App.entitlements                                       # environment as intended
grep -c CODE_SIGN_ENTITLEMENTS ios/App/App.xcodeproj/project.pbxproj   # 2
# and check which bundle id the next build will actually use (§1.1)
```

### One-line diagnosis table

| Log line | What is wrong |
| --- | --- |
| `Google attestation data: 0 root(s), …` | No network to `android.googleapis.com` and no cache. Android is dead in the water. |
| `androidSigningDigests is empty - accepting signing certificate [x] unchecked` | Item 7 unset. Copy `x` into the property. |
| `Signaturzertifikat [x] ist nicht erlaubt` | Item 7 set, but not to the key that signed the installed app. Copy `x` in, or work out which of the three keys it is. |
| `packageName [x] ist nicht erlaubt` | Item 6 wrong. Should be `<PACKAGE_NAME>`. |
| `die App-ID der Attestierung ist nicht konfiguriert` | Item 8. The device's `TEAMID.bundleid` is not listed. |
| `App-Attest-Umgebung <env> ist nicht erlaubt` | Item 9. Add `<env>`. |
| `apple_validation_category_01=<n> ist … nicht erlaubt` | Production entitlement on a build that is neither TestFlight nor App Store. Rebuild with `--configuration development`. |
| `accepting the AOSP software attestation root …` | Item 10 is `true` and you are talking to an emulator. |
| `verifiedBootPolicy=log: deviceLocked=false …` | Unlocked bootloader, accepted because item 11 is `log`. |
| `Attestierungsformat none wird nicht akzeptiert (attestationPolicy=strict …)` | A **browser** reached the endpoint. See §0.2 — expected and unfixable; use the app. |
| `DEMO MODE: enrolling an UNATTESTED credential …` | Item 3 is `demo` and a browser enrolled. Fine for the ceremony walkthrough, never for the attested demo. |
| `der Passkey ist nicht gerätegebunden (BE/BS gesetzt)` | A synced platform passkey (iCloud Keychain / Google Password Manager) reached the endpoint instead of the app's own authenticator. |
| a `403 ATTESTATION_REJECTED` naming the **origin**, Android only | Item 2. The app sent `android:apk-key-hash:…` and `acceptedOrigins` does not list it (§2.9). |
| `attestationChallenge entspricht nicht dem clientDataHash` | Android client bug: the Keystore attestation challenge was not set to the WebAuthn `clientDataHash`. |
| `serveWellKnown=false - … are NOT served` | The two association files answer 404. Harmless for the attested path; platform passkeys cannot work (§0.1). |
| `iosAppIds is empty - … EMPTY webcredentials.apps list` | The AASA grants nothing. iOS will never offer a platform passkey for this host (§1.5). |
| `androidWebCredentialDigests and androidSigningDigests are both empty` | `assetlinks.json` grants nothing. Android platform passkeys fail **silently**, on the phone, with nothing in this log (§2.10). |
| `403 CEREMONY_EXPIRED` / `CEREMONY_CONSUMED` | More than `ceremonyTtlSeconds` (300) between `…/options` and `…/verify`, or a replay. On iOS, remember that a `serverUnavailable` retry is allowed **with the same challenge** — register ceremonies are consumed only on success. |
