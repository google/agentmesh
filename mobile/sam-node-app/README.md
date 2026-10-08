# SAM Connect (Android)

This folder contains a Flutter application that packages and runs the native Go-based `sam-node` mesh client on Android using Go's CGO compiler and Dart FFI (Foreign Function Interface).

SAM Connect currently supports Android only. The repository has an iOS FFI
library build target, but no iOS app project or release.

For manual testing, follow the [Android tester tutorial](../../site/content/docs/preview/mobile.md#android-tester-tutorial).
Choose browser enrollment on `https://bananas.sam-mesh.dev` or
`https://hub.sam-mesh.dev`, or scan the QR code from your own `sam-one` mesh.
Both paths include connection checks and instructions for reporting failures.

---

## Architecture Overview

The app compiles the core Go mesh networking and routing logic into a C-compatible shared library (`.so`), which is loaded dynamically by the Dart runtime. The Dart GUI manages the lifecycle of the node (enrollment, start, stop) via FFI function calls, while any tool registration, discovery, or mesh API queries are sent via standard HTTP JSON-RPC to the local loopback port of the node's sidecar server.

---

## Prerequisites

Before building the application, ensure you have configured:
1. **Flutter SDK**: Installed and configured (run `flutter doctor` to verify).
2. **Go Compiler**: Version 1.26+ installed.
3. **Android NDK**: Required to cross-compile the Go library for Android platforms. Ensure the `ANDROID_NDK_HOME` environment variable points to your NDK installation.

Android DNS bootstrap addresses (`/dnsaddr/...`) require Android 10 or newer.
The mobile client resolves their TXT records through Android's native resolver,
which uses the device's network and private DNS configuration. Older Android
versions can still use explicit router IP addresses.

---

## Compilation Instructions

To build the app, you must first compile the Go FFI library and bundle it inside the Flutter project:

### 1. Compile FFI Library

Run one of the following from the **repository root directory**. The `mobile-ffi-*` targets only build into `bin/`; the `cp` step puts the library where the Flutter project loads it from. (`make mobile-app-apk` and `make mobile-app-apk-emulator` do build, copy and release APK in one go.)

*   **For Android ARM64 (physical phones, and emulators on Apple Silicon hosts)**:
    ```bash
    make mobile-ffi-android
    mkdir -p mobile/sam-node-app/android/app/src/main/jniLibs/arm64-v8a
    cp bin/android/libsam.so mobile/sam-node-app/android/app/src/main/jniLibs/arm64-v8a/
    ```

*   **For Android x86_64 emulators (Intel and Linux hosts)**:
    ```bash
    make mobile-ffi-android-x86_64
    mkdir -p mobile/sam-node-app/android/app/src/main/jniLibs/x86_64
    cp bin/android-x86_64/libsam.so mobile/sam-node-app/android/app/src/main/jniLibs/x86_64/
    ```

### 2. Run the App

Connect your device or start your emulator, then run:
```bash
cd mobile/sam-node-app
flutter run
```

### 3. Publishing to Google Play

Google Play takes an Android App Bundle (`.aab`) signed with an **upload key**; it rejects the debug key that `make mobile-app-apk` falls back to. Set the key up once:

1.  Create the upload keystore outside the repository (`*.jks` and `key.properties` are git-ignored anyway, but keep it out of the tree). `keytool` prompts for the passwords, so they never appear in a shell history:
    ```bash
    keytool -genkey -v -keystore ~/upload-keystore.jks -keyalg RSA -keysize 2048 -validity 10000 -alias upload
    ```
    Back the file up: with [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756) Google holds the app signing key and this is only the upload key, but losing it still means a key-reset request.
2.  Tell Gradle where it is, in `mobile/sam-node-app/android/key.properties`:
    ```properties
    storeFile=/home/you/upload-keystore.jks
    storePassword=...
    keyAlias=upload
    keyPassword=...
    ```
    CI uses the equivalent environment variables instead of a file: `ANDROID_KEYSTORE_PATH`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`.
3.  Build from the repository root:
    ```bash
    make mobile-app-bundle MOBILE_BUILD_NAME=1.2.3 MOBILE_BUILD_NUMBER=42
    ```
    The bundle lands in `mobile/sam-node-app/build/app/outputs/bundle/release/app-release.aab`. `MOBILE_BUILD_NAME`/`MOBILE_BUILD_NUMBER` override the `version: X.Y.Z+N` in `pubspec.yaml`; Play refuses a `versionCode` (`N`) it has already seen, so bump it on every upload.
4.  Upload the `.aab` in the Play Console (**Release → Testing/Production → Create new release**).

#### From CI

The **Mobile App** workflow ([`.github/workflows/mobile.yml`](../../.github/workflows/mobile.yml)) builds the APK and, when the upload key is configured, the bundle:

*   **On every `mobile/v*` tag**, the app's own release cycle, independent of the mesh (`v*`) and SDK (`sdk/*/v*`) tags; the workflow creates a GitHub release for the tag with both artifacts attached, the tag supplies the version name.
*   **On demand** (**Actions → Mobile App → Run workflow**) from any branch or tag. Pick a Google Play **track** (`internal`, `alpha`, `beta`, `production`) to publish the bundle after the build, or leave `none` to only build; the APK and `.aab` are always available as run artifacts. `build_number` overrides the versionCode, which otherwise is the workflow run number.

Repository secrets for signing: `ANDROID_KEYSTORE_BASE64` (`base64 -w0 upload-keystore.jks`), `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD` — the values you chose when running `keytool` above. Without them the APK is debug-signed and the bundle is skipped. `GOOGLE_SERVICES_JSON_BASE64` is the base64 of the `google-services.json` downloaded from the Firebase Console (*Project settings → Your apps → dev.sammesh.connect*); without it the build uses the dummy template and Firebase features fail at runtime.

Publishing is keyless: [`hack/publish-play.sh`](../../hack/publish-play.sh) drives the Play Developer API with a short-lived token minted through Workload Identity Federation from the repository variables `WIF_PROVIDER_NAME_APP_STORE` and `SERVICE_ACCOUNT_EMAIL_APP_STORE`. That service account must be invited in **Play Console → Users and permissions** with *Release to production / testing tracks* rights on the app, and the very first release of a new app still has to go through the console (the API cannot create the app listing).

---

## How to Use the Application

Once launched, the app (installed as **SAM Connect**, application id `dev.sammesh.connect`) asks you to enroll, then shows the dashboard:

1.  **Scan enrollment code**: The primary path. `sam-one` prints a single-use `sam://enroll?server=...&token=...` QR code at startup (and on demand with `sam-one token qr`); scan it, confirm the control plane hostname, and the app enrolls through `POST /enroll` with no identity provider involved. The phone's stock camera app can scan it too: the `sam://` link opens SAM Connect. Only `https://` control planes are accepted (plaintext `http://` for loopback only), because the control plane is the device's trust root. See [Your own mesh](../../site/content/docs/getting-started/your-own-mesh.md).
2.  **Enter details manually**: Paste a whole `sam://enroll` link or a bare bootstrap token together with the **Control plane URL**, then **Join with token**. On a full control plane, mint the token with `POST /admin/bootstrap-tokens` (see `development/kind/run-local-node.sh`); on `sam-one`, `sam-one token create`. Below it, **Login & Enroll (Browser)** and **Device Login** are the OIDC alternatives: the app reads the issuer from the control plane's `/info` endpoint and opens a login.
3.  **Local API Token**: The bearer token that secures the local sidecar REST API. It is generated on first launch and kept in the app's private storage; view, copy or regenerate it on the **Config** tab. There is no default: Android loopback is shared by every installed app, so a fixed value would let any of them act as this node.
4.  **Labels**: Set on the **Config** tab *before* enrolling; they are attested into the node's Biscuit at that point.
5.  **Start Node**: Launches the Go node runtime in the background. It will bind its local MCP sidecar to `127.0.0.1:5005`.
6.  **Stop Node**: Gracefully shuts down the background Go mesh client.

---

---

## Features & New Capabilities

### 📱 1. Embedded MCP Server & Real Telemetry
The app now includes an embedded Dart MCP server that exposes real-time telemetry from the device:
*   **Battery Status**: Level and charging state.
*   **Location**: Coarse/Fine coordinates (requires permissions).
*   **Foreground Service**: Keeps the node alive and connected even when the phone is idle or backgrounded (Android 14+ compatible).

### 🤖 2. Android 16 AppFunctions (On-Device MCP)
Exposes capabilities directly to the OS registry, allowing native assistants (like Gemini) to orchestrate tasks without manual app navigation.
*   `getMeshStatus`: Returns node stats and connected peers.
*   `callRemoteMeshTool`: Proxy to invoke tools on remote mesh peers.

---

## How to Use the Application

### 📸 Screenshots

| Node Status / Dashboard | Services & Telemetry |
|:---:|:---:|
| ![Node Logged](../../site/static/images/mobile_node_logged.png) | ![Services Enabled](../../site/static/images/mobile_services_enabled.png) |

1.  **Dashboard Tab**: Displays current status, Node ID, connected peers, and DHT size.
2.  **Services Tab**: Allows enabling/disabling embedded sensors (Battery/Location) and bridging external local MCP servers.
3.  **Config Tab**: The node's labels and attenuation, the app's stand-in for `sam-node.yaml`. Labels (comma-separated `key=value`) are set here; the control plane attests them into the node's Biscuit at enrollment, so changing them later means pressing Re-enroll, which re-attests them with the login session saved at enrollment (the browser opens only if that session has expired) and keeps the node's identity. A node that joined with a token or QR code has no login session and the control plane re-mints from the labels already on record, so Re-enroll is disabled for it: unenroll and join again with the new labels. Attenuation is Datalog rules, policies and checks that limit who may call this node, one statement per line (e.g. `check if label("region", "eu-west-1");`). They are read when the node starts, and a syntax error fails the start. Same syntax and same errors as the `attenuation` block of `sam-node.yaml`; see [Node configuration](../../site/content/docs/reference/node-config.md#attenuation).

---

## Developer Integration & Usage Examples

### Option 1: CLI Usage (Technical Verification)

You can query the phone's telemetry from a remote machine (or another node) using the repository's `mcp-client` utility.

1.  **Discover tools on the remote phone service**:
    ```bash
    # Query the local SAM node proxy for tools hosted by the phone-sensors peer
    # (-token is your own node's API token, not the phone's)
    go run cmd/mcp-client/main.go \
      -url "http://localhost:8080/sam/<PHONE_PEER_ID>/mcp/phone-sensors" \
      -token "$(cat ~/.config/sam-mesh/api-token)" \
      -list
    ```
    *Output:*
    *   `get_battery_status`: Returns the current battery level and charging status of the device.
    *   `get_location`: Returns the approximate location of the device, rounded to about a kilometre.

2.  **Query the location**:
    ```bash
    go run cmd/mcp-client/main.go \
      -url "http://localhost:8080/sam/<PHONE_PEER_ID>/mcp/phone-sensors" \
      -token "$(cat ~/.config/sam-mesh/api-token)" \
      -tool "get_location"
    ```
    *Output:* `{"latitude": 42.28, "longitude": -8.61, "precision_km": 1}`

---

### Option 2: AI Agent Interaction Flow

Clean, successful flow of an AI agent discovering and querying the mesh.

| Step | Action | Details / Tool | Result |
|---|---|---|---|
| 1 | Discover Peers & Tools | `find_remote_tools` | Found peer `<PHONE_PEER_ID>` hosting service `phone-sensors` with tool `mcp://phone-sensors/get_location`. |
| 2 | Verify Schema | `describe_remote_tool` | Confirmed `get_location` requires no input parameters: `{"input_schema": {"type": "object", "properties": {}}}`. |
| 3 | Query Location | `call_remote_tool` | Received: `{"latitude": 42.2805588, "longitude": -8.6124088}` |
| 4 | Resolve Address | Web Search | Geolocated to Vigo / Redondela area, Galicia, Spain. |
