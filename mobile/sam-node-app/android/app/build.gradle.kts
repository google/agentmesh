import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
    id("com.google.gms.google-services")
    id("com.google.devtools.ksp")
}

// Release (Play upload) signing: android/key.properties for a workstation,
// ANDROID_KEYSTORE_* environment variables for CI. Both are git-ignored /
// never committed; when neither is present the build falls back to the debug
// key so `flutter run --release` and local APKs keep working.
val keystoreProperties = Properties().apply {
    val f = rootProject.file("key.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun signingValue(propertyKey: String, envKey: String): String? =
    keystoreProperties.getProperty(propertyKey)?.takeIf { it.isNotBlank() } ?: System.getenv(envKey)?.takeIf { it.isNotBlank() }

val releaseStoreFile = signingValue("storeFile", "ANDROID_KEYSTORE_PATH")
val releaseStorePassword = signingValue("storePassword", "ANDROID_KEYSTORE_PASSWORD")
val releaseKeyAlias = signingValue("keyAlias", "ANDROID_KEY_ALIAS")
val releaseKeyPassword = signingValue("keyPassword", "ANDROID_KEY_PASSWORD")
val hasReleaseSigning = listOf(releaseStoreFile, releaseStorePassword, releaseKeyAlias, releaseKeyPassword).all { it != null }

android {
    namespace = "dev.sammesh.connect"
    compileSdk = 37 // Keep as 37, Gradle usually maps this correctly, but let's check if it needs to be 37
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "dev.sammesh.connect"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // Only ABIs that have a libsam.so (see the Makefile jnilibs targets)
        // may be packaged. Plugin AARs (ML Kit, JNA, CameraX) ship
        // armeabi-v7a natives too; without this filter Play lists that ABI
        // as supported and serves the app to 32-bit devices, where it dies
        // opening the FFI library. Requires disable-abi-filtering=true in
        // gradle.properties, or the Flutter plugin overrides the list.
        ndk {
            abiFilters.clear()
            abiFilters.addAll(listOf("arm64-v8a", "x86_64"))
        }
    }

    buildTypes {
        release {
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.maybeCreate("release").apply {
                    // Relative storeFile paths resolve against android/, where key.properties lives.
                    storeFile = rootProject.file(releaseStoreFile!!)
                    storePassword = releaseStorePassword
                    keyAlias = releaseKeyAlias
                    keyPassword = releaseKeyPassword
                }
            } else {
                logger.warn("No release signing configured (android/key.properties or ANDROID_KEYSTORE_*); signing release with the debug key.")
                signingConfig = signingConfigs.getByName("debug")
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
        // Kotlin 2.4 defaults the module name to "{group}:{project}"; the
        // appfunctions compiler names a generated class after it, and ':'
        // is not legal in an identifier.
        moduleName = "sam_node_app"
    }
}

flutter {
    source = "../.."
}

ksp {
    arg("appfunctions:aggregateAppFunctions", "true")
}

dependencies {
    val appFunctionsVersion = "1.0.0-alpha09" // alpha10 seems missing or restricted

    implementation("androidx.appfunctions:appfunctions:$appFunctionsVersion")
    implementation("androidx.appfunctions:appfunctions-service:$appFunctionsVersion")
    ksp("androidx.appfunctions:appfunctions-compiler:$appFunctionsVersion")

    // JNA for calling Go C exports
    implementation("net.java.dev.jna:jna:5.19.1@aar")
}
