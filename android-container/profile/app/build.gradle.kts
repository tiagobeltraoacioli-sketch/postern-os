// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern Container — DPC / managed-profile app shell (Postern Labs product).
// UNAUDITED · never provisioned on hardware. `built ≠ booted`.
//
// Versions come from the single catalog gradle/libs.versions.toml (Dev 5 owns
// it). `./gradlew :app:assembleDebug` now builds a real debug APK on any host
// with the Android SDK (android-34 + build-tools 34.0.0) and a JDK 17 — the Nix
// devshell (toolchain/flake.nix) is one such host, no longer the only path.
// `build-and-verify.sh` assembles then asserts the DeviceAdminReceiver + SDK levels.

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "labs.postern.container"
    compileSdk = 34

    defaultConfig {
        applicationId = "labs.postern.container"

        // API 30 (Android 11) floor: managed-profile provisioning + per-profile
        // policy (setPermittedInputMethods, always-on lockdown VPN) are stable and
        // well-behaved from R onward, and StrongBox (API 28) is available. We gate
        // provisioning at RUNTIME via isProvisioningAllowed(...) regardless — never
        // assume the platform supports a managed profile.
        minSdk = 30
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-design"

        // T1 harness: the instrumented ProfileLifecycleE2ETest runs INSIDE the
        // provisioned profile via `am instrument --user <id>` (see
        // test/e2e/provision-lifecycle.sh). Standard AndroidX test runner.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // A real release channel is F-Droid + a signed direct APK (Play is a poor
            // fit for the DPC provisioning APIs). Signing config is intentionally
            // absent — this is a scaffold, not a shippable build.
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }
    composeOptions {
        // Match the Kotlin compiler via the catalog (Compose ↔ Kotlin compat table).
        kotlinCompilerExtensionVersion = libs.versions.composeCompiler.get()
    }

    sourceSets {
        getByName("test") {
            // The committed kernel golden vectors (apps/porog-crossprofile/
            // golden-vectors.json, emitted by export-vectors.mjs) land on the
            // unit-test classpath so CrossProfileReconcilerParityTest pins the ONE
            // Kotlin decision port to the ONE authoritative .mjs kernel — a single
            // committed copy of the truth, never a second drift-prone copy under
            // src/test/resources. (rootDir = android-container/profile, so ../../
            // is the repo root.)
            resources.srcDir(rootProject.file("../../apps/porog-crossprofile"))
        }
    }
}

dependencies {
    // The SHARED managed-profile plumbing: provisioning + lifecycle + the DPC
    // skeleton. Porog is a thin consumer that subclasses the abstract seams and
    // adds ONLY its hardening (LockdownPolicy). NoporIS consumes the same module.
    implementation(project(":android-common"))

    // Minimal Compose surface for the "Create Postern Container" onboarding screen.
    implementation(platform(libs.compose.bom))
    implementation(libs.bundles.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    // Coroutines for off-main-thread DevicePolicyManager / keystore work.
    implementation(libs.kotlinx.coroutines.android)

    // ── Host unit tests (plain JVM; `./gradlew :app:testDebugUnitTest`) ──────
    // CrossProfileReconcilerParityTest replays the committed kernel golden
    // vectors through the single Kotlin decision port; WorkChallengePolicyGuardTest
    // guards the work-challenge prompt gate. junit was previously missing here
    // entirely (src/test could not even compile). The real org.json resolves
    // AHEAD of the mockable android.jar so the pure decide() runs on the JVM.
    testImplementation(libs.junit)
    testImplementation(libs.org.json)

    // ── T1 functional harness (ProfileLifecycleE2ETest) — deferred-to-VM ─────
    // Instrumented, runs as profile-owner inside the managed profile. It honestly
    // SKIPS (assumeTrue) when not run inside a provisioned profile, so a green
    // pipeline off-device never implies device-proven.
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.bundles.androidTest)
    androidTestImplementation(libs.junit)

    // NOTE: no postern-sdk / JNA dependency here. The Rust cores load through the
    // one UniFFI facade (Dev-B owns it); this DPC shell consumes only the thin
    // PosternSdkBridge seam and ships a NO-OP stub. Wallet/workspace apps that
    // actually embed libpostern_sdk.so (built by cargo-ndk against the NDK pinned
    // in the catalog) live inside the provisioned profile.
}
