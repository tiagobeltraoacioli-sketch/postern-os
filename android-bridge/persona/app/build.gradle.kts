// SPDX-License-Identifier: MIT OR Apache-2.0
//
// NoporIS — persona MECHANISM app shell (Postern Labs product).
// SCAFFOLD · DESIGN ONLY · UNAUDITED · never provisioned on hardware.
//
// This app is Porog's DPC + (flavor selector, single-slot orchestration, persona
// lifecycle). It CONSUMES the shared DPC via `:android-common` and must NOT re-implement
// managed-profile provisioning/lifecycle. See ../COMMON-INTERFACE.md.
//
// Versions come from the single catalog gradle/libs.versions.toml, mirroring Porog's
// android-container/profile/gradle/libs.versions.toml (bucketA/PARTITION.md, Dev B).

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "labs.postern.persona"
    compileSdk = 34

    defaultConfig {
        applicationId = "labs.postern.persona"

        // API 30 (Android 11) floor: same as Porog's DPC — managed-profile provisioning
        // and per-profile policy are stable from R onward. We gate provisioning at
        // RUNTIME via the shared ProvisioningPreflight + single-slot resolver, never by
        // SDK level. Private Space (Android 15+) is the design's fallback where the
        // one-profile constraint bites; it is NOT this app's mechanism (see README §slot).
        minSdk = 30
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-design"

        // T1 harness: the (pending) instrumented persona-lifecycle test runs INSIDE
        // the provisioned persona via `am instrument --user <id>`, same pattern as
        // Porog's ProfileLifecycleE2ETest. Standard AndroidX test runner.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            // Real release channel is F-Droid + a signed direct APK (Play is a poor fit
            // for the DPC provisioning APIs; the Play *persona* uses Play natively — do
            // not conflate the bridge app with the persona). Signing config intentionally
            // absent — scaffold, not a shippable build.
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
        // Match the Kotlin compiler via the catalog (Compose ↔ Kotlin compat table) —
        // same source of truth as Porog, instead of a second hardcoded "1.5.14".
        kotlinCompilerExtensionVersion = libs.versions.composeCompiler.get()
    }
}

dependencies {
    // THE shared managed-profile DPC (provisioning + lifecycle + lockdown + seams),
    // extracted from Porog by Dev N-common. `android-common` now lands as a live
    // `include(":android-common")` in settings.gradle.kts (bucketA/PARTITION.md pre-box
    // fix, Dev B) — this project reference is no longer a scaffold placeholder.
    implementation(project(":android-common"))

    // Minimal Compose surface for the "two worlds" switcher / provisioning entry.
    // Routed through the version catalog (gradle/libs.versions.toml) so Porog and
    // NoporIS share exactly one set of pins — no second hardcoded version drifting
    // out from under the catalog.
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    // Window/splash theme named in AndroidManifest.xml (Theme.Material3.DayNight.NoActionBar).
    // Compose renders its own MaterialTheme; this only resolves the pre-Compose window theme.
    implementation(libs.material)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)

    implementation(libs.kotlinx.coroutines.android)

    // Pure-logic unit tests (fail-closed flavor parsing + single-slot resolution +
    // cross-profile bearer screening). These are Android-free by construction so they run
    // on a plain JVM via :app:testDebugUnitTest — and the app as a whole now assembles
    // (:app:assembleDebug) on JDK 17 + a local Android SDK.
    testImplementation(libs.junit)

    // ── T1 instrumented harness deps — deferred-to-VM ─────────────────────────
    // Wired so an instrumented `androidTest` source set resolves the moment it lands
    // (mirrors Porog's androidTestImplementation block exactly, same catalog bundle).
    // HONEST GAP (bucketA/PARTITION.md, Dev B scope is build files only): as of this
    // commit there is no `app/src/androidTest/` Kotlin in this repo for NoporIS yet —
    // that source (the fleet2-reconciled persona-lifecycle instrumented test, UI-bridge
    // devs' file, analogous to Porog's ProfileLifecycleE2ETest) has not landed. These
    // dependencies make the build ready to consume it the moment it does; they do not
    // fabricate the test itself.
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.bundles.androidTest)
    androidTestImplementation(libs.junit)

    // NOTE: no postern-sdk / JNA dependency here — same as Porog's DPC. Cores load through
    // the one UniFFI facade (Dev-B) via the PosternSdkBridge seam (NoOp), inside the
    // provisioned persona, never in this housing.
}
