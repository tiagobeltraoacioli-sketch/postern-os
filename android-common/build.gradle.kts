// SPDX-License-Identifier: MIT OR Apache-2.0
//
// android-common — the SHARED, hardening-free managed-profile plumbing.
//
// This is the generic AOSP managed-profile (work-profile) provisioning +
// lifecycle core, extracted from Porog's DPC so that BOTH Porog (the hardened
// "door") and NoporIS (the dual-persona "bridge") consume ONE implementation
// instead of forking a second Device Policy Controller. It contains NO hardening
// and NO product branding — the lockdown baseline stays in the Porog app; the
// NoporIS persona flavors live in the NoporIS app. Each consumer subclasses the
// abstract seams here.
//
// This module only *calls* Android platform APIs (DevicePolicyManager,
// DeviceAdminReceiver, ComponentActivity). It redistributes NO AOSP source and
// bundles NO Google Mobile Services. "Android" is used nominatively only.
//
// SCAFFOLD · DESIGN ONLY · UNAUDITED · reference-prototype · never provisioned on
// hardware. Consumed as a Gradle module by each product's settings.gradle.kts;
// it carries no plugin versions of its own (the consuming project's
// pluginManagement supplies them).

// Plugins are applied WITHOUT a version on purpose: this module is a subproject of
// whichever product build includes it (Porog's ../settings.gradle.kts, or NoporIS's),
// and that parent puts AGP + Kotlin on the build classpath (Porog does so via the
// version catalog's `apply false` block). Keeping `id(...)` version-less here means
// android-common stays consumable by BOTH products without forking. Dependency
// COORDINATES, however, come from the single catalog `libs` (Dev 5 owns it).
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "labs.postern.common"
    compileSdk = 34

    defaultConfig {
        // Same API 30 (Android 11) floor as the Porog app shell: managed-profile
        // provisioning + per-profile policy are stable from R onward. Provisioning
        // is still gated at RUNTIME via isProvisioningAllowed(...) — never assume
        // the platform supports a managed profile by SDK level alone.
        minSdk = 30
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // ComponentActivity + the ActivityResult APIs used by the abstract
    // ManagedProfileProvisioningActivity. `api` because ComponentActivity is the
    // public superclass of that abstract Activity, so consumers subclass against
    // it. Non-Compose: consumers that want a Compose onboarding UI add Compose in
    // their own module.
    api(libs.androidx.activity)
    // @WorkerThread on the profile-scoped wipe.
    implementation(libs.androidx.annotation)
    // Off-main-thread DevicePolicyManager / keystore work in consumers.
    implementation(libs.kotlinx.coroutines.android)

    // ── Host unit tests (plain JVM: `./gradlew :android-common:testDebugUnitTest`) ──
    // ManagedProfileStateMachineTest exercises the pure deriveState() decision on the
    // JVM (no device/emulator/mock). junit comes from the SAME single catalog
    // (gradle/libs.versions.toml) the Porog app and T1 harness use — one source of
    // truth for versions, never a second fork. Without this the shared module's test
    // source set could not compile, so the pure-JVM DPC suite was only partly green.
    testImplementation(libs.junit)
}
