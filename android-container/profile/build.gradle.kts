// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Root build file for the Postern Container DPC app shell.
// UNAUDITED · never provisioned on hardware. Builds a real debug APK on any host
// with the Android SDK (android-34 + build-tools 34.0.0) and a JDK 17.
//
// Plugin VERSIONS are declared ONCE here via the version catalog
// (gradle/libs.versions.toml, owned by Dev 5) and applied `false`; the :app and
// :android-common modules apply them without re-stating a version.

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
