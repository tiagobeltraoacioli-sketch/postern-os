// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Root build file for the NoporIS persona app shell.
// SCAFFOLD · DESIGN ONLY · UNAUDITED · compiles + unit-tests green on JDK 17 + local Android
// SDK, but never provisioned or booted on hardware.
//
// Plugin versions come from the `libs` version catalog (gradle/libs.versions.toml):
// AGP 8.5.0 / Kotlin 1.9.24 — the same pins as Porog and the wallet.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
