// Root build script — plugin versions only; modules apply them.
// Versions come from the `libs` version catalog (gradle/libs.versions.toml):
// AGP 8.5.0 / Kotlin 1.9.24, aligned with Porog and NoporIS (was 8.5.2 inline —
// the catalog is now the single pin per the A1/A10 infra spec).
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
