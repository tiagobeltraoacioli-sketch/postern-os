// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern Container — DPC / managed-profile app shell (Postern Labs product).
// The "housing": a self-enrolled Device Policy Controller that provisions an
// Android managed profile (work profile) via ACTION_PROVISION_MANAGED_PROFILE.
//
// Builds a real debug APK with the Android SDK (`./gradlew :app:assembleDebug`);
// UNAUDITED · reference-prototype · never provisioned on hardware. `built ≠ booted`.
// See README.md for the build chain and the honest trust boundary.

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "PosternContainer"

// The SHARED, hardening-free managed-profile plumbing, extracted so Porog and
// NoporIS consume ONE DPC core (no second fork). It lives at the repo root
// (../../android-common), a sibling of android-container/, and is co-owned by the
// Porog A-lead and the NoporIS N-lead — changes to it require both to sign off.
include(":android-common")
project(":android-common").projectDir = file("../../android-common")

include(":app")
