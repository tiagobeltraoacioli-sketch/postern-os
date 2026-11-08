// SPDX-License-Identifier: MIT OR Apache-2.0
//
// NoporIS — persona MECHANISM app shell (Postern Labs product).
// The "bridge": a flavor selector (clean == Porog vs Google-Play persona) over the
// SHARED managed-profile DPC (`android-common/`, extracted from Porog by Dev N-common),
// plus persona lifecycle (provision / switch / destroy-this-world-only).
//
// SCAFFOLD: this project now COMPILES and its pure JVM unit tests pass on JDK 17 + a local
// Android SDK (platforms;android-34, build-tools;34.0.0). It is still
// DESIGN ONLY · UNAUDITED · reference-prototype · never provisioned or booted on hardware.
// See README.md for the honest trust boundary and COMMON-INTERFACE.md for the
// `android-common` contract this app consumes (it does NOT duplicate the DPC).

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

rootProject.name = "NoporIsPersona"

// The shared managed-profile DPC. Owned jointly by Dev N-lead + Porog A-lead, extracted
// from `android-container/` into `android-common/` by Dev N-common. This app CONSUMES it
// by dependency (see app/build.gradle.kts) and never forks it. `android-common` has
// landed (pre-box fix, Dev B / bucketA PARTITION.md: this was verified commented-out
// and blocking the first box-day `./gradlew`), so the include is live, matching Porog's
// equivalent settings.gradle.kts wiring.
include(":android-common")
project(":android-common").projectDir = file("../../android-common")

include(":app")
