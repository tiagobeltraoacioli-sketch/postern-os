// Postern Wallet — Android app shell (Postern Labs product).
// A light client / wallet for the ownerless Bloch-SIS-PoW protocol.
//
// SKELETON: this project is NOT built in this repo (needs the Android SDK).
// See README.md for the build chain (cargo-ndk + uniffi-bindgen → bindings + .so).

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

rootProject.name = "PosternWallet"
include(":app")
