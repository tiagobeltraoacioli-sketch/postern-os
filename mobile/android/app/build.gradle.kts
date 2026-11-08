plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "labs.postern.wallet"
    compileSdk = 34

    defaultConfig {
        applicationId = "labs.postern.wallet"
        minSdk = 28          // API 28 (Android 9) — first release with StrongBox (setIsStrongBoxBacked).
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // The UniFFI-generated Kotlin loads `libpostern_sdk.so` via JNA; ship one
        // per ABI under app/src/main/jniLibs/<abi>/ (see README — cargo ndk output).
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
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
        // Match the Kotlin 1.9.24 compiler (see the Compose ↔ Kotlin compat table).
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // Jetpack Compose (BOM pins the mutually-compatible versions).
    implementation(platform("androidx.compose:compose-bom:2024.06.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.4")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // HTTP to the node JSON-RPC endpoint (NodeRpc.kt).
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Kotlin coroutines (ViewModel scope, off-main-thread RPC + keystore work).
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // UniFFI runtime: the generated `postern_sdk.kt` uses JNA to bind libpostern_sdk.so.
    // (uniffi's Kotlin backend depends on net.java.dev.jna.) Add the AAR variant
    // so the native JNA dispatcher is bundled for Android.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
