# ProGuard/R8 rules for Postern Wallet.

# JNA (the UniFFI runtime) uses reflection + JNI; keep its classes intact.
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }

# UniFFI-generated bindings load native symbols by name via JNA — don't rename.
# Unified Postern SDK facade (crates/postern-sdk), migrated off uniffi.bloch_mobile.
-keep class uniffi.postern_sdk.** { *; }
