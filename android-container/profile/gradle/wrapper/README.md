<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Gradle wrapper — jar materialization (deferred-to-VM)

`gradle-wrapper.jar` is a **binary** artifact and is intentionally NOT committed by
this macOS-authored scaffold (no Gradle here to emit or verify it, and we do not
hand-fabricate binaries). The text wrapper (`gradle-wrapper.properties`, `gradlew`,
`gradlew.bat`) is authored and VM-ready; the jar is materialized once, on the Nix
VM, on first setup:

```bash
# Inside the devshell (nix develop ../../toolchain), from android-container/profile/:
gradle wrapper --gradle-version 8.9 --distribution-type bin
# → writes gradle/wrapper/gradle-wrapper.jar to match gradle-wrapper.properties.
```

After that, `./gradlew :app:assembleDebug` works offline against the pinned
distribution. `built ≠ booted`: producing an APK proves nothing is provisioned —
that is the T1 harness's job (`../../test/e2e/provision-lifecycle.sh`), and it is
`UNTESTED-until-hardware` until it runs on the KVM emulator / a device.
