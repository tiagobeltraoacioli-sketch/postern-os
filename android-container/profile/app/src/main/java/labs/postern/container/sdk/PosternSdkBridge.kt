// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.sdk

/**
 * The **A↔B seam**: the only surface across which this DPC/provisioning shell
 * touches the Rust cores. Per the design, exactly **one** FFI surface ships —
 * `crates/postern-sdk` (`cdylib`, a single `uniffi::setup_scaffolding!`) — loaded
 * on the Kotlin side as `libpostern_sdk.so` via JNA, with generated bindings under
 * `uniffi.postern_sdk.*`.
 *
 * - **Dev-B** owns the facade internals, the `cargo ndk` build, and the generated
 *   bindings. **Dev A** consumes only this thin bridge.
 * - This DPC *shell* deliberately embeds **no** cores — the wallet/messenger/vault
 *   workspace apps that actually call `libpostern_sdk.so` run **inside** the
 *   provisioned managed profile. The bridge exists so the housing can report SDK
 *   availability without depending on Dev-B's build being present.
 *
 * Ships as an interface + a NO-OP stub. **Scaffolding to the interface; not an
 * implementation.** DESIGN ONLY · UNAUDITED · never run on a device.
 */
interface PosternSdkBridge {

    /**
     * Whether `libpostern_sdk.so` + its generated bindings are present and
     * loadable in this process. The scaffold reports honestly (the stub says
     * `false`) rather than assuming the native lib is bundled.
     */
    fun isAvailable(): Boolean

    /**
     * The facade version string, once loaded. `null` when unavailable. A real
     * bridge reads this from the generated `uniffi.postern_sdk` surface.
     */
    fun facadeVersion(): String?

    companion object {
        /** The NO-OP stub used until Dev-B's native lib + bindings are wired in. */
        val NoOp: PosternSdkBridge = object : PosternSdkBridge {
            override fun isAvailable(): Boolean = false
            override fun facadeVersion(): String? = null
        }
    }
}
