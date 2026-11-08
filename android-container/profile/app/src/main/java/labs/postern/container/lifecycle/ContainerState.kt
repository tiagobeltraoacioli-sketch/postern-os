// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.lifecycle

import labs.postern.common.profile.lifecycle.ManagedProfileState

/**
 * The lifecycle states of the Postern Container (an Android managed profile).
 *
 * The states themselves are the generic, shared [ManagedProfileState]
 * (android-common); `ContainerState` is Porog's name for that same set —
 * `ABSENT / UNSUPPORTED / PROVISIONING / ACTIVE / WIPED`. Kept as a typealias so
 * Porog code and docs keep their "container" vocabulary while both products read
 * one shared state model.
 *
 * DESIGN ONLY · UNAUDITED · reference-prototype. State is derived from platform
 * facts (DevicePolicyManager profile-owner status, provisioning-allowed checks),
 * never persisted as ground truth — the OS is authoritative.
 */
typealias ContainerState = ManagedProfileState
