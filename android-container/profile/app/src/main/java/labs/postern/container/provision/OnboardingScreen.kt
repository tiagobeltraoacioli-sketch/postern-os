// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.provision

import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import labs.postern.common.profile.provision.ProvisioningResult
import labs.postern.container.R
import labs.postern.container.provision.ui.HonestyBanner
import labs.postern.container.provision.ui.PorogTheme
import labs.postern.container.provision.ui.ProvisioningResultCard
import labs.postern.container.provision.ui.SuspendResumeTile

/**
 * The "Create Porog" onboarding screen — the personal-profile threshold from which
 * the user provisions the hardened work profile.
 *
 * This is a **pure, stateless** composable: it takes UI state and emits callbacks,
 * so [ProvisioningActivity] owns all state and side effects (provisioning dispatch,
 * quiet-mode toggles) and the screen stays previewable and testable.
 *
 * ## What it renders (top to bottom)
 * 1. The mandatory [HonestyBanner] — hardened-not-anonymous, key-attested-device
 *    (not a measured-boot workspace), profile-owner-not-device-owner, sideload
 *    first, SCAFFOLD · UNAUDITED. Never softened, never dismissible.
 * 2. Title + honest framing of what a Porog actually is.
 * 3. The single one-tap **Create Porog** CTA → [onCreatePorog], which fires
 *    `ACTION_PROVISION_MANAGED_PROFILE` via the shared provisioning flow.
 * 4. Honest [ProvisioningResultCard] — **never** claims "ready" on `Dispatched`.
 * 5. The personal-side [SuspendResumeTile] (quiet mode), wired to Dev 1's
 *    `ContainerProfileManager.pauseContainer()` / `resumeContainer()`. Only shown
 *    when [containerExists] — before a container exists, suspend/resume is a
 *    meaningless affordance and would invite the user to tap a dead action.
 *
 * ## Status
 * SCAFFOLD · DESIGN ONLY · UNAUDITED. The one-tap consent flow is not
 * headless-scriptable, so its real behavior is **UNTESTED-until-VM/device** (device
 * / T2). Nothing here has been composed on screen — the macOS host has no SDK.
 *
 * @param containerExists whether a provisioned container is present (drives whether
 *   the Suspend/Resume tile renders at all). The caller derives this from a
 *   parent-context lifecycle read (see [ProvisioningActivity]); default `true`
 *   preserves prior previews/callers that don't yet track existence explicitly.
 */
@Composable
fun OnboardingScreen(
    provisioningState: ProvisioningUiState,
    suspendTileState: SuspendTileState,
    onCreatePorog: () -> Unit,
    onSuspend: () -> Unit,
    onResume: () -> Unit,
    modifier: Modifier = Modifier,
    suspendRequestFailed: Boolean = false,
    containerExists: Boolean = true,
) {
    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            HonestyBanner()

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = stringResource(R.string.onboarding_title),
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onBackground,
                )
                Text(
                    text = stringResource(R.string.onboarding_subtitle),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(R.string.onboarding_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onBackground,
                )
            }

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Button(
                    onClick = onCreatePorog,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(text = stringResource(R.string.onboarding_cta_create))
                }
                Text(
                    text = stringResource(R.string.onboarding_cta_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // Honest status. Idle renders as a quiet inline line; every other state
            // is a card whose copy never upgrades "dispatched" to "ready".
            if (provisioningState is ProvisioningUiState.Idle) {
                Text(
                    text = stringResource(R.string.onboarding_result_idle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                ProvisioningResultCard(state = provisioningState)
            }

            // Suspend/Resume only makes sense once a container exists to pause.
            if (containerExists) {
                SuspendResumeTile(
                    state = suspendTileState,
                    onSuspend = onSuspend,
                    onResume = onResume,
                    lastRequestFailed = suspendRequestFailed,
                )
            }
        }
    }
}

/**
 * The honest, UI-facing projection of a provisioning outcome.
 *
 * Deliberately mirrors the shared [ProvisioningResult] but adds an [Idle] starting
 * state and lives in the UI layer so the screen never has to reason about
 * `ActivityResult` codes. The mapping is [fromResult]; note that **`Dispatched` is
 * NOT a success state** — it means only that Android accepted the flow.
 */
sealed interface ProvisioningUiState {
    /** No provisioning has been requested yet. */
    data object Idle : ProvisioningUiState

    /** Android accepted `ACTION_PROVISION_MANAGED_PROFILE`. NOT "ready". */
    data object Dispatched : ProvisioningUiState

    /** The user backed out of the system provisioning screen. */
    data object Cancelled : ProvisioningUiState

    /** Honest dead-end — the platform cannot host a managed profile here. */
    data class Unsupported(val reason: String) : ProvisioningUiState

    /** The platform returned a non-OK result code. */
    data class Failed(val resultCode: Int) : ProvisioningUiState

    companion object {
        /** Project a shared [ProvisioningResult] into its honest UI state. */
        fun fromResult(result: ProvisioningResult): ProvisioningUiState = when (result) {
            is ProvisioningResult.Dispatched -> Dispatched
            is ProvisioningResult.Cancelled -> Cancelled
            is ProvisioningResult.Unsupported -> Unsupported(result.reason)
            is ProvisioningResult.Failed -> Failed(result.resultCode)
        }
    }
}

/**
 * Last-known quiet-mode state of the container, as reflected on the personal-side
 * tile. [UNKNOWN] is the honest default before any toggle and whenever the personal
 * side cannot read the profile — we never guess "running".
 */
enum class SuspendTileState { RUNNING, PAUSED, UNKNOWN }

@Preview(name = "Onboarding · idle (light)", showBackground = true)
@Preview(
    name = "Onboarding · idle (dark)",
    showBackground = true,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
private fun OnboardingScreenIdlePreview() {
    PorogTheme {
        OnboardingScreen(
            provisioningState = ProvisioningUiState.Idle,
            suspendTileState = SuspendTileState.UNKNOWN,
            onCreatePorog = {},
            onSuspend = {},
            onResume = {},
            containerExists = false,
        )
    }
}

@Preview(name = "Onboarding · dispatched", showBackground = true)
@Composable
private fun OnboardingScreenDispatchedPreview() {
    PorogTheme {
        OnboardingScreen(
            provisioningState = ProvisioningUiState.Dispatched,
            suspendTileState = SuspendTileState.RUNNING,
            onCreatePorog = {},
            onSuspend = {},
            onResume = {},
            containerExists = true,
        )
    }
}
