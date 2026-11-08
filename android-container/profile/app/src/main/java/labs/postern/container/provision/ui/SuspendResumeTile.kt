// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.provision.ui

import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import labs.postern.container.R
import labs.postern.container.provision.SuspendTileState

/**
 * Personal-side **Suspend / Resume** tile — the whole-container quiet-mode toggle.
 *
 * Quiet mode (`UserManager.requestQuietModeEnabled`) is a **parent/personal-context**
 * action, so it lives on this personal-profile onboarding screen, not inside the
 * profile. Tapping the button calls Dev 1's
 * `ContainerProfileManager.pauseContainer()` / `resumeContainer()`.
 *
 * ## Honesty
 * The tile shows the **last action taken**, not a live cross-profile read: from the
 * personal side we cannot fully see into the profile we own, and the OS is
 * authoritative for quiet mode. That caveat is on the tile, always. When the state
 * is [SuspendTileState.UNKNOWN] the label says so rather than guessing "running".
 *
 * ## Status
 * SCAFFOLD · DESIGN ONLY · UNAUDITED. The button's real effect is
 * **UNTESTED-until-VM/device** (quiet mode needs a provisioned profile on an
 * emulator/hardware; the macOS host cannot run it).
 */
@Composable
fun SuspendResumeTile(
    state: SuspendTileState,
    onSuspend: () -> Unit,
    onResume: () -> Unit,
    modifier: Modifier = Modifier,
    lastRequestFailed: Boolean = false,
) {
    OutlinedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.outlinedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.suspend_tile_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = stringResource(R.string.suspend_tile_body),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = stateLabel(state),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // A single button that flips meaning with the last-known state. When the
            // state is UNKNOWN we default the affordance to "Pause" (the protective
            // action) but never claim the profile is currently running.
            val showResume = state == SuspendTileState.PAUSED
            OutlinedButton(
                onClick = if (showResume) onResume else onSuspend,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = if (showResume) {
                        stringResource(R.string.suspend_tile_action_resume)
                    } else {
                        stringResource(R.string.suspend_tile_action_suspend)
                    },
                )
            }

            if (lastRequestFailed) {
                Text(
                    text = stringResource(R.string.suspend_tile_request_failed),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Text(
                text = stringResource(R.string.suspend_tile_caveat),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun stateLabel(state: SuspendTileState): String = when (state) {
    SuspendTileState.RUNNING -> stringResource(R.string.suspend_tile_state_active)
    SuspendTileState.PAUSED -> stringResource(R.string.suspend_tile_state_paused)
    SuspendTileState.UNKNOWN -> stringResource(R.string.suspend_tile_state_unknown)
}

@Preview(name = "Suspend tile · unknown", showBackground = true, widthDp = 380)
@Preview(
    name = "Suspend tile · paused (dark)",
    showBackground = true,
    widthDp = 380,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
private fun SuspendResumeTilePreview() {
    PorogTheme {
        SuspendResumeTile(
            state = SuspendTileState.UNKNOWN,
            onSuspend = {},
            onResume = {},
            modifier = Modifier.padding(16.dp),
        )
    }
}
