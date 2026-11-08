// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.provision.ui

import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import labs.postern.container.R
import labs.postern.container.provision.ProvisioningUiState

/**
 * Honest rendering of a provisioning outcome.
 *
 * The one invariant this card exists to protect: **`Dispatched` never reads as
 * "ready".** A dispatched result means only that Android accepted the system
 * provisioning flow — enrollment truth lands separately, inside the new profile,
 * in the DPC's `onProfileProvisioningComplete`. The copy says exactly that, and the
 * card uses a neutral/attention color for `Dispatched`, never a success green.
 *
 * `Unsupported` and `Failed` are honest dead-ends shown with the error color; they
 * are never dressed up or retried silently.
 *
 * ## Status
 * SCAFFOLD · DESIGN ONLY · UNAUDITED. **UNTESTED-until-VM/device.**
 */
@Composable
fun ProvisioningResultCard(
    state: ProvisioningUiState,
    modifier: Modifier = Modifier,
) {
    if (state is ProvisioningUiState.Idle) {
        // Idle is rendered as a quiet inline line by the caller; nothing to card.
        return
    }

    val accent: Color = when (state) {
        is ProvisioningUiState.Dispatched -> MaterialTheme.colorScheme.primary
        is ProvisioningUiState.Cancelled -> MaterialTheme.colorScheme.onSurfaceVariant
        is ProvisioningUiState.Unsupported -> MaterialTheme.colorScheme.error
        is ProvisioningUiState.Failed -> MaterialTheme.colorScheme.error
        is ProvisioningUiState.Idle -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = stringResource(R.string.onboarding_result_heading),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = titleFor(state),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = accent,
            )
            Text(
                text = bodyFor(state),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            detailFor(state)?.let { detail ->
                Text(
                    text = detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun titleFor(state: ProvisioningUiState): String = when (state) {
    is ProvisioningUiState.Dispatched -> stringResource(R.string.onboarding_result_dispatched_title)
    is ProvisioningUiState.Cancelled -> stringResource(R.string.onboarding_result_cancelled_title)
    is ProvisioningUiState.Unsupported -> stringResource(R.string.onboarding_result_unsupported_title)
    is ProvisioningUiState.Failed -> stringResource(R.string.onboarding_result_failed_title)
    is ProvisioningUiState.Idle -> ""
}

@Composable
private fun bodyFor(state: ProvisioningUiState): String = when (state) {
    is ProvisioningUiState.Dispatched -> stringResource(R.string.onboarding_result_dispatched_body)
    is ProvisioningUiState.Cancelled -> stringResource(R.string.onboarding_result_cancelled_body)
    is ProvisioningUiState.Unsupported -> stringResource(R.string.onboarding_result_unsupported_body)
    is ProvisioningUiState.Failed -> stringResource(R.string.onboarding_result_failed_body)
    is ProvisioningUiState.Idle -> ""
}

@Composable
private fun detailFor(state: ProvisioningUiState): String? = when (state) {
    is ProvisioningUiState.Unsupported ->
        state.reason.takeIf { it.isNotBlank() }
            ?.let { stringResource(R.string.onboarding_result_unsupported_reason, it) }
    is ProvisioningUiState.Failed ->
        stringResource(R.string.onboarding_result_failed_code, state.resultCode)
    else -> null
}

@Preview(name = "Result · dispatched", showBackground = true, widthDp = 380)
@Preview(
    name = "Result · dispatched (dark)",
    showBackground = true,
    widthDp = 380,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
private fun ProvisioningResultCardDispatchedPreview() {
    PorogTheme {
        ProvisioningResultCard(
            state = ProvisioningUiState.Dispatched,
            modifier = Modifier.padding(16.dp),
        )
    }
}

@Preview(name = "Result · unsupported", showBackground = true, widthDp = 380)
@Composable
private fun ProvisioningResultCardUnsupportedPreview() {
    PorogTheme {
        ProvisioningResultCard(
            state = ProvisioningUiState.Unsupported("FEATURE_MANAGED_USERS absent"),
            modifier = Modifier.padding(16.dp),
        )
    }
}
