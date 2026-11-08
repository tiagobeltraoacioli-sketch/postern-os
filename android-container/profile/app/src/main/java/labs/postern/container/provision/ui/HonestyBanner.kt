// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.provision.ui

import android.content.res.Configuration
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import labs.postern.container.R

/**
 * The **mandatory** Porog honesty banner and its supporting rows.
 *
 * This is the load-bearing UI element of the whole product: the honest labeling
 * *is* the value proposition, so this banner is not decorative and must not be
 * softened, collapsed, or made dismissible. Every string comes from
 * `res/values/strings.xml` and is bound by `scripts/check-trust-labels.sh`.
 *
 * The headline row is the verbatim four-part claim:
 * "Hardened, not anonymous · key-attested device, not a measured-boot workspace ·
 *  DESIGN ONLY · UNAUDITED". The phrase "key-attested" never appears without its
 * qualifier "not a measured-boot workspace" on the same line (the ±3-line rule).
 *
 * ## Status
 * SCAFFOLD · DESIGN ONLY · UNAUDITED. Visual rendering is
 * **UNTESTED-until-VM/device** (no Android SDK on the macOS host).
 */
@Composable
fun HonestyBanner(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(12.dp),
            )
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        // The verbatim, non-negotiable headline claim.
        Text(
            text = stringResource(R.string.onboarding_honesty_banner),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        HonestyRow(stringResource(R.string.onboarding_honesty_row_profile))
        HonestyRow(stringResource(R.string.onboarding_honesty_row_attest))
        HonestyRow(stringResource(R.string.onboarding_honesty_row_distribution))
        HonestyRow(stringResource(R.string.onboarding_honesty_row_scaffold))
    }
}

@Composable
private fun HonestyRow(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Preview(name = "HonestyBanner · light", showBackground = true, widthDp = 380)
@Preview(
    name = "HonestyBanner · dark",
    showBackground = true,
    widthDp = 380,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
private fun HonestyBannerPreview() {
    PorogTheme {
        HonestyBanner(modifier = Modifier.padding(16.dp))
    }
}
