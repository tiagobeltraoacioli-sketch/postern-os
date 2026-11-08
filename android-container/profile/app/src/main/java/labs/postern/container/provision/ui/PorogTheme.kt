// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.provision.ui

import android.content.res.Configuration
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.tooling.preview.Preview

/**
 * Minimal, dependency-light Material3 theme for the Porog onboarding surface.
 *
 * Deliberately **static** color schemes (no Material-You dynamic color): the
 * onboarding "threshold" reads the same on every device so the honesty banner is
 * never restyled into something softer than it is. Light + dark are both defined
 * and follow the system setting.
 *
 * ## Status
 * SCAFFOLD · DESIGN ONLY · UNAUDITED. Colors are a placeholder identity, not a
 * brand sign-off. On-device rendering is **UNTESTED-until-VM/device** — the macOS
 * host has no Android SDK and nothing here has ever been composed on screen.
 */

// A restrained, high-contrast palette. "Porog amber" for the primary action; a
// muted red-orange for the honest-warning surfaces so a dead-end never looks green.
private val PorogAmber = Color(0xFFB4690E)
private val PorogAmberDark = Color(0xFFE79A3B)
private val WarnRust = Color(0xFF8A3324)
private val WarnRustLight = Color(0xFFF0B7A6)

private val PorogLightColors = lightColorScheme(
    primary = PorogAmber,
    onPrimary = Color.White,
    secondary = Color(0xFF5A5148),
    background = Color(0xFFFBF7F1),
    onBackground = Color(0xFF1C1B1A),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1C1B1A),
    surfaceVariant = Color(0xFFEDE6DC),
    onSurfaceVariant = Color(0xFF4C463E),
    error = WarnRust,
    onError = Color.White,
)

private val PorogDarkColors = darkColorScheme(
    primary = PorogAmberDark,
    onPrimary = Color(0xFF3A2400),
    secondary = Color(0xFFCFC4B6),
    background = Color(0xFF141312),
    onBackground = Color(0xFFEAE4DC),
    surface = Color(0xFF1E1C1A),
    onSurface = Color(0xFFEAE4DC),
    surfaceVariant = Color(0xFF35312B),
    onSurfaceVariant = Color(0xFFCFC4B6),
    error = WarnRustLight,
    onError = Color(0xFF3A0A00),
)

/** Compose Material3 wrapper. Follows the system dark/light setting by default. */
@Composable
fun PorogTheme(
    useDarkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (useDarkTheme) PorogDarkColors else PorogLightColors,
        typography = Typography(),
        content = content,
    )
}

@Preview(name = "Theme · light", showBackground = true)
@Preview(
    name = "Theme · dark",
    showBackground = true,
    uiMode = Configuration.UI_MODE_NIGHT_YES,
)
@Composable
private fun PorogThemePreview() {
    PorogTheme {
        HonestyBanner()
    }
}
