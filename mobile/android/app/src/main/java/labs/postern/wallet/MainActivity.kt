package labs.postern.wallet

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import labs.postern.wallet.ui.WalletScreen

/**
 * Compose host for Postern Wallet.
 *
 * A Postern Labs product: a light client / wallet for the ownerless
 * Bloch-SIS-PoW protocol. All wallet crypto is delegated to the Rust core
 * (`bloch-mobile`) via UniFFI; this Activity only hosts the UI tree.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    val vm: WalletViewModel = viewModel()
                    WalletScreen(viewModel = vm)
                }
            }
        }
    }
}
