package labs.postern.wallet.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import labs.postern.wallet.WalletViewModel

/**
 * The single wallet screen: create / restore, show the address + balance, and a
 * send stub. Deliberately minimal — this is the skeleton's UI surface.
 */
@Composable
fun WalletScreen(viewModel: WalletViewModel) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Postern Wallet", style = androidx.compose.material3.MaterialTheme.typography.headlineSmall)
        Text(
            "Light client for the ownerless Bloch-SIS-PoW protocol",
            style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
        )
        Divider()

        if (state.address == null) {
            CreateOrRestore(
                busy = state.busy,
                onCreate = viewModel::createWallet,
                onRestore = viewModel::restore,
            )
        } else {
            WalletDetails(
                address = state.address!!,
                balanceSats = state.balanceSats,
                chainHeight = state.chainHeight,
                busy = state.busy,
                lastTxid = state.lastTxid,
                onRefresh = viewModel::refreshBalance,
                onSend = viewModel::signAndBroadcast,
            )
        }

        state.mnemonicToBackUp?.let { phrase ->
            MnemonicBackupCard(phrase = phrase, onDismiss = viewModel::dismissMnemonicBackup)
        }

        state.error?.let { err ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Text(
                    "Error: $err",
                    color = androidx.compose.material3.MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(12.dp),
                )
            }
        }

        if (state.busy) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
            ) {
                CircularProgressIndicator()
            }
        }
    }
}

@Composable
private fun CreateOrRestore(
    busy: Boolean,
    onCreate: () -> Unit,
    onRestore: (String) -> Unit,
) {
    var mnemonic by remember { mutableStateOf("") }

    Button(onClick = onCreate, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
        Text("Create new wallet")
    }
    Text("— or restore —", modifier = Modifier.padding(vertical = 4.dp))
    OutlinedTextField(
        value = mnemonic,
        onValueChange = { mnemonic = it },
        label = { Text("BIP39 recovery phrase") },
        modifier = Modifier.fillMaxWidth(),
        minLines = 2,
    )
    OutlinedButton(
        onClick = { onRestore(mnemonic) },
        enabled = !busy && mnemonic.isNotBlank(),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text("Restore wallet")
    }
}

@Composable
private fun WalletDetails(
    address: String,
    balanceSats: ULong?,
    chainHeight: ULong?,
    busy: Boolean,
    lastTxid: String?,
    onRefresh: () -> Unit,
    onSend: (String) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Receiving address", style = androidx.compose.material3.MaterialTheme.typography.labelMedium)
            Text(address, fontFamily = FontFamily.Monospace, overflow = TextOverflow.Ellipsis, maxLines = 2)
            Divider()
            Text(
                "Balance: " + (balanceSats?.let { "$it sats" } ?: "—"),
                style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
            )
            chainHeight?.let { Text("Chain height: $it", style = androidx.compose.material3.MaterialTheme.typography.bodySmall) }
        }
    }

    OutlinedButton(onClick = onRefresh, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
        Text("Refresh balance")
    }

    Spacer(Modifier.height(4.dp))
    SendStub(busy = busy, onSend = onSend)

    lastTxid?.let {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("Last broadcast response", style = androidx.compose.material3.MaterialTheme.typography.labelMedium)
                Text(it, fontFamily = FontFamily.Monospace, maxLines = 4, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun SendStub(busy: Boolean, onSend: (String) -> Unit) {
    // Send STUB: a real build assembles the unsigned tx from UTXOs (fetched over
    // RPC) for a recipient address + amount. Here we accept the unsigned tx hex
    // directly so the signing path (core `signTxHex`) stays real, not faked.
    var unsignedHex by remember { mutableStateOf("") }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Send (stub)", style = androidx.compose.material3.MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = unsignedHex,
                onValueChange = { unsignedHex = it },
                label = { Text("Unsigned tx hex") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = false,
                minLines = 2,
            )
            Button(
                onClick = { onSend(unsignedHex.trim()) },
                enabled = !busy && unsignedHex.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Sign & broadcast")
            }
        }
    }
}

@Composable
private fun MnemonicBackupCard(phrase: String, onDismiss: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                "Back up this recovery phrase — it is the ONLY backup and is shown once.",
                style = androidx.compose.material3.MaterialTheme.typography.titleSmall,
            )
            Text(phrase, fontFamily = FontFamily.Monospace)
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                Button(onClick = onDismiss) { Text("I saved it") }
            }
        }
    }
}
