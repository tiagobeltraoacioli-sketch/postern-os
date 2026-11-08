// SPDX-License-Identifier: MIT OR Apache-2.0
package labs.postern.container.provision

import android.content.ComponentName
import android.os.Bundle
import android.os.Process
import android.os.UserHandle
import android.os.UserManager
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import labs.postern.common.profile.provision.ManagedProfileProvisioningActivity
import labs.postern.common.profile.provision.ProvisioningResult
import labs.postern.container.dpc.PosternDeviceAdminReceiver
import labs.postern.container.lifecycle.ContainerProfileManager
import labs.postern.container.provision.ui.PorogTheme

/**
 * The "Create Porog" onboarding entry point. Runs in the **personal** profile to
 * trigger managed-profile provisioning, then hands off to the DPC **inside** the
 * new profile (see [PosternDeviceAdminReceiver.onProfileProvisioningComplete]).
 *
 * The generic provisioning mechanism — preflight, the
 * `ACTION_PROVISION_MANAGED_PROFILE` intent, and result mapping — lives in the
 * shared [ManagedProfileProvisioningActivity] (android-common). Porog supplies its
 * own admin component, its Compose onboarding UI ([OnboardingScreen]), and — as a
 * personal/parent-context action — the container **Suspend/Resume** (quiet mode)
 * controls.
 *
 * This is the Porog brand made literal: the guarded **threshold** the traveller
 * crosses to move between the ordinary side of the phone and the hardened
 * workspace — one door, one device.
 *
 * ## State ownership
 * This activity is the single owner of onboarding UI state. [OnboardingScreen] is a
 * stateless composable; the activity feeds it [ProvisioningUiState] /
 * [SuspendTileState] / container-existence and receives its callbacks. The
 * provisioning result arrives via the shared [onProvisioningResult] override; the
 * quiet-mode toggle calls Dev 1's [ContainerProfileManager.pauseContainer] /
 * [ContainerProfileManager.resumeContainer]. [onCreate] and [onResume] both call
 * [refreshContainerState] so returning to this screen (after suspending elsewhere,
 * or completing provisioning) reflects live OS state, not only the last local
 * action.
 *
 * ## Honest boundary
 * Provisioning creates a real second Android user with its own FBE key; it does
 * NOT create a new OS and does NOT measure the workspace. It attests the phone, not
 * the workspace — hardened, not anonymous. Self-enrolled profile-owner, never
 * device-owner. A rooted host defeats the boundary. This is an app on stock
 * Android — it is NEVER "Postern OS".
 *
 * ## Status
 * SCAFFOLD · DESIGN ONLY · UNAUDITED. The one-tap consent flow is not
 * headless-scriptable, so the real end-to-end behavior is
 * **UNTESTED-until-VM/device** (T1 emulator exercises the enrolled code path via
 * adb; the true one-tap consent flow is device / T2). Never run on hardware yet.
 */
class ProvisioningActivity : ManagedProfileProvisioningActivity() {

    /** The single source of truth for the provisioning result shown on screen. */
    private var provisioningState by mutableStateOf<ProvisioningUiState>(ProvisioningUiState.Idle)

    /** Last-known quiet-mode state for the personal-side Suspend/Resume tile. */
    private var suspendTileState by mutableStateOf(SuspendTileState.UNKNOWN)

    /** Set when Android declined/intercepted the most recent quiet-mode request. */
    private var suspendRequestFailed by mutableStateOf(false)

    /**
     * Whether a provisioned container currently exists, as observed from the
     * parent/personal context via [resolveContainerHandle]. Drives whether the
     * Suspend/Resume tile is shown at all — before a container exists there is
     * nothing to suspend.
     */
    private var containerExists by mutableStateOf(false)

    /**
     * Porog's lifecycle owner, used here only for its personal/parent-context
     * quiet-mode toggles. Constructed lazily against the application context so it
     * outlives configuration changes.
     */
    private val containerManager: ContainerProfileManager by lazy {
        ContainerProfileManager(applicationContext)
    }

    /** Porog's DPC is the admin component installed as profile owner. */
    override fun adminComponent(): ComponentName =
        PosternDeviceAdminReceiver.componentName(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        refreshContainerState()
        setContent {
            PorogTheme {
                OnboardingScreen(
                    provisioningState = provisioningState,
                    suspendTileState = suspendTileState,
                    onCreatePorog = ::requestContainerProvisioning,
                    onSuspend = { toggleQuietMode(pause = true) },
                    onResume = { toggleQuietMode(pause = false) },
                    suspendRequestFailed = suspendRequestFailed,
                    containerExists = containerExists,
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Live-sync on return to this screen (e.g. after suspending/resuming from
        // elsewhere, or after provisioning completed) rather than trusting only the
        // last locally-taken action.
        refreshContainerState()
    }

    /** Called from [OnboardingScreen] when the user taps "Create Porog". */
    fun requestContainerProvisioning() {
        requestProvisioning() // shared preflight + provisioning dispatch.
    }

    override fun onProvisioningResult(result: ProvisioningResult) {
        // Honest projection. NOTE: Dispatched is NOT "ready" — enrollment completes
        // only inside the new profile, in the DPC's onProfileProvisioningComplete.
        // ProvisioningUiState.fromResult carries that asymmetry into the UI copy.
        provisioningState = ProvisioningUiState.fromResult(result)
    }

    /**
     * Toggle whole-container quiet mode from the personal (parent) context.
     *
     * Delegates to Dev 1's [ContainerProfileManager.pauseContainer] /
     * [ContainerProfileManager.resumeContainer], which return the platform's
     * success flag (the request may be declined or user-intercepted). We reflect the
     * **last action** honestly and never assert a live cross-profile read.
     *
     * The DPM/UserManager call is off the main thread; the OS remains authoritative
     * for the true quiet-mode state.
     */
    private fun toggleQuietMode(pause: Boolean) {
        suspendRequestFailed = false
        lifecycleScope.launch {
            val accepted = withContext(Dispatchers.IO) {
                if (pause) containerManager.pauseContainer() else containerManager.resumeContainer()
            }
            if (accepted) {
                suspendTileState = if (pause) SuspendTileState.PAUSED else SuspendTileState.RUNNING
            } else {
                suspendRequestFailed = true
            }
        }
    }

    /**
     * Refresh the personal-side view of the container: whether it exists at all
     * ([containerExists]), and — if so — its last-observed quiet-mode state
     * ([suspendTileState]). Called from [onCreate] and [onResume].
     *
     * Honest limit: from the personal/parent context we cannot inspect the
     * container's internals — only that a sibling profile is present, and its
     * quiet-mode flag, both read via [resolveContainerHandle].
     */
    private fun refreshContainerState() {
        val workProfile = resolveContainerHandle()
        containerExists = workProfile != null
        if (workProfile == null) {
            suspendTileState = SuspendTileState.UNKNOWN
            return
        }
        val um = getSystemService(UserManager::class.java)
        suspendTileState = if (um?.isQuietModeEnabled(workProfile) == true) {
            SuspendTileState.PAUSED
        } else {
            SuspendTileState.RUNNING
        }
    }

    /**
     * Resolve the managed profile's handle from the **parent** context: the first of
     * this user's profiles that is not the caller itself. `null` when no managed profile
     * exists. Honest limit: this personal-side view cannot inspect the container's
     * internals, only that a profile is present and its quiet-mode flag.
     */
    private fun resolveContainerHandle(): UserHandle? {
        val um = getSystemService(UserManager::class.java) ?: return null
        val self = Process.myUserHandle()
        return um.userProfiles.firstOrNull { it != self }
    }
}
