// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Postern Labs — Android Key-Attestation CAPTURE harness (device side).
//
// This is the "stripped, zero-dependency android.jar-only APK that calls the
// identical Keystore APIs" referenced by
//   crates/postern-seal-companion/src/testdata/PROVENANCE.md
//
// It drives EXACTLY the code path that
//   labs.postern.wallet.StrongBoxKey.generateTeeFallbackKey
// runs on real hardware: an EC P-256 key generated inside the AndroidKeyStore
// with an attestation challenge (our verifier nonce) and StrongBox OFF (the TEE
// / software-KeyMint fallback path). The KeyStore returns a leaf-first X.509
// certificate chain carrying the Android Key-Attestation extension
// (OID 1.3.6.1.4.1.11129.2.1.17); we emit that chain, verbatim and unmodified,
// so the Rust verifier's `captured_emulator_attestation` vectors are
// reproducible instead of a one-off.
//
// HONEST LIMIT (do not overstate): on the `google_apis` emulator KeyMint is a
// SOFTWARE reference implementation, so the attested security level is
// Software(0) and the RootOfTrust is NOT hardware-enforced. This harness proves
// the full parse+evaluate pipeline runs over a REAL Keystore-minted chain; it is
// NOT a StrongBox / secure-element attestation and carries no hardware security
// claim. On real hardware the very same code emits a genuine TEE/StrongBox
// chain. `captured != StrongBox-hardware-attested`.
//
// The DER bytes are written to this app's OWN external files dir (no runtime
// permission needed) and ALSO logged base64 to logcat, so the host driver can
// extract them by either channel:
//     /sdcard/Android/data/labs.postern.capture/files/
//         nonce.bin, chain-0.der, chain-1.der, ..., capture.ok  (or capture.err)
//
// Built against android.jar only (no AndroidX, no Gradle) — see
// capture-android-attestation.sh in the same directory.

package labs.postern.capture;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;

public final class CaptureActivity extends Activity {

    private static final String TAG = "POSTERN_CAP";

    // MUST equal crates/postern-seal-companion/src/testdata/nonce.bin so the
    // captured leaf binds the exact challenge the Rust verifier asserts. The
    // host driver overrides this via the `nonce_b64` intent extra; this literal
    // is only the fallback default.
    private static final String DEFAULT_NONCE = "postern-seal-mobile-attest-nnc32";

    // The Keystore alias for the throwaway attested key. Regenerated every run.
    private static final String ALIAS = "postern-capture-key";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        File dir = getExternalFilesDir(null);
        try {
            byte[] nonce = resolveNonce();
            Certificate[] chain = attest(nonce);
            emit(dir, nonce, chain);
            // Signal success LAST, only after every DER is on disk.
            writeFile(new File(dir, "capture.ok"), Integer.toString(chain.length).getBytes("UTF-8"));
            Log.i(TAG, "COUNT " + chain.length);
            Log.i(TAG, "END");
        } catch (Throwable t) {
            // Fail LOUD and fail CLOSED — never leave a half-written vector that
            // could masquerade as a real capture.
            String msg = t.getClass().getName() + ": " + t.getMessage();
            Log.e(TAG, "CAPTURE FAILED: " + msg, t);
            try {
                if (dir != null) writeFile(new File(dir, "capture.err"), msg.getBytes("UTF-8"));
            } catch (Throwable ignored) { /* best effort */ }
        } finally {
            finish();
        }
    }

    /** The verifier nonce: `nonce_b64` intent extra if present, else the default. */
    private byte[] resolveNonce() throws Exception {
        String b64 = getIntent() != null ? getIntent().getStringExtra("nonce_b64") : null;
        if (b64 != null && !b64.isEmpty()) {
            return Base64.decode(b64, Base64.NO_WRAP);
        }
        return DEFAULT_NONCE.getBytes("UTF-8");
    }

    /**
     * Generate an EC P-256 key inside AndroidKeyStore with our attestation
     * challenge and StrongBox OFF (the TEE / software-KeyMint fallback path —
     * identical to StrongBoxKey.generateTeeFallbackKey), then return the
     * leaf-first attestation certificate chain the Keystore minted.
     */
    private Certificate[] attest(byte[] nonce) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(nonce);
        // The TEE / non-StrongBox path. On the google_apis emulator there is no
        // discrete StrongBox HSM, so this is what runs; on hardware this is the
        // documented fallback when StrongBox is unavailable.
        spec.setIsStrongBoxBacked(false);

        kpg.initialize(spec.build());
        kpg.generateKeyPair();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain(ALIAS);
        if (chain == null || chain.length == 0) {
            throw new IllegalStateException(
                    "AndroidKeyStore returned no attestation chain for alias " + ALIAS);
        }
        return chain; // leaf-first, exactly as the Keystore returned it
    }

    /** Write nonce.bin + chain-N.der to disk (primary) and base64 to logcat (mirror). */
    private void emit(File dir, byte[] nonce, Certificate[] chain) throws Exception {
        if (dir == null) {
            throw new IllegalStateException("getExternalFilesDir(null) was null");
        }
        Log.i(TAG, "BEGIN");
        writeFile(new File(dir, "nonce.bin"), nonce);
        Log.i(TAG, "NONCE " + Base64.encodeToString(nonce, Base64.NO_WRAP));
        for (int i = 0; i < chain.length; i++) {
            byte[] der = chain[i].getEncoded();
            writeFile(new File(dir, "chain-" + i + ".der"), der);
            Log.i(TAG, "CERT " + i + " " + Base64.encodeToString(der, Base64.NO_WRAP));
        }
    }

    private static void writeFile(File f, byte[] bytes) throws Exception {
        FileOutputStream out = new FileOutputStream(f);
        try {
            out.write(bytes);
            out.flush();
            out.getFD().sync();
        } finally {
            out.close();
        }
    }
}
