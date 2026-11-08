import { Card, HonestNote } from "../components";
import { AUDIT_STATUS, KEYSTORE_HONEST } from "../honesty";

export default function KeysScreen() {
  return (
    <section className="screen" aria-label="Keys and recovery">
      <h2 className="scr">Keys &amp; recovery</h2>

      <HonestNote kind="soft">
        <strong>Software keystore.</strong> {KEYSTORE_HONEST}
      </HonestNote>

      <Card title="Signing key">
        <div className="kv">
          <span className="k">scheme</span>
          <span className="v">
            Falcon-1024 ‖ ML-DSA-65 <span className="tag info">post-quantum</span>
          </span>
        </div>
        <div className="kv">
          <span className="k">held in</span>
          <span className="v">
            browser software keystore <span className="tag soft">not Secure Enclave / StrongBox</span>
          </span>
        </div>
        <p className="hint">
          Keygen + signing are the reused hybrid-PQ WASM core (bloch_wallet_wasm.wasm) + wallet-live.js — the crypto is
          not reinvented in this UI.
        </p>
      </Card>

      <Card title="Recovery phrase">
        <p className="small dim">
          Your recovery phrase is the only backup of this wallet. Anyone who reads it controls the funds. Write it on
          paper; never photograph it or type it into another app.
        </p>
      </Card>

      <HonestNote kind="warn">
        <strong>Read me.</strong> {AUDIT_STATUS}
      </HonestNote>
    </section>
  );
}
