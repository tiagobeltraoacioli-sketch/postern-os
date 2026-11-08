import { Card, HonestNote, PreviewTag } from "../components";
import { FUNDS_HONEST, KEYSTORE_HONEST } from "../honesty";

export default function ApproveScreen() {
  return (
    <section className="screen" aria-label="Approve">
      <h2 className="scr">Approve &amp; sign</h2>

      <HonestNote kind="info">
        <strong>Phone-as-signer (WYSIWYS).</strong> A paired device holds no key. It sends the bytes it wants signed;
        this phone parses them and shows exactly what a signature would mean — parsed from the actual bytes, never from
        requester-supplied prose.
      </HonestNote>

      <Card title="Incoming request">
        <div className="kv">
          <span className="k">tier</span>
          <span className="v">read-only login challenge</span>
        </div>
        <div className="kv">
          <span className="k">signature</span>
          <span className="v">
            hybrid Falcon-1024 ‖ ML-DSA-65 via the reused WASM core <PreviewTag label="computed on unlock" />
          </span>
        </div>
        <p className="hint">
          Multi-output or undecodable requests are refused (fail-closed), not guessed or under-displayed.
        </p>
      </Card>

      <HonestNote kind="warn">
        <strong>Keystore.</strong> {KEYSTORE_HONEST}
      </HonestNote>

      <HonestNote kind="soft">
        <strong>Funds.</strong> {FUNDS_HONEST}
      </HonestNote>
    </section>
  );
}
