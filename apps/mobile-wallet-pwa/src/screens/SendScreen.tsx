import { useState } from "react";
import { Card, HonestNote, PreviewTag } from "../components";
import { FUNDS_HONEST, KEYSTORE_HONEST } from "../honesty";

export default function SendScreen() {
  const [to, setTo] = useState("");
  const [amt, setAmt] = useState("");

  return (
    <section className="screen" aria-label="Send">
      <h2 className="scr">Send</h2>

      <label className="fld">
        <span className="lab">Recipient address</span>
        <input
          className="in mono"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          placeholder="blk1… recipient address"
        />
      </label>

      <label className="fld">
        <span className="lab">Amount (BLCH)</span>
        <input
          className="in mono"
          value={amt}
          onChange={(e) => setAmt(e.target.value)}
          inputMode="decimal"
          autoComplete="off"
          placeholder="0.00000000"
        />
        <div className="hint">1 BLCH = 100,000,000 sats.</div>
      </label>

      <Card title="Before you sign">
        <div className="kv">
          <span className="k">to</span>
          <span className="v mono">{to || "—"}</span>
        </div>
        <div className="kv">
          <span className="k">amount</span>
          <span className="v">{amt || "—"} BLCH</span>
        </div>
        <div className="kv">
          <span className="k">signing</span>
          <span className="v">
            hybrid Falcon-1024 ‖ ML-DSA-65 <PreviewTag label="wired via WASM core on unlock" />
          </span>
        </div>
      </Card>

      <button className="btn primary" type="button" disabled={!to || !amt}>
        Review &amp; sign →
      </button>

      <HonestNote kind="soft">
        <strong>Irreversible.</strong> {FUNDS_HONEST}
      </HonestNote>

      <HonestNote kind="warn">
        <strong>Keystore.</strong> {KEYSTORE_HONEST}
      </HonestNote>
    </section>
  );
}
