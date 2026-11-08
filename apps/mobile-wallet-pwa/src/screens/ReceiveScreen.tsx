import { Card, HonestNote } from "../components";
import { RPC_HONEST } from "../honesty";

const DEMO_ADDR = "blk1qexampleonly0000referenceprototype0shape";

function groups(addr: string, size = 4): string[] {
  const out: string[] = [];
  for (let i = 0; i < addr.length; i += size) out.push(addr.slice(i, i + size));
  return out;
}

export default function ReceiveScreen() {
  return (
    <section className="screen" aria-label="Receive">
      <h2 className="scr">Receive</h2>

      <Card title="Address · index 0">
        <div className="addr-chunks" aria-label="Receiving address in verifiable groups">
          {groups(DEMO_ADDR).map((g, i) => (
            <span className="chunk" key={i}>
              <span className="ix">{i}</span>
              {g}
            </span>
          ))}
        </div>
        <p className="hint">
          Read the address in numbered groups so you and the sender can compare position-by-position out loud.
        </p>
      </Card>

      <HonestNote kind="info">
        <strong>No QR here — on purpose.</strong> A faked QR is invisible; this prototype ships the honest fallback
        (numbered groups you verify by hand). {RPC_HONEST}
      </HonestNote>

      <HonestNote kind="warn">
        The address <em>shape</em> is illustrative in this UI; the real diversified-address encoder is the reused Bloch
        WASM core, not reinvented here.
      </HonestNote>
    </section>
  );
}
