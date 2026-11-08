import { Card } from "../components";
import { HONEST_LINES } from "../honesty";

export default function AboutScreen() {
  return (
    <section className="screen" aria-label="About and honest limits">
      <h2 className="scr">About &amp; honest limits</h2>

      <Card title="What this is">
        <p className="small dim">
          A touch-first React reference-prototype UI for a Bloch mobile wallet. It wraps the existing hybrid-PQ WASM
          core, wallet-live.js and the same-origin /rpc client — the crypto and node access are reused, not reinvented.
          No mining. No native shell. Same-origin, CSP-strict, installable PWA.
        </p>
      </Card>

      <Card title="Honest limits (every one, never rounded off)">
        <ul className="tight">
          {HONEST_LINES.map((l) => (
            <li key={l.id}>{l.text}</li>
          ))}
        </ul>
      </Card>

      <p className="center muted small">
        Postern Wallet — mobile PWA · Postern Labs · reference prototype · Unaudited · the coin is not a security and
        carries no promise of value.
      </p>
    </section>
  );
}
