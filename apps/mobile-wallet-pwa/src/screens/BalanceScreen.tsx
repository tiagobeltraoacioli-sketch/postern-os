import { useEffect, useState } from "react";
import { Card, HonestNote, PreviewTag } from "../components";
import { AUDIT_STATUS, COIN_HONEST, RPC_HONEST } from "../honesty";
import { getBalanceSats, getHeight, endpoint } from "../rpc";

const SATS = 100_000_000;
function fmtCoins(sats: number): string {
  const whole = Math.floor(sats / SATS);
  const frac = String(sats % SATS).padStart(8, "0");
  return whole.toLocaleString("en-US") + "." + frac;
}

// A demo receiving address SHAPE (illustrative — the real encoder lives in Bloch
// core / wallet-live.js). Reads below are keyed to it only to exercise the real
// /rpc path; no balance is fabricated.
const DEMO_ADDR = "blk1qexampleonly0000referenceprototype0shape";

export default function BalanceScreen() {
  const [sats, setSats] = useState<number | null>(null);
  const [height, setHeight] = useState<number | null>(null);
  const [live, setLive] = useState<boolean>(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      const [b, h] = await Promise.all([getBalanceSats(DEMO_ADDR), getHeight()]);
      if (!alive) return;
      setSats(b);
      setHeight(h);
      setLive(b != null || h != null);
    })();
    return () => {
      alive = false;
    };
  }, []);

  return (
    <section className="screen" aria-label="Balance">
      <div className="card hero">
        <div className="amt">
          {sats == null ? "—" : fmtCoins(sats)}
          <span className="unit">BLCH</span>
        </div>
        <div className="fiat">
          {live ? (
            <>Read from the hosted node via /rpc. {COIN_HONEST}</>
          ) : (
            <>
              Node unreachable — showing no balance rather than a fabricated one <PreviewTag label="preview" />.{" "}
              {COIN_HONEST}
            </>
          )}
        </div>
        <div className="netbadge">
          <span className="netdot" /> height {height == null ? "unreachable" : height.toLocaleString("en-US")}
        </div>
      </div>

      <HonestNote kind={live ? "info" : "warn"}>
        <strong>{live ? "Live." : "Preview."}</strong> {RPC_HONEST} Endpoint:{" "}
        <span className="mono">{endpoint()}</span>.
      </HonestNote>

      <HonestNote kind="soft">
        <strong>Read me first.</strong> {AUDIT_STATUS}
      </HonestNote>

      <Card title="Your receiving address">
        <div className="kv">
          <span className="k">address (index 0)</span>
          <span className="v mono">{DEMO_ADDR}</span>
        </div>
        <p className="hint">
          Address <em>shape</em> is illustrative; the real encoder ships in the reused WASM core / wallet-live.js.
        </p>
      </Card>
    </section>
  );
}
