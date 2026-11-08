/* ============================================================================
   Same-origin JSON-RPC client — REUSES the exact contract of the existing
   apps/mobile-wallet/wallet-live.js Rpc object (method names + param shapes are
   byte-identical to the node's). The only network this app makes is to the
   SAME-ORIGIN "/rpc" proxy (connect-src 'self'); no third-party RPC host.

   Reads are REAL. When the proxy/node is unreachable this returns null and the
   UI shows an honest "node unreachable — preview" state; it never fabricates a
   balance or height.
   ============================================================================ */

const DEFAULT_RPC = "/rpc";
const LS_RPC = "postern-wallet.rpc";

export function endpoint(): string {
  try {
    return (localStorage.getItem(LS_RPC) || DEFAULT_RPC).trim();
  } catch {
    return DEFAULT_RPC;
  }
}

async function post(method: string, params: unknown[], timeoutMs = 20000): Promise<unknown> {
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), timeoutMs);
  let r: Response;
  try {
    r = await fetch(endpoint(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: params || [] }),
      signal: ctrl.signal,
      cache: "no-store",
    });
  } finally {
    clearTimeout(to);
  }
  if (!r.ok) throw new Error("node HTTP " + r.status);
  const j = (await r.json()) as { error?: unknown; result?: unknown };
  if (j && j.error != null) throw new Error("node error: " + JSON.stringify(j.error));
  return j ? j.result : undefined;
}

export async function getHeight(): Promise<number | null> {
  try {
    const r = (await post("getblockcount", [])) as number | { height?: number };
    if (typeof r === "number") return r;
    if (r && typeof r.height === "number") return r.height;
    return null;
  } catch {
    return null;
  }
}

export async function getBalanceSats(address: string): Promise<number | null> {
  try {
    const r = (await post("getbalance", [address])) as number | { satoshis?: number };
    if (r && typeof (r as { satoshis?: number }).satoshis === "number") {
      return (r as { satoshis: number }).satoshis;
    }
    if (typeof r === "number") return r;
    return null;
  } catch {
    return null;
  }
}
