// Cloudflare Pages root middleware — runs on EVERY request to the project
// (posternlabs.com AND posternpool.com), before any specific Function or static
// asset. Purpose: OFAC comprehensive-sanctions geo-restriction for the HOSTED
// service. Returns HTTP 451 (Unavailable For Legal Reasons) to visitors
// geolocated in comprehensively-sanctioned jurisdictions.
//
// HONEST SCOPE + LIMITS (do not overclaim what this does):
//   - This gates the HOSTED website + Functions (the service a US-organizing
//     company provides). It is a compliance control, not a security boundary.
//   - It is IP-geolocation based and therefore trivially evadable with a VPN or
//     Tor. It does NOT — and cannot — restrict the ownerless, permissionless
//     Bloch P2P protocol (no one operates it), nor software already downloaded.
//   - Founder decision (2026-07-18): apply site-wide 451 for the OFAC
//     comprehensive list, accepting that this also blocks the informational
//     pages and open-source materials (which may carry their own sanctions
//     exemptions) and is reachable-around by design of Postern's own tools.
//
// List = OFAC comprehensively-sanctioned countries (ISO-3166 alpha-2) + the
// Russia-occupied regions of Ukraine (best-effort at region granularity, which
// Cloudflare reports less reliably than country).
const BLOCKED_COUNTRIES = new Set(["CU", "IR", "KP", "SY"]);
// Occupied regions of Ukraine that OFAC covers (Crimea, Sevastopol, and the
// so-called DNR/LNR). Cloudflare reports these under country "UA"; region/city
// strings vary, so this is a best-effort substring match, not authoritative.
const BLOCKED_UA_REGIONS = ["crimea", "sevastopol", "donetsk", "luhansk", "lugansk"];

export async function onRequest(context) {
  const { request, next } = context;
  const cf = request.cf || {};
  const country = String(cf.country || request.headers.get("CF-IPCountry") || "").toUpperCase();

  let blocked = BLOCKED_COUNTRIES.has(country);
  if (!blocked && country === "UA") {
    const where = `${cf.region || ""} ${cf.regionCode || ""} ${cf.city || ""}`.toLowerCase();
    blocked = BLOCKED_UA_REGIONS.some((r) => where.includes(r));
  }

  if (!blocked) return next();

  return new Response(interstitial(country), {
    status: 451,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-postern-geoblock": country || "unknown",
      // RFC 7725: point at the authority for the restriction.
      link: '<https://ofac.treasury.gov/sanctions-programs-and-country-information>; rel="blocked-by"',
    },
  });
}

function interstitial(country) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>451 — Unavailable for legal reasons · Postern Labs</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background:#0b0d10; color:#e7ebef; padding:2rem; }
  main { max-width:640px; }
  h1 { font-size:1.4rem; margin:0 0 .25rem; }
  .code { font-size:.8rem; letter-spacing:.08em; text-transform:uppercase; color:#8b97a3; margin-bottom:1.25rem; }
  p { color:#c3ccd4; }
  a { color:#7db1ff; }
  .note { margin-top:1.5rem; font-size:.85rem; color:#8b97a3; border-top:1px solid #22272e; padding-top:1rem; }
  @media (prefers-color-scheme: light) { body { background:#f6f8fa; color:#1b2126; } p{color:#3a444d} .code,.note{color:#5a6570} .note{border-color:#e1e6ea} }
</style></head><body><main>
  <div class="code">HTTP 451 · Unavailable for legal reasons${country ? " · " + country : ""}</div>
  <h1>This hosted service isn't available in your region</h1>
  <p>Postern Labs is organizing as a U.S. (Wyoming) company and cannot provide
  this hosted website and its services to jurisdictions under comprehensive
  U.S. sanctions (OFAC). Access has been blocked based on the region of your
  network address.</p>
  <p>This restriction is on the <strong>hosted service</strong> only. Postern's
  software is open source, and the <strong>Bloch protocol is ownerless and
  permissionless</strong> — no company operates or gates it.</p>
  <p class="note">Legal authority:
  <a href="https://ofac.treasury.gov/sanctions-programs-and-country-information" rel="nofollow noopener">U.S. OFAC sanctions programs</a>.
  If you believe this is a mistake, it may be your network's geolocation.</p>
</main></body></html>`;
}
