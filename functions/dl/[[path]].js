// Pages Function — /dl/<file>
//
// A privacy-preserving download counter for the Postern OS images AND the
// desktop app installers. It does ONE honest thing: keep an AGGREGATE per-file
// tally, then 302 the visitor to the real artifact. It deliberately records
// NOTHING about *who* downloads: no IP, no User-Agent, no per-user timestamp,
// no cookie. Just a number per file. This is what lets the site keep its "no
// telemetry" promise while still giving the operator an honest sense of reach.
// The tally counts download EVENTS, not unique people (no dedup by design).
//
// Counts are readable at /dl/stats (aggregate JSON, no PII).

const OS_BASE = "https://pub-dca67fd26bfb4a6b98115e596095ecd3.r2.dev/os/v0.1";

// R2-hosted OS images.
const ALLOW = new Set([
  "postern-os-node-x86_64.iso",
  "postern-os-desktop-x86_64.iso",
  "postern-os-mobile-pinephone-aarch64.img",
]);

// Same-origin static desktop app installers (served from the Pages root, not
// R2). Routed through here only to get the same aggregate, no-PII tally; the
// redirect stays same-origin so this cannot become an open redirect.
const SITE_ALLOW = new Set([
  "Postern-Desktop-macOS.dmg",
  "Postern-Desktop-Windows-x64.msi",
]);

export async function onRequest(context) {
  const { params, env, request } = context;
  const key = Array.isArray(params.path) ? params.path.join("/") : (params.path || "");

  // /dl/stats — aggregate counts, no PII. Cheap read-only view for the operator.
  if (key === "stats") {
    const out = {};
    if (env.DL_COUNTS) {
      for (const name of [...ALLOW, ...SITE_ALLOW]) {
        out[name] = Number(await env.DL_COUNTS.get(name)) || 0;
      }
    }
    out._note =
      "Aggregate per-file download counts (download EVENTS, not unique people). " +
      "No IP, User-Agent, or per-user data is recorded — only these tallies. KV " +
      "is eventually consistent and the increment is best-effort, so treat this " +
      "as an operational estimate, not an exact ledger.";
    return new Response(JSON.stringify(out, null, 2), {
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }

  const isOs = ALLOW.has(key);
  const isSite = SITE_ALLOW.has(key);
  if (!isOs && !isSite) {
    return new Response("Not found", { status: 404 });
  }

  // Count — aggregate only, best-effort. A lost race under concurrent hits is
  // acceptable for an ops metric; we never trade accuracy for anything that
  // would identify the downloader.
  if (env.DL_COUNTS) {
    const cur = Number(await env.DL_COUNTS.get(key)) || 0;
    context.waitUntil(env.DL_COUNTS.put(key, String(cur + 1)));
  }

  // OS images live on R2; desktop installers are same-origin static files. The
  // same-origin destination is built from the request URL, never from user
  // input, so /dl/ still cannot be abused as an open redirect.
  const dest = isOs
    ? `${OS_BASE}/${key}`
    : new URL(`/${key}`, request.url).toString();
  return Response.redirect(dest, 302);
}
