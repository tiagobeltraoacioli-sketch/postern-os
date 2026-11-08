// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) Postern Labs and Postern community contributors
//
// Calendar-month + free-window helpers, and the up-front, honest disclosure
// text shown at first run.
//
// The free windows (business-freemium 24mo, corporate-master 6mo) are HONEST,
// self-disclosed clocks — not surveillance. The window bounds live inside the
// signed token (iat/exp); the disclosure simply renders them. There is NO
// phone-home and nothing about usage is transmitted.

import type { MasterToken, Tier } from "./types.js";

export const CORPORATE_MASTER_MONTHS = 6;
export const BUSINESS_FREEMIUM_MONTHS = 24;
export const BUSINESS_FREEMIUM_SEATS = 3;

/** Add N calendar months to an instant (UTC), clamping end-of-month. */
export function addMonthsUtc(from: Date, months: number): Date {
  const d = new Date(from.getTime());
  const targetMonth = d.getUTCMonth() + months;
  const day = d.getUTCDate();
  d.setUTCDate(1);
  d.setUTCMonth(targetMonth);
  // Clamp for shorter target months (e.g. Aug 31 + 6mo -> Feb 28/29).
  const lastDay = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)).getUTCDate();
  d.setUTCDate(Math.min(day, lastDay));
  return d;
}

/** Months for a given tier's free window. */
export function windowMonthsForTier(tier: Tier): number {
  switch (tier) {
    case "corporate-master":
      return CORPORATE_MASTER_MONTHS;
    case "business-freemium":
      return BUSINESS_FREEMIUM_MONTHS;
    case "personal":
      return 0;
  }
}

function titleCase(tier: string): string {
  return tier
    .split("-")
    .map((w) => (w.length > 0 ? w[0]!.toUpperCase() + w.slice(1) : w))
    .join(" ");
}

/**
 * Human-readable, up-front disclosure derived from a master token. Callers
 * should surface this verbatim at first run so the free-period terms are stated
 * honestly.
 */
export function disclosureForMaster(master: MasterToken): string {
  const p = master.payload;
  const months = windowMonthsForTier(p.tier);
  const start = new Date(p.iat * 1000).toUTCString();
  const end = new Date(p.exp * 1000).toUTCString();
  const seats = p.seats === "unlimited" ? "unlimited seats" : `up to ${p.seats} desktops`;
  return [
    `Postern ${titleCase(p.tier)} — free period (${seats}).`,
    ``,
    `This license is free to use for ${months} months.`,
    `  Free period began:  ${start}`,
    `  Free period ends:   ${end}`,
    ...(p.duns ? [`  Company DUNS:       ${p.duns} (format-checked; honor system)`] : []),
    ``,
    `After it ends, a license (billed in ordinary currency — not any token or`,
    `coin) is required for continued business use. Personal editions of Postern`,
    `are, and always will be, free and need no license at all.`,
    ``,
    `Verification is fully offline: nothing about your usage is transmitted.`,
  ].join("\n");
}
