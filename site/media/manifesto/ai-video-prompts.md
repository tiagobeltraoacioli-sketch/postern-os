# "Why Postern" — AI video: platform pick + ready-to-paste prompts

## Which platform is best? (honest answer)

There is **no single tool** that outputs a finished manifesto with (a) cinematic
visuals, (b) accurate on-screen words, and (c) narration + subtitles in one shot.
AI text-to-video models render **specific text badly** (they'd mangle "POSTERN
LABS"), so the crisp words/glyph must be **overlaid in an editor**, not generated.

**Recommended stack (best result today):**
1. **Google Veo 3** (via *Google Flow* / Gemini) — **primary, best pick** for the
   cinematic, abstract B-roll: strong prompt adherence, native audio, ~8s clips.
   Generate one clip per scene from the prompts below.
2. **ElevenLabs** — the **narration voice** (grave documentary tone) from the
   script. (Veo 3 can voice too, but ElevenLabs is cleaner/consistent.)
3. **CapCut** (free) or **Descript / Premiere** — **assemble**: stitch the clips,
   import `why-postern.srt` for captions, and overlay the exact words + the gate
   glyph (`~/Downloads/postern-labs-brand.png`) as sharp text/PNG layers.

**Alternatives:** *Runway Gen-4* or *Kling 2.x* (swap for Veo 3 if unavailable);
*HeyGen / Synthesia* only if you want a narrated presenter (off-aesthetic here).
**Simplest one-tool path (lower quality):** paste the MASTER prompt into *Kling*
or *Pika*, generate ~8s hero clips, add captions in CapCut.

> If you'd rather skip AI video entirely: this storyboard is **type-driven** —
> a **kinetic-typography** cut in CapCut/After Effects would look cleaner and get
> every word right. Tell me and I'll deliver that edit spec instead.

---

## MASTER prompt (paste once; reuse the style for every scene)

> Cinematic, restrained, high-end title-sequence aesthetic. Palette: deep
> graphite/ink (#0d1014) with a single warm brass accent (#c9a648). Slow, grave,
> hopeful mood — like the cold open of a serious documentary. Volumetric haze,
> fine film grain, shallow depth of field, deliberate slow camera moves. Abstract
> and symbolic, NOT literal; NO coins, NO money, NO logos of other brands, NO
> people's faces in close-up, NO text baked into the image (text is added later).
> 16:9, 24fps, cinematic color grade.

**Negative prompt:** `coins, cryptocurrency symbols, dollar signs, charts, price
graphs, cartoonish, neon, glossy 3D crypto, stock-photo businessmen, watermarks,
gibberish text, on-screen captions`

---

## Per-scene prompts (one ~5–8s clip each; prepend the MASTER style)

1. **Open** — Pure black. A single thin horizontal line of brass light breathes in the center. Silence, then a low sub-bass swell.
2. **The question** — An arched gate / portcullis shape (an ancient postern door) draws itself in thin brass strokes on graphite, self-illuminated.
3. **The board with extra steps** — A cold, clinical wireframe diagram assembling: a central node wired to smaller nodes, one glowing "pause" switch; the whole thing feels corporate and dimming, slightly menacing.
4. **The mast** — A single ship's mast in fog; a heavy rope wraps and knots around it in slow motion; a small mechanical switch beside it greys out and locks shut.
5. **Three denials** — Minimal graphite void; three sharp brass slashes strike inward, one at a time, decisive.
6. **Property, life, privacy** — Warm dawn light bleeds into the graphite; three soft glowing orbs settle into a calm horizontal row.
7. **Penumbra** — Extreme close macro of a soft luminous halo — a penumbra — glowing at the edge of a dark disc (like a solar eclipse's edge).
8. **Code that does not drift** — Abstract streams of monospaced glyphs flow like water past the camera; one small brass constant stays perfectly still while everything around it flickers and ages.
9. **Verify, not trust** — A brass checkmark forms, dissolves into particles, and re-forms identically — recomputing itself, proving itself.
10. **The maker steps away** — A lone silhouette walks out of frame into fog; left behind, the brass gate glyph stands alone, self-lit and steady.
11. **Close** — The gate glyph holds center; brass light settles. (Wordmark POSTERN LABS + the honest footer are added as an editor overlay — not generated.)

---

## Narration (ElevenLabs)

- **Voice:** male or female, deep, unhurried, documentary gravitas; slight warmth
  by the end. British or neutral-international English. Stability high, style low.
- **Script:** use `why-postern-script.md` (the Narration column), in order.
- Export the voice track, drop it under the assembled visuals, then align
  `why-postern.srt` to it (nudge timings to the final voice pacing).

## Final card overlays (add crisp, in the editor — never AI-generated)
- Wordmark: **POSTERN LABS** (brass, letter-spaced) — or drop in the brand PNG.
- Small honest footer (must stay): *Pre-mainnet · unaudited · not a security ·
  not investment advice · the coin has no value claim, by design.*

Target length ~90–95s. Output `why-postern.mp4` → put it in the site home hero.
