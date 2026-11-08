#!/usr/bin/env python3
"""
Postern Labs — investor/funder deck generator.

Builds four files into this directory, from ONE shared content model:

    postern-kfw.pptx / postern-kfw.pdf                  (KfW funder pitch)
    postern-institutional.pptx / postern-institutional.pdf

Design: the Postern "sovereign secure instrument panel" identity
(graphite/ink surfaces, one warm brass accent, mono kickers) — the same
visual language as apps/sotto/index.html.

There is no LibreOffice in this environment, so the PDF is authored
directly with reportlab and the PPTX with python-pptx; both renderers
consume the same slide dictionaries and the same geometry (a 1280x720 px
space: 1 px = 9525 EMU for PPTX, 0.75 pt for PDF), and both use the same
Helvetica/Courier metrics for line wrapping, so the two formats match.

Usage:  python3 build_decks.py
Deps:   python-pptx, reportlab  (no network, no external fonts)
"""

import re
import os

from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas as pdfcanvas

from pptx import Presentation
from pptx.util import Emu, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

HERE = os.path.dirname(os.path.abspath(__file__))

# ----------------------------------------------------------------------
# palette — mirrors apps/sotto/index.html (dark instrument panel)
# ----------------------------------------------------------------------
BG        = "0d1014"
SURFACE   = "14181f"
SURFACE2  = "1a2029"
SURFACE3  = "212934"
BORDER    = "29323e"
BORDER_HI = "3a4552"
TEXT      = "e9e5da"
DIM       = "a8adb5"
MUTED     = "79818c"
BRASS     = "c9a648"
BRASS_HI  = "e4c465"
BRASS_DIM = "8f7630"
OK        = "63ab7c"
WARN      = "d08c2e"
LIVE      = "e4574f"

W, H = 1280.0, 720.0          # design space in "px"
MX = 72.0                     # side margin
CW = W - 2 * MX               # content width
TOP = 168.0                   # content top (below title chrome)
BOTTOM = 660.0                # content bottom (above footer)

# ----------------------------------------------------------------------
# text runs + shared wrapping (reportlab metrics drive BOTH backends)
# ----------------------------------------------------------------------

def pdf_font(mono, bold):
    if mono:
        return "Courier-Bold" if bold else "Courier"
    return "Helvetica-Bold" if bold else "Helvetica"


def pptx_font(mono):
    return "Courier New" if mono else "Helvetica"


# characters outside WinAnsi (reportlab base-14 fonts) -> safe fallback
PDF_SANITIZE = {"‖": "/", "→": ">", "≥": ">=", "✓": "-",
                "●": "•", "“": '"', "”": '"'}


def sanitize_pdf(s):
    for k, v in PDF_SANITIZE.items():
        s = s.replace(k, v)
    return s


def run(text, mono=False, bold=False, color=None):
    return {"t": text, "mono": mono, "bold": bold, "c": color}


BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def parse_runs(text, base_color=None, bold_color=None, mono=False):
    """Mini-markdown: **bold** segments become bold (and brighter)."""
    runs, pos = [], 0
    for m in BOLD_RE.finditer(text):
        if m.start() > pos:
            runs.append(run(text[pos:m.start()], mono=mono, color=base_color))
        runs.append(run(m.group(1), mono=mono, bold=True,
                        color=bold_color or base_color))
        pos = m.end()
    if pos < len(text):
        runs.append(run(text[pos:], mono=mono, color=base_color))
    return runs or [run("", color=base_color)]


def measure(text, mono, bold, size_px):
    return stringWidth(sanitize_pdf(text), pdf_font(mono, bold),
                       size_px * 0.75) / 0.75


def wrap_runs(runs, size_px, max_w_px):
    """Greedy word wrap over styled runs -> list of lines (lists of runs).

    Tokens carry a "glue" flag: a run that starts without whitespace after
    a run that ends without whitespace is part of the SAME word (e.g. a
    bold span followed by a period), so no space is inserted between them.
    """
    words = []  # (text, style_run, glue_to_previous)
    prev_flush = False  # previous run ended with a non-space character
    for r in runs:
        t = r["t"]
        if t == "":
            continue
        for i, w in enumerate(t.split(" ")):
            if w == "":
                continue
            glue = (i == 0 and not t.startswith(" ") and prev_flush
                    and bool(words))
            words.append((w, r, glue))
        prev_flush = not t.endswith(" ")
    lines, cur, cur_w = [], [], 0.0
    space = measure(" ", False, False, size_px)
    for wtext, r, glue in words:
        ww = measure(wtext, r["mono"], r["bold"], size_px)
        add = ww if (glue or not cur) else ww + space
        if cur and not glue and cur_w + add > max_w_px:
            lines.append(cur)
            cur, cur_w = [], 0.0
            add = ww
        cur.append((wtext, r, glue and bool(cur)))
        cur_w += add
    if cur:
        lines.append(cur)
    # merge words back into styled runs, inserting the separating spaces
    out = []
    for line in lines:
        merged = []
        for wtext, r, glue in line:
            sep = "" if (glue or not merged) else " "
            if merged and merged[-1][1] is r:
                merged[-1][0] += sep + wtext
            else:
                merged.append([sep + wtext, r])
        out.append([run(t, r["mono"], r["bold"], r["c"]) for t, r in merged])
    return out or [[run("")]]


def text_height(lines, size_px, leading):
    return len(lines) * size_px * leading


# ----------------------------------------------------------------------
# backends — same drawing interface, px coordinates, y from slide top
# ----------------------------------------------------------------------

class PptxBackend:
    name = "pptx"

    def __init__(self, title):
        self.prs = Presentation()
        self.prs.slide_width = Emu(int(W * 9525))
        self.prs.slide_height = Emu(int(H * 9525))
        self.slide = None

    def new_slide(self):
        self.slide = self.prs.slides.add_slide(self.prs.slide_layouts[6])
        f = self.slide.background.fill
        f.solid()
        f.fore_color.rgb = RGBColor.from_string(BG.upper())

    def rect(self, x, y, w, h, fill=None, stroke=None, stroke_w=1.0, radius=0):
        shp_type = MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE
        s = self.slide.shapes.add_shape(
            shp_type, Emu(int(x * 9525)), Emu(int(y * 9525)),
            Emu(int(w * 9525)), Emu(int(h * 9525)))
        if radius:
            try:
                s.adjustments[0] = max(0.0, min(0.5, radius / min(w, h)))
            except Exception:
                pass
        s.shadow.inherit = False
        if fill:
            s.fill.solid()
            s.fill.fore_color.rgb = RGBColor.from_string(fill.upper())
        else:
            s.fill.background()
        if stroke:
            s.line.color.rgb = RGBColor.from_string(stroke.upper())
            s.line.width = Pt(stroke_w * 0.75)
        else:
            s.line.fill.background()
        return s

    def hline(self, x, y, w, color, thickness=1.0):
        self.rect(x, y, w, thickness, fill=color)

    def dot(self, cx, cy, d, color):
        s = self.slide.shapes.add_shape(
            MSO_SHAPE.OVAL, Emu(int((cx - d / 2) * 9525)),
            Emu(int((cy - d / 2) * 9525)),
            Emu(int(d * 9525)), Emu(int(d * 9525)))
        s.shadow.inherit = False
        s.fill.solid()
        s.fill.fore_color.rgb = RGBColor.from_string(color.upper())
        s.line.fill.background()

    def text_lines(self, x, y, w, lines, size, color, align="l",
                   leading=1.35, tracking=0.0):
        tb = self.slide.shapes.add_textbox(
            Emu(int(x * 9525)), Emu(int((y - size * 0.18) * 9525)),
            Emu(int(w * 9525)),
            Emu(int((text_height(lines, size, leading) + size * 0.5) * 9525)))
        tf = tb.text_frame
        tf.word_wrap = False
        tf.auto_size = None
        for m in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
            setattr(tf, m, 0)
        aligns = {"l": PP_ALIGN.LEFT, "c": PP_ALIGN.CENTER, "r": PP_ALIGN.RIGHT}
        for i, line in enumerate(lines):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            p.alignment = aligns[align]
            p.line_spacing = leading
            p.space_before = 0
            p.space_after = 0
            for r in line:
                rn = p.add_run()
                rn.text = r["t"]
                rn.font.size = Pt(size * 0.75)
                rn.font.bold = r["bold"]
                rn.font.name = pptx_font(r["mono"])
                rn.font.color.rgb = RGBColor.from_string(
                    (r["c"] or color).upper())
                if tracking:
                    rPr = rn._r.get_or_add_rPr()
                    rPr.set("spc", str(int(tracking * 0.75 * 100)))

    def save(self, path):
        self.prs.save(path)


class PdfBackend:
    name = "pdf"

    def __init__(self, title):
        self._path = None
        self.c = None
        self._title = title
        self._first = True

    def _ensure(self):
        if self.c is None:
            self.c = pdfcanvas.Canvas(self._path, pagesize=(W * 0.75, H * 0.75))
            self.c.setTitle(self._title)
            self.c.setAuthor("Postern Labs")

    def set_path(self, path):
        self._path = path

    def new_slide(self):
        self._ensure()
        if not self._first:
            self.c.showPage()
        self._first = False
        self.c.setFillColor("#" + BG)
        self.c.rect(0, 0, W * 0.75, H * 0.75, stroke=0, fill=1)

    def _y(self, y_px):
        return (H - y_px) * 0.75

    def rect(self, x, y, w, h, fill=None, stroke=None, stroke_w=1.0, radius=0):
        c = self.c
        if fill:
            c.setFillColor("#" + fill)
        if stroke:
            c.setStrokeColor("#" + stroke)
            c.setLineWidth(stroke_w * 0.75)
        c.roundRect(x * 0.75, self._y(y + h), w * 0.75, h * 0.75,
                    radius * 0.75, stroke=1 if stroke else 0,
                    fill=1 if fill else 0)

    def hline(self, x, y, w, color, thickness=1.0):
        self.rect(x, y, w, thickness, fill=color)

    def dot(self, cx, cy, d, color):
        self.c.setFillColor("#" + color)
        self.c.circle(cx * 0.75, self._y(cy), (d / 2) * 0.75, stroke=0, fill=1)

    def text_lines(self, x, y, w, lines, size, color, align="l",
                   leading=1.35, tracking=0.0):
        c = self.c
        size_pt = size * 0.75
        tr_pt = tracking * 0.75
        for i, line in enumerate(lines):
            base_px = y + size * 0.82 + i * size * leading
            lw = sum(measure(r["t"], r["mono"], r["bold"], size)
                     for r in line) + tracking * max(
                0, sum(len(sanitize_pdf(r["t"])) for r in line) - 1)
            if align == "c":
                sx = x + (w - lw) / 2
            elif align == "r":
                sx = x + w - lw
            else:
                sx = x
            t = c.beginText(sx * 0.75, self._y(base_px))
            # ALWAYS set char space: Tc is persistent graphics state in
            # PDF, so a tracked kicker would otherwise leak into body text
            t.setCharSpace(tr_pt)
            for r in line:
                t.setFont(pdf_font(r["mono"], r["bold"]), size_pt)
                t.setFillColor("#" + (r["c"] or color))
                t.textOut(sanitize_pdf(r["t"]))
            c.drawText(t)

    def save(self, path):
        self.c.save()


# ----------------------------------------------------------------------
# drawing helpers (backend-agnostic)
# ----------------------------------------------------------------------

def draw_text(b, x, y, w, content, size, color=TEXT, mono=False, bold=False,
              align="l", leading=1.35, tracking=0.0, wrap=True,
              bold_color=None):
    """content: str (with **bold** spans, \\n = forced break) or run list."""
    if isinstance(content, str):
        lines = []
        for seg in content.split("\n"):
            runs = parse_runs(seg, base_color=color, bold_color=bold_color,
                              mono=mono)
            if bold:
                for r in runs:
                    r["bold"] = True
            lines += wrap_runs(runs, size, w * 0.94) if wrap else [runs]
    else:
        lines = wrap_runs(content, size, w * 0.94) if wrap else [content]
    b.text_lines(x, y, w, lines, size, color, align, leading, tracking)
    return text_height(lines, size, leading)


def measure_text(content, w, size, leading=1.35, color=TEXT, bold_color=None):
    runs = parse_runs(content, base_color=color, bold_color=bold_color) \
        if isinstance(content, str) else content
    return text_height(wrap_runs(runs, size, w * 0.94), size, leading)


def kicker(b, x, y, text, color=BRASS_DIM, size=11, align="l", w=CW):
    draw_text(b, x, y, w, text.upper(), size, color=color, mono=True,
              bold=True, align=align, tracking=2.2, wrap=False)


def chrome(b, slide, deck, idx, total):
    """Standard non-cover slide chrome: eyebrow, title, keyline, footer."""
    kicker(b, MX, 46, slide.get("eyebrow", deck["eyebrow"]))
    draw_text(b, MX, 76, CW, slide["title"], 30, color=TEXT, bold=True,
              leading=1.15, bold_color=BRASS_HI)
    b.hline(MX, 138, CW, BORDER, 1)
    b.hline(MX, 137, 120, BRASS, 2.4)
    footer(b, deck, idx, total)


def footer(b, deck, idx, total):
    b.hline(MX, 674, CW, BORDER, 1)
    kicker(b, MX, 686, "POSTERN LABS", color=MUTED, size=9.5)
    kicker(b, MX, 686, deck["tag"], color=MUTED, size=9.5, align="c", w=CW)
    kicker(b, MX, 686, "%02d / %02d" % (idx, total), color=BRASS_DIM,
           size=9.5, align="r", w=CW)


def panel(b, x, y, w, h, highlight=False, fill=SURFACE):
    b.rect(x, y, w, h, fill=fill,
           stroke=BRASS_DIM if highlight else BORDER,
           stroke_w=1.4 if highlight else 1.0, radius=10)


# ----------------------------------------------------------------------
# slide-kind renderers
# ----------------------------------------------------------------------

def render_cover(b, s, deck, idx, total):
    kicker(b, MX, 46, s["eyebrow"])
    kicker(b, MX, 46, s.get("date", ""), color=MUTED, align="r", w=CW)
    b.hline(MX, 70, CW, BORDER, 1)

    # wordmark: POSTERN (near-white) LABS (brass), wide-tracked mono
    wm = [run("POSTERN ", mono=True, bold=True, color=TEXT),
          run("LABS", mono=True, bold=True, color=BRASS)]
    b.text_lines(MX, 210, CW, [wm], 56, TEXT, align="c", tracking=16)

    b.hline(W / 2 - 70, 302, 140, BRASS, 2.4)

    draw_text(b, MX + 60, 330, CW - 120, s["headline"], 33, color=TEXT,
              bold=True, align="c", leading=1.2)
    draw_text(b, MX + 130, 420, CW - 260, s["sub"], 16.5, color=DIM,
              align="c", leading=1.5)

    kicker(b, MX, 560, s["foot"], color=MUTED, size=10.5, align="c", w=CW)
    if s.get("byline"):
        kicker(b, MX, 590, s["byline"], color=BRASS_DIM, size=10,
               align="c", w=CW)
    footer(b, deck, idx, total)


def render_grid(b, s, deck, idx, total):
    chrome(b, s, deck, idx, total)
    items, cols = s["items"], s.get("cols", 3)
    gap = 16.0
    y0 = TOP
    if s.get("intro"):
        y0 += draw_text(b, MX, y0, CW, s["intro"], 14.5, color=DIM,
                        leading=1.4, bold_color=TEXT) + 16
    rows = (len(items) + cols - 1) // cols
    pw = (CW - (cols - 1) * gap) / cols
    avail = BOTTOM - y0 - (16 if s.get("note") else 0) \
        - (measure_text(s["note"], CW, 12) if s.get("note") else 0)
    ph = (avail - (rows - 1) * gap) / rows
    for i, it in enumerate(items):
        r, cix = divmod(i, cols)
        x = MX + cix * (pw + gap)
        y = y0 + r * (ph + gap)
        panel(b, x, y, pw, ph, highlight=it.get("hi", False))
        pad = 18
        yy = y + pad
        kicker(b, x + pad, yy, it["kicker"],
               color=it.get("kcolor", BRASS), size=10)
        yy += 24
        if it.get("head"):
            yy += draw_text(b, x + pad, yy, pw - 2 * pad, it["head"], 15,
                            color=TEXT, bold=True, leading=1.2) + 6
        draw_text(b, x + pad, yy, pw - 2 * pad, it["body"], 12.5,
                  color=DIM, leading=1.42, bold_color=TEXT)
    if s.get("note"):
        draw_text(b, MX, BOTTOM - measure_text(s["note"], CW, 12), CW,
                  s["note"], 12, color=MUTED, leading=1.4, bold_color=DIM)


def render_rows(b, s, deck, idx, total):
    chrome(b, s, deck, idx, total)
    y0 = TOP
    if s.get("intro"):
        y0 += draw_text(b, MX, y0, CW, s["intro"], 14, color=DIM,
                        leading=1.35, bold_color=TEXT) + 12
    rows = s["rows"]
    gap = 9.0
    note_h = (measure_text(s["note"], CW, 12) + 12) if s.get("note") else 0
    rh = (BOTTOM - y0 - note_h - (len(rows) - 1) * gap) / len(rows)
    name_w = 250.0
    tag_w = 190.0
    for i, (name, desc, tag, hi) in enumerate(rows):
        y = y0 + i * (rh + gap)
        panel(b, MX, y, CW, rh, highlight=hi,
              fill=SURFACE2 if hi else SURFACE)
        pad = 18
        ty = y + (rh - 20) / 2 - 4
        draw_text(b, MX + pad, ty, name_w, name, 15,
                  color=BRASS_HI if hi else TEXT, bold=True, leading=1.15)
        dx = MX + pad + name_w + 14
        dw = CW - pad * 2 - name_w - 14 - tag_w - 10
        dh = measure_text(desc, dw, 12.5, leading=1.3)
        draw_text(b, dx, y + (rh - dh) / 2, dw, desc, 12.5, color=DIM,
                  leading=1.3, bold_color=TEXT)
        tcol = {"ok": OK, "warn": WARN, "brass": BRASS, "muted": MUTED}[tag[1]]
        kicker(b, MX + CW - pad - tag_w, y + (rh - 12) / 2, tag[0],
               color=tcol, size=9.5, align="r", w=tag_w)
    if s.get("note"):
        draw_text(b, MX, BOTTOM - note_h + 12, CW, s["note"], 12,
                  color=MUTED, leading=1.4, bold_color=DIM)


def render_split(b, s, deck, idx, total):
    chrome(b, s, deck, idx, total)
    gap = 20.0
    cw2 = (CW - gap) / 2
    note_h = (measure_text(s["note"], CW, 12.5) + 16) if s.get("note") else 0
    ph = BOTTOM - TOP - note_h
    for cix, col in enumerate((s["left"], s["right"])):
        x = MX + cix * (cw2 + gap)
        panel(b, x, TOP, cw2, ph, highlight=col.get("hi", False))
        pad = 22
        yy = TOP + pad
        kicker(b, x + pad, yy, col["kicker"],
               color=col.get("kcolor", BRASS), size=10.5)
        yy += 26
        yy += draw_text(b, x + pad, yy, cw2 - 2 * pad, col["head"], 17,
                        color=TEXT, bold=True, leading=1.2) + 12
        for btext in col["bullets"]:
            runs = [run("–  ", bold=True, color=BRASS)] + \
                parse_runs(btext, base_color=DIM, bold_color=TEXT)
            yy += draw_text(b, x + pad, yy, cw2 - 2 * pad, runs, 13,
                            color=DIM, leading=1.38) + 9
    if s.get("note"):
        draw_text(b, MX, BOTTOM - note_h + 16, CW, s["note"], 12.5,
                  color=MUTED, leading=1.4, bold_color=DIM)


def render_ledger(b, s, deck, idx, total):
    chrome(b, s, deck, idx, total)
    y0 = TOP
    if s.get("intro"):
        y0 += draw_text(b, MX, y0, CW, s["intro"], 14.5, color=DIM,
                        leading=1.4, bold_color=TEXT) + 14
    rows = s["rows"]
    gap = 10.0
    note_h = (measure_text(s["note"], CW, 12.5) + 14) if s.get("note") else 0
    pad = 18
    body_w = CW - 2 * pad - 46
    heights = []
    for tone, head, body in rows:
        hh = 20 + measure_text(body, body_w, 12.5, leading=1.38) + 8
        heights.append(hh + 2 * (pad - 6))
    scale = min(1.0, (BOTTOM - y0 - note_h - (len(rows) - 1) * gap) /
                sum(heights))
    y = y0
    for (tone, head, body), hh in zip(rows, heights):
        hh *= scale
        panel(b, MX, y, CW, hh, fill=SURFACE)
        color = {"ok": OK, "warn": WARN}[tone]
        b.dot(MX + pad + 10, y + pad + 4, 9, color)
        tx = MX + pad + 46
        yy = y + pad - 6
        yy += draw_text(b, tx, yy, body_w, head, 14, color=TEXT, bold=True,
                        leading=1.2) + 4
        draw_text(b, tx, yy, body_w, body, 12.5, color=DIM, leading=1.38,
                  bold_color=TEXT)
        y += hh + gap
    if s.get("note"):
        draw_text(b, MX, BOTTOM - note_h + 14, CW, s["note"], 12.5,
                  color=MUTED, leading=1.42, bold_color=DIM)


def render_close(b, s, deck, idx, total):
    kicker(b, MX, 46, s.get("eyebrow", deck["eyebrow"]))
    b.hline(MX, 70, CW, BORDER, 1)
    b.hline(W / 2 - 70, 216, 140, BRASS, 2.4)
    draw_text(b, MX + 40, 246, CW - 80, s["statement"], 30, color=TEXT,
              bold=True, align="c", leading=1.3, bold_color=BRASS_HI)
    draw_text(b, MX + 110, 388, CW - 220, s["body"], 15.5, color=DIM,
              align="c", leading=1.55, bold_color=TEXT)
    kicker(b, MX, 560, s["contact"], color=MUTED, size=10.5, align="c", w=CW)
    wm = [run("POSTERN ", mono=True, bold=True, color=TEXT),
          run("LABS", mono=True, bold=True, color=BRASS)]
    b.text_lines(MX, 596, CW, [wm], 18, TEXT, align="c", tracking=8)
    footer(b, deck, idx, total)


RENDERERS = {"cover": render_cover, "grid": render_grid, "rows": render_rows,
             "split": render_split, "ledger": render_ledger,
             "close": render_close}


# ----------------------------------------------------------------------
# shared content fragments (used by both decks)
# ----------------------------------------------------------------------

def protocol_vs_company(note):
    return {
        "kind": "split", "title": "Two things, deliberately separate",
        "left": {
            "kicker": "THE PROTOCOL · OWNERLESS", "kcolor": MUTED,
            "head": "Bloch-SIS-PoW",
            "bullets": [
                "A post-quantum proof-of-work protocol: SHAKE-256 hashcash "
                "PoW with a Module-SIS structural gate, hybrid "
                "**Falcon‖ML-DSA** lattice signatures.",
                "**No owner, no foundation, no official site or explorer** "
                "— it exposes RPC/APIs, and that is all. Like Bitcoin: "
                "public infrastructure that third parties build on.",
                "Today: a **zero-security testnet, unaudited, explicitly "
                "worth nothing by design** until independently audited.",
                "**No token sale, no listing effort — ever.** The coin "
                "funds nothing and is marketed to no one. Disclosed in full: "
                "a **17% founder premine** (10-yr cliff, 40-yr vest), "
                "structurally passive — the single fact a skeptic weighs "
                "against ‘ownerless’, kept visible on purpose.",
            ],
        },
        "right": {
            "kicker": "THE COMPANY · OWNED PRODUCTS", "kcolor": BRASS,
            "head": "Postern Labs", "hi": True,
            "bullets": [
                "A **product company** — the BlackBerry model: it sells "
                "privacy and security software. You pay for protection, "
                "support and provable integrity, **never for a coin**.",
                "Products are fully rebranded away from “Bloch”; "
                "only the wallet and explorer touch the protocol, and only "
                "through its **public RPC/API** — like anyone else.",
                "Revenue that betrays nothing: **grants, paid signed builds "
                "& support, organizational deployments.**",
                "Differentiator: **reproducible + remotely attestable** — "
                "a Postern product can prove it is the genuine build.",
            ],
        },
        "note": note,
    }


def portfolio_rows(intro, note):
    return {
        "kind": "rows", "title": "The product portfolio",
        "intro": intro,
        "rows": [
            ("Postern Container",
             "Hardened, isolated, **attestable privacy workspace on the "
             "Android phone you already own** — sensitive apps, data and "
             "comms sealed off. The low-friction entry product.",
             ("DESIGN SPEC", "muted"), False),
            ("Postern OS — Desktop",
             "Daily-driver privacy Linux: reproducible, hardened, encrypted, "
             "private-by-default. “Personalized Linux.”",
             ("FOUNDATIONS BUILT", "warn"), False),
            ("Postern OS — Mobile",
             "Privacy phone Linux — adds protection to the device; "
             "deliberately never rewards the user with tokens.",
             ("FOUNDATIONS BUILT", "warn"), False),
            ("Postern Seal",
             "The integrity proof: reproducible build + hardening + TEE "
             "attestation — **proves a device runs the genuine, "
             "unmodified Postern build.**",
             ("L1–L2 VERIFIED", "ok"), False),
            ("Postern Wallet",
             "Post-quantum hybrid wallet (Falcon‖ML-DSA), diversified "
             "addresses, on-device key vault. Consumes the protocol via "
             "public RPC/API.",
             ("BUILT · TESTNET", "warn"), False),
            ("Postern Explorer",
             "Independent explorer/dashboard on the protocol’s RPC/API "
             "— the way mempool.space is independent of Bitcoin.",
             ("DEPLOYED", "ok"), False),
            ("S·OTTO",
             "**Privacy-first voice assistant on the user’s own Claude "
             "account** — no Postern server, no account, no telemetry. "
             "The Postern thesis in consumer form.",
             ("WORKING PROTOTYPE", "brass"), True),
        ],
        "note": note,
    }


def sotto_spotlight(eyebrow):
    return {
        "kind": "split", "eyebrow": eyebrow,
        "title": "Sotto — a voice assistant that keeps its voice down",
        "left": {
            "kicker": "WHAT IT IS", "kcolor": BRASS, "hi": True,
            "head": "“Sotto voce” — sovereign, "
                    "user-owned, push-to-talk",
            "bullets": [
                "A Siri-class voice assistant — speak or type, hear it "
                "answer, set timers — shipped as **one readable HTML "
                "page** anyone can inspect.",
                "**Push-to-talk only.** The microphone is captured only "
                "while the user holds the orb or the space bar — never "
                "in the background.",
                "The user connects **their own Claude account with their "
                "own Anthropic API key**. Postern operates no server: no "
                "middleman, no account, no telemetry, no analytics.",
                "Key and conversation live **only in the user’s "
                "browser**; one click erases everything. There is no server "
                "copy — none exists.",
            ],
        },
        "right": {
            "kicker": "WHY IT MATTERS", "kcolor": MUTED,
            "head": "The thesis, demonstrated in a consumer app",
            "bullets": [
                "**Sovereignty as a product**: the user owns the "
                "relationship with their model provider directly — no "
                "intermediary to breach, subpoena or monetize.",
                "It shows the private-by-default stack is **not just "
                "expert infrastructure** — it can be a mainstream, "
                "pleasant consumer experience.",
                "**Honesty in the UI**: its privacy panel states exactly "
                "who sees what — including what is **not** private "
                "(next slide).",
                "Status today: **working prototype** (apps/sotto). The "
                "shipping product fills the wired engine slot with "
                "**on-device Whisper** speech recognition.",
            ],
        },
    }


def sotto_ledger(eyebrow):
    return {
        "kind": "ledger", "eyebrow": eyebrow,
        "title": "Sotto — the honest privacy ledger",
        "intro": "Sotto never claims “100% private.” It claims "
                 "**no extra parties** — and states, inside the "
                 "product, exactly who sees what:",
        "rows": [
            ("warn", "Your words → Anthropic — only when you send",
             "Conversation text goes from the browser **directly to "
             "api.anthropic.com under the user’s own key** — no "
             "middleman relays or logs it. Anthropic’s own terms apply "
             "to the user directly. Send nothing, transmit nothing."),
            ("warn", "Your voice → the browser vendor — only while "
             "you hold to talk",
             "Browser Web-Speech transcription **may send audio to the "
             "browser vendor’s servers** — so voice input is not "
             "fully private, and Sotto says so. Typing is offered as the "
             "fully local path; the shipping product fills the same engine "
             "slot with **on-device Whisper (whisper.cpp/WASM)**."),
            ("ok", "Spoken replies — on-device",
             "Text-to-speech uses the operating system’s own voices; "
             "the audio is generated locally and never leaves the machine."),
            ("ok", "Key, settings, conversation — this browser only",
             "API key in localStorage; conversation in tab memory, gone on "
             "close. “Erase everything” wipes it all instantly."),
        ],
        "note": "This candour is the point: **overclaiming to at-risk users "
                "is the one unforgivable sin.** Sotto’s guarantee is "
                "precise — no Postern servers, no resellers, no "
                "analytics; the only network destination in its code is "
                "api.anthropic.com.",
    }


def founder_slide(eyebrow=None):
    s = {
        "kind": "grid", "cols": 2,
        "title": "The founder",
        "items": [
            {"kicker": "FOUNDER & CEO · POSTERN LABS · 2026–PRESENT",
             "kcolor": BRASS, "hi": True,
             "head": "Tiago Tenório (“TT”)",
             "body": "Tiago Tenório (TT) is the founder and CEO of Postern "
                     "Labs. He comes from Brazil's payments and fintech "
                     "sector — a Visa prepaid/third-party ISO agent "
                     "(2018–2020); founder of the AG47 office and a member "
                     "of C6 Bank's Conexão C6 program, operating across São "
                     "Paulo, Goiás, the Federal District, Alagoas and Paraná "
                     "(2020–2021); a national distribution partner in First "
                     "Data Corporation's Ignite program for acquiring "
                     "products and services (2020–2021); PMO lead on a cards "
                     "project at Havan (2021–2022); and Commercial Director "
                     "at Avalon Capital, an asset manager (2022). In 2026 he "
                     "founded Postern Labs to build privacy-first, "
                     "post-quantum software — and the ownerless "
                     "Bloch-SIS-PoW protocol its products build on, in "
                     "which he holds no privileged role beyond a fully "
                     "disclosed, structurally passive 17% founder premine."},
            {"kicker": "ROLES, NOT ENDORSEMENTS", "kcolor": MUTED,
             "head": "Stated plainly",
             "body": "Full name: **Tiago B. de A. Tenório**.\n"
                     "The companies named opposite — Visa, C6 Bank, First "
                     "Data, Havan, Avalon Capital — state his prior roles "
                     "only: **none of them endorses, backs, funds or is "
                     "affiliated with Postern Labs or Bloch-SIS-PoW.**\n"
                     "LinkedIn: www.linkedin.com/in/"
                     "tiago-b-de-a-tenorio-a-a028733bb"},
        ],
    }
    if eyebrow:
        s["eyebrow"] = eyebrow
    return s


# ----------------------------------------------------------------------
# DECK 1 — KfW funder pitch
# ----------------------------------------------------------------------

KFW = {
    "file": "postern-kfw",
    "title": "Postern Labs — Funding Proposal (KfW)",
    "eyebrow": "POSTERN LABS · FUNDING PROPOSAL",
    "tag": "KFW — CONFIDENTIAL DRAFT",
    "slides": [
        {
            "kind": "cover",
            "eyebrow": "FUNDING PROPOSAL · PREPARED FOR KFW",
            "date": "JULY 2026",
            "headline": "Private by default. Provable by design.",
            "sub": "Permissive-licensed privacy and security infrastructure "
                   "— reproducible, remotely attestable, and honest "
                   "about its limits. A proposal for public-interest funding "
                   "of the three gates that genuinely need it: an "
                   "independent audit, hardware attestation, and mobile "
                   "SDKs.",
            "foot": "CONFIDENTIAL DRAFT · NO TOKEN IS SOLD, LISTED OR "
                    "MARKETED · NO USER-KYC, EVER · ORGANIZING AS A "
                    "WYOMING, USA LLC",
            "byline": "Tiago Tenório (TT) · Founder & CEO",
        },
        {
            "kind": "grid", "cols": 2,
            "title": "The problem: privacy is the exception, "
                     "not the default",
            "items": [
                {"kicker": "SURVEILLANCE BY DEFAULT",
                 "head": "Being observed is the price of participation",
                 "body": "Mainstream platforms monetize behavioural data. "
                         "For most people, carrying a phone or sharing a "
                         "document means being profiled by default — "
                         "privacy is an expert exercise, not a starting "
                         "point."},
                {"kicker": "METADATA — THE LEAK NOBODY FIXES",
                 "head": "Documents betray their authors",
                 "body": "Office files, PDFs and photos leak author names, "
                         "employers, GPS positions and full revision "
                         "history (OOXML docProps, PDF XMP, image EXIF). A "
                         "documented, unglamorous hole that mainstream "
                         "tooling leaves open — and the permissive "
                         "open-source world lacks tools to close."},
                {"kicker": "TRUST YOU CANNOT VERIFY",
                 "head": "“Secure” still means “trust "
                         "us”",
                 "body": "Even hardened devices ask for blind trust: a user "
                         "cannot prove that their device is running the "
                         "genuine, unmodified build of its software rather "
                         "than a tampered one."},
                {"kicker": "WHO PAYS THE PRICE", "kcolor": WARN,
                 "head": "The people who need privacy most",
                 "body": "Investigative journalists, human-rights and "
                         "defense lawyers, NGO researchers handle sensitive "
                         "material with consumer-grade tools — and "
                         "overclaiming “secure” products puts "
                         "exactly these people at risk."},
            ],
        },
        {
            "kind": "grid", "cols": 4,
            "title": "The Postern thesis",
            "intro": "Postern Labs builds privacy and security software on "
                     "permissive open source — governed by four "
                     "non-negotiable commitments:",
            "items": [
                {"kicker": "01 · PRIVATE BY DEFAULT",
                 "head": "The default is silence",
                 "body": "Scrub, encrypt and isolate by default. Disclosure "
                         "is an explicit, user-held opt-in switch — "
                         "never the network’s decision, never a "
                         "gatekeeper’s."},
                {"kicker": "02 · PROVABLE, NOT PROMISED",
                 "head": "Reproducible + attestable",
                 "body": "Reproducible builds plus remote attestation: a "
                         "Postern device can prove it runs the genuine, "
                         "unmodified build. The differentiator over "
                         "GrapheneOS or stock Linux, which harden but "
                         "cannot prove."},
                {"kicker": "03 · PERMISSIVE-LICENSED",
                 "head": "MIT / Apache / BSD only",
                 "body": "No AGPL/GPL code embedded, ever — enforced "
                         "in CI. The whole stack stays auditable, reusable "
                         "and embeddable by anyone, including other "
                         "public-interest projects."},
                {"kicker": "04 · HONEST BY CONSTITUTION",
                 "head": "Claims are audit-gated",
                 "body": "Verified, built, designed and gated are kept "
                         "distinct — in the docs and in the product "
                         "UI. No fabricated traction, no overclaiming to "
                         "at-risk users."},
            ],
        },
        protocol_vs_company(
            "Funding would support **Postern Labs — the company and "
            "its open-source security work.** The protocol remains "
            "ownerless and receives no privileges; diligence is on the "
            "company, never on users."),
        portfolio_rows(
            "Owned, rebranded products — each honestly labelled with "
            "what exists today. Product names are provisional.",
            "Status tags reflect the internal status table verbatim: "
            "**verified / built / foundations / design** — nothing "
            "here is inflated. The full daily-driver OS and the Android "
            "container are still to build."),
        sotto_spotlight("PRODUCT SPOTLIGHT · S·OTTO"),
        sotto_ledger("PRODUCT SPOTLIGHT · S·OTTO"),
        {
            "kind": "grid", "cols": 3,
            "title": "What exists today — verified, honestly labelled",
            "items": [
                {"kicker": "PROTOCOL CORE", "kcolor": OK,
                 "body": "Proof-of-work node (SHAKE-256 hashcash with a "
                         "Module-SIS structural gate) **mines and "
                         "verifies end-to-end**; hybrid Falcon‖ML-DSA "
                         "signatures built and tested. **Unaudited**; "
                         "estimator research done — PoW security is "
                         "cumulative hash work, not lattice hardness; "
                         "canonical gate parameters being finalized."},
                {"kicker": "SECURITY DISCIPLINE", "kcolor": OK,
                 "body": "Eight internally-found vulnerabilities fixed; "
                         "consensus audit pass, fuzzing, dependency-license "
                         "and secret scanning in CI. **Internal only "
                         "— not yet third-party.**"},
                {"kicker": "DESKTOP + EXPLORER", "kcolor": OK,
                 "body": "Postern Desktop (Tauri) builds and runs: node "
                         "control, wallet, miner. The explorer is deployed. "
                         "Reproducible NixOS profiles exist for desktop "
                         "and mobile — **foundations, not daily-driver "
                         "claims.**"},
                {"kicker": "NINE PRODUCT CRATES", "kcolor": WARN,
                 "body": "Tested Rust cores: in-process Tor (Arti), "
                         "metadata hygiene, Matrix E2EE, secrets vault, "
                         "document quarantine, attestation companion, PQ "
                         "file courier, passkeys, panic lock. **Cores, not "
                         "yet products** — UI and packaging land with "
                         "Postern Suite v0.1."},
                {"kicker": "ATTESTATION", "kcolor": WARN,
                 "body": "L1 reproducible-build digest and L2 hardening "
                         "profile **verified**; the hardware TEE level is "
                         "designed but **not yet run on real SEV-SNP "
                         "hardware** — one of the funded items."},
                {"kicker": "SOTTO", "kcolor": BRASS,
                 "body": "**Working prototype** — the first "
                         "consumer-shaped Postern app, shipped as a single "
                         "auditable HTML file with its honest privacy "
                         "ledger built into the product."},
            ],
            "note": "One maintainer, wide surface — stated plainly. "
                    "The current phase converts breadth into two finished "
                    "edges: a credible canonical proof-of-work and one "
                    "shippable product.",
        },
        {
            "kind": "split",
            "title": "Roadmap — every claim behind its gate",
            "left": {
                "kicker": "PROTOCOL · PATH TO AN AUDITABLE CANDIDATE",
                "kcolor": MUTED,
                "head": "Six gates, in strict order",
                "bullets": [
                    "**G1–G3** Estimator research published honestly "
                    "(PoW security = cumulative hash work; no lattice "
                    "bit-security claim) → canonical gate parameters "
                    "frozen with a no-shortcut analysis → node mining "
                    "them. Self-funded, in progress.",
                    "**G4** Public ePrint parameter rationale — free "
                    "academic scrutiny *before* any paid audit.",
                    "**G5** Live multi-node WAN network plus an "
                    "adversarial test harness.",
                    "**G6** Third-party audit — **the only paid "
                    "gate.** Only after all six: “auditable mainnet "
                    "candidate.” Honest horizon: **6–12+ "
                    "months.**",
                ],
            },
            "right": {
                "kicker": "PRODUCTS · SHIP ONE REAL THING AT A TIME",
                "kcolor": BRASS,
                "head": "Flagship first, then the phone",
                "bullets": [
                    "**Postern Suite v0.1** — desktop privacy toolbox "
                    "(scrub / vault / quarantine / verify / panic) with "
                    "the metadata-hygiene wedge. Buildable now, weeks away.",
                    "**Hygiene CLI** for journalists and developers ships "
                    "the same week — the cheapest proof Postern is "
                    "real.",
                    "**Postern Container (Android) MVP** and mobile SDK "
                    "builds — the funded item.",
                    "**Seal on real TEE hardware**, then attestation "
                    "verification for organizations.",
                    "**Sotto**: on-device Whisper engine and a packaged "
                    "release alongside the Suite.",
                ],
            },
            "note": "Forward-looking items above are **plans, not "
                    "promises** — sequenced, costed and gated; none "
                    "are presented as existing traction.",
        },
        founder_slide("FUNDING PROPOSAL · THE FOUNDER"),
        {
            "kind": "grid", "cols": 3,
            "title": "The ask — fund the external gates",
            "intro": "Everything Postern can do alone is already underway "
                     "at near-zero cost. Grant support is requested only "
                     "for the **three gates that genuinely need money** "
                     "— a scoped budget is available on request:",
            "items": [
                {"kicker": "01 · INDEPENDENT AUDIT", "kcolor": BRASS,
                 "head": "Third-party security audit",
                 "body": "Narrowly scoped: canonical PoW parameters, "
                         "consensus and reorg logic, hybrid post-quantum "
                         "signatures, serialization. **The single gate "
                         "between “built and tested” and "
                         "“independently verified”** — and "
                         "the largest cost. Sequenced after free academic "
                         "review (ePrint) to keep it cheap and "
                         "well-scoped."},
                {"kicker": "02 · HARDWARE ATTESTATION", "kcolor": BRASS,
                 "head": "Remote attestation on real silicon",
                 "body": "End-to-end attestation on real "
                         "confidential-computing hardware (SEV-SNP / TPM): "
                         "real quotes, full verify chain. Turns Postern "
                         "Seal from a **verified design into a "
                         "demonstrable public good** — provable "
                         "integrity for any Linux user."},
                {"kicker": "03 · MOBILE SDKS + CONTAINER",
                 "kcolor": BRASS,
                 "head": "The private stack, on phones",
                 "body": "Android/iOS SDK builds (cargo-ndk, xcframework), "
                         "the Postern Container MVP with hardware-backed "
                         "keys, and the on-device Whisper engine that "
                         "makes Sotto’s voice path fully local. "
                         "**Brings private-by-default to the device "
                         "people actually carry.**"},
            ],
            "note": "No funding amount is stated in this draft — the "
                    "scoped budget per work package is prepared separately "
                    "with the founder.",
        },
        {
            "kind": "grid", "cols": 2,
            "title": "Why this fits public-interest funding",
            "items": [
                {"kicker": "OPEN INFRASTRUCTURE, PERMISSIVELY",
                 "head": "Funded work stays a public good",
                 "body": "Everything funded is and remains open source "
                         "under **permissive licenses** (MIT / Apache-2.0 "
                         "/ BSD) — auditable, reusable and embeddable "
                         "by anyone, including other publicly funded "
                         "projects. Reproducible builds and post-quantum "
                         "migration are core deliverables, not add-ons."},
                {"kicker": "DILIGENCE ON THE COMPANY — NEVER ON USERS",
                 "head": "Full transparency, zero user-KYC",
                 "body": "Postern Labs accepts complete diligence on the "
                         "company, its finances and its code. It will "
                         "**never impose identity checks on users** — "
                         "the journalists, lawyers and researchers who "
                         "need these tools most are exactly the people an "
                         "identity gate excludes or endangers."},
                {"kicker": "AN ESTABLISHED FUNDING CLASS",
                 "head": "NLnet / OTF / Sovereign Tech Fund territory",
                 "body": "The request follows the established "
                         "public-interest model: grants for permissive "
                         "privacy infrastructure. **No token is sold, "
                         "listed or marketed; funding never touches the "
                         "coin** — though a **17% founder premine** (10-yr "
                         "cliff, 40-yr vest) is disclosed in full and kept "
                         "structurally passive. Postern declines any funding "
                         "incompatible with permissive licensing or the "
                         "no-user-KYC rule."},
                {"kicker": "HONESTY AS POLICY", "kcolor": WARN,
                 "head": "This proposal contains no inflated claims",
                 "body": "Status tables distinguish verified / built / "
                         "designed / gated. The protocol is called what it "
                         "is — an unaudited zero-security testnet. "
                         "Forward-looking items are labelled plans. **The "
                         "candour is the product’s core feature, and "
                         "this document’s.**"},
            ],
        },
        {
            "kind": "close",
            "statement": "Private by default. Provable by design.\n"
                         "Honest by constitution.",
            "body": "Bloch-SIS-PoW is an ownerless, post-quantum protocol "
                    "— no owner, no site, no token sale, worth nothing "
                    "by design until independently audited. **Postern Labs "
                    "sells privacy and security software** — the "
                    "BlackBerry model on permissive open source: protection, "
                    "support and provable integrity, never a coin. Your "
                    "funding closes the three gates the mission cannot "
                    "close alone. **Postern is organizing as a Wyoming, "
                    "USA LLC.**",
            "contact": "CONTACT: TIAGO TENÓRIO (TT) · FOUNDER & CEO "
                       "· SCOPED BUDGET AVAILABLE ON REQUEST",
        },
    ],
}

# ----------------------------------------------------------------------
# DECK 2 — institutional presentation
# ----------------------------------------------------------------------

INSTITUTIONAL = {
    "file": "postern-institutional",
    "title": "Postern Labs — Institutional Presentation",
    "eyebrow": "POSTERN LABS · INSTITUTIONAL",
    "tag": "INSTITUTIONAL",
    "slides": [
        {
            "kind": "cover",
            "eyebrow": "INSTITUTIONAL PRESENTATION",
            "date": "JULY 2026",
            "headline": "Privacy and security software you can verify.",
            "sub": "Postern Labs is a product company on permissive open "
                   "source: reproducible, remotely attestable, and honest "
                   "about its limits. You pay for protection, support and "
                   "provable integrity — never for a coin.",
            "foot": "PERMISSIVE-LICENSED · AUDIT-GATED CLAIMS · "
                    "NO USER-KYC, EVER · ORGANIZING AS A WYOMING, USA LLC",
            "byline": "Tiago Tenório (TT) · Founder & CEO",
        },
        {
            "kind": "grid", "cols": 2,
            "title": "Who we are",
            "items": [
                {"kicker": "THE BLACKBERRY MODEL",
                 "head": "A product company, not a token project",
                 "body": "Postern Labs sells privacy and security software: "
                         "protection, support and provable integrity. "
                         "Customers pay for the product — **never for "
                         "a coin.** Revenue: paid signed builds and "
                         "support, organizational deployments, grants for "
                         "the open-source core. **Postern is organizing as "
                         "a Wyoming, USA LLC.**"},
                {"kicker": "ON PERMISSIVE OPEN SOURCE",
                 "head": "Free source, honest business",
                 "body": "Built on permissive Linux and a "
                         "permissive-license rule enforced in CI: MIT / "
                         "Apache-2.0 / BSD only, **AGPL/GPL never forked "
                         "or embedded.** The source always stays free and "
                         "buildable by anyone."},
                {"kicker": "WHO IT SERVES",
                 "head": "Document-handling professionals under pressure",
                 "body": "Investigative journalists, human-rights and "
                         "defense lawyers, NGO researchers — plus the "
                         "newsrooms, firms and NGOs that equip them. "
                         "At-risk users are **served, never marketed to.**"},
                {"kicker": "WHAT MAKES IT DIFFERENT", "kcolor": BRASS,
                 "head": "Provable, and honest about limits",
                 "body": "**Reproducible + remotely attestable**: a Postern "
                         "product can prove it is the genuine, unmodified "
                         "build — where others ask for trust. And an "
                         "honesty rule: every claim audit-gated, every "
                         "limit stated in the product UI."},
            ],
        },
        founder_slide("INSTITUTIONAL · THE FOUNDER"),
        protocol_vs_company(
            "Postern Labs owns its products; the protocol has no owner and "
            "grants no privileges. The wallet and explorer consume it the "
            "same way anyone else can — through the public RPC/API."),
        {
            "kind": "grid", "cols": 4,
            "title": "Principles — the non-negotiables",
            "items": [
                {"kicker": "PRIVACY + SECURITY",
                 "head": "Both, by default",
                 "body": "Scrub, encrypt, isolate by default; disclosure "
                         "is the user’s explicit opt-in (view-key "
                         "style), never the network’s or a "
                         "gatekeeper’s decision."},
                {"kicker": "HONESTY, AUDIT-GATED",
                 "head": "Say what is verified",
                 "body": "Verified / built / designed / gated are kept "
                         "distinct — in docs and in the UI. Unaudited "
                         "means unaudited, and the product says so. No "
                         "overclaiming, especially to at-risk users."},
                {"kicker": "PERMISSIVE ONLY",
                 "head": "MIT / Apache / BSD",
                 "body": "MPL tolerated only as unmodified aggregation; "
                         "**AGPL/GPL never forked or embedded** — "
                         "Element, libsignal, Bitwarden, ONLYOFFICE are "
                         "ruled out by policy, and CI enforces it across "
                         "every dependency tree."},
                {"kicker": "NO GATEKEEPERS",
                 "head": "No user-KYC, ever",
                 "body": "Identity gates exclude or endanger exactly the "
                         "people who need these tools most. Compliance "
                         "lives at the edge, in the user’s hands "
                         "— or it is surveillance."},
            ],
        },
        portfolio_rows(
            "The portfolio — owned, rebranded, each product honestly "
            "labelled with its real status. Names are provisional.",
            "**Foundations today, products next**: the roadmap ships one "
            "real thing at a time — Postern Suite (desktop) first, "
            "the Android container second, the full OS as destination."),
        {
            "kind": "grid", "cols": 3,
            "title": "The app layer — cores built, permissively",
            "intro": "Nine tested Rust cores fill out the products — "
                     "every dependency permissive, every limit stated:",
            "items": [
                {"kicker": "HYGIENE · THE WEDGE", "kcolor": BRASS,
                 "body": "**Scrub metadata by default** from Office files, "
                         "PDFs and images (author, GPS, revision history); "
                         "prove/seal by opt-in. Incumbent tools are "
                         "GPL/LGPL — a permissive Rust engine is the "
                         "moat, and it demos in ten seconds."},
                {"kicker": "TOR / VPN",
                 "body": "**Arti in-process Tor** — no external app "
                         "— already wired into Postern Desktop; "
                         "WireGuard (boringtun) next. The container’s "
                         "always-on dependency."},
                {"kicker": "VAULT + PANIC LOCK",
                 "body": "AEAD-sealed secrets vault, TEE/Argon2-keyed, "
                         "tamper-detected. **Panic Lock re-locks everything "
                         "instantly — denies access, never destroys "
                         "evidence** (a deliberate ethics call)."},
                {"kicker": "MESSENGER · MATRIX",
                 "body": "Fresh Apache-licensed client on matrix-rust-sdk; "
                         "Megolm E2EE core tested offline. Honest limits "
                         "stated: the homeserver sees the social graph, "
                         "and Megolm is classical — **not yet "
                         "post-quantum.**"},
                {"kicker": "COURIER + QUARANTINE",
                 "body": "Serverless P2P file drop over ephemeral Tor "
                         "onion with **ML-KEM post-quantum sealing**; "
                         "Quarantine rebuilds untrusted documents safely "
                         "from pixels."},
                {"kicker": "SEAL COMPANION + KEYS",
                 "body": "User-facing attestation verifier (self-audit + "
                         "peer-verify) — the differentiator made "
                         "tangible — and a FIDO2/passkey authenticator "
                         "with TEE-wrapped credentials."},
            ],
            "note": "Honest status: these are **tested cores in-tree, not "
                    "yet packaged products** — UI and packaging land "
                    "with Postern Suite v0.1, the current flagship effort.",
        },
        sotto_spotlight("PRODUCTS · S·OTTO"),
        sotto_ledger("PRODUCTS · S·OTTO"),
        {
            "kind": "split",
            "title": "Postern Seal — proof, not promises",
            "left": {
                "kicker": "THE LADDER", "kcolor": BRASS, "hi": True,
                "head": "Three levels of provable integrity",
                "bullets": [
                    "**L1 · Reproducible build** — anyone can "
                    "rebuild the product and match the published digest. "
                    "**Verified today.**",
                    "**L2 · Hardening profile** — the hardened "
                    "configuration is part of what is proven. **Verified "
                    "today.**",
                    "**L3 · Hardware attestation** — a TEE quote "
                    "(SEV-SNP / verified root hash) binds “genuine "
                    "Postern build” to silicon. **Designed; not yet "
                    "run on production hardware** — stated plainly.",
                ],
            },
            "right": {
                "kicker": "WHAT IT UNLOCKS", "kcolor": MUTED,
                "head": "Where hardening ends, proof begins",
                "bullets": [
                    "**Self-audit**: a user verifies their own device is "
                    "genuine — via the Seal Companion app.",
                    "**Peer verification**: prove to a colleague or source "
                    "that the device handling their material is unmodified.",
                    "**Fleet verification for organizations** — the "
                    "later service business, after L3 lands on real "
                    "hardware.",
                    "GrapheneOS, Red Hat and Ubuntu **harden**; a Postern "
                    "product additionally **proves** — that is the "
                    "defensible difference.",
                ],
            },
        },
        {
            "kind": "grid", "cols": 2,
            "title": "Roadmap — one real thing at a time",
            "items": [
                {"kicker": "NOW · THE FLAGSHIP", "kcolor": BRASS,
                 "head": "Postern Suite v0.1 + Hygiene CLI",
                 "body": "The desktop privacy toolbox — Scrub, Vault, "
                         "Quarantine, Verify, Panic in one app, with the "
                         "metadata-hygiene wedge and per-pane honesty "
                         "text. **Buildable now**; the CLI ships the same "
                         "week. Node/wallet demoted to an advanced tab "
                         "labelled zero-value testnet."},
                {"kicker": "NEXT · SCRUTINY",
                 "head": "Free review first, paid audit second",
                 "body": "Public ePrint parameter rationale → academic "
                         "review → **narrowly-scoped third-party "
                         "audit** (grant-funded). Attestation demonstrated "
                         "on real TEE hardware; a TUF-based signed update "
                         "channel for releases."},
                {"kicker": "THEN · THE PHONE",
                 "head": "Container MVP + mobile SDKs",
                 "body": "The Android privacy container with "
                         "hardware-backed keys — the low-friction "
                         "entry product — plus mobile SDK builds and "
                         "Sotto’s on-device Whisper engine."},
                {"kicker": "DESTINATION",
                 "head": "The full sovereign stack",
                 "body": "Postern OS as daily driver, enterprise "
                         "deployments for newsrooms, firms and NGOs, and "
                         "Seal verification for fleets. **Every milestone "
                         "audit-gated; horizons stated honestly** — "
                         "6–12+ months for protocol candidacy."},
            ],
        },
        {
            "kind": "close",
            "statement": "You pay for protection —\n"
                         "and you can verify it.",
            "body": "Postern Labs: privacy and security software on "
                    "permissive open source — **private by default, "
                    "reproducible, remotely attestable, honest about "
                    "limits.** From the metadata scrubber to the Sotto "
                    "voice assistant to the attested OS: one thesis, "
                    "shipped one real product at a time. **Postern is "
                    "organizing as a Wyoming, USA LLC.**",
            "contact": "CONTACT: TIAGO TENÓRIO (TT) · FOUNDER & CEO "
                       "· LINKEDIN ON THE FOUNDER SLIDE · POSTERN LABS",
        },
    ],
}

# ----------------------------------------------------------------------
# build + verify
# ----------------------------------------------------------------------

def build_deck(deck):
    total = len(deck["slides"])
    outputs = []
    for backend_cls, ext in ((PptxBackend, "pptx"), (PdfBackend, "pdf")):
        b = backend_cls(deck["title"])
        path = os.path.join(HERE, deck["file"] + "." + ext)
        if isinstance(b, PdfBackend):
            b.set_path(path)
        for i, s in enumerate(deck["slides"], start=1):
            b.new_slide()
            RENDERERS[s["kind"]](b, s, deck, i, total)
        b.save(path)
        outputs.append(path)
        print("wrote %s  (%d slides)" % (path, total))
    return outputs


def verify():
    from pptx import Presentation as P
    ok = True
    for name in ("postern-kfw", "postern-institutional"):
        pp = os.path.join(HERE, name + ".pptx")
        prs = P(pp)
        texts = []
        for sl in prs.slides:
            for sh in sl.shapes:
                if sh.has_text_frame:
                    texts.append(sh.text_frame.text)
        blob = "\n".join(texts)
        assert len(prs.slides._sldIdLst) > 0
        has_sotto = "Sotto" in blob or "S·OTTO" in blob
        print("verify %s.pptx: slides=%d sotto=%s" %
              (name, len(prs.slides._sldIdLst), has_sotto))
        ok &= has_sotto

        pd = os.path.join(HERE, name + ".pdf")
        raw = open(pd, "rb").read()
        assert raw.startswith(b"%PDF"), "bad PDF header"
        assert b"%%EOF" in raw[-64:], "missing EOF"
        try:
            import pypdf
            r = pypdf.PdfReader(pd)
            pages = len(r.pages)
            ptext = "".join(p.extract_text() or "" for p in r.pages)
            print("verify %s.pdf: pages=%d size=%d sotto=%s" %
                  (name, pages, len(raw), "Sotto" in ptext))
        except ImportError:
            print("verify %s.pdf: size=%d header/EOF ok (pypdf absent)" %
                  (name, len(raw)))
    return ok


if __name__ == "__main__":
    build_deck(KFW)
    build_deck(INSTITUTIONAL)
    verify()
