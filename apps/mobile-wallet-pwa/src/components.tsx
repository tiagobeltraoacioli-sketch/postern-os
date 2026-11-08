import type { ReactNode } from "react";
import { TOP_BANNER } from "./honesty";

/** Persistent honesty banner shown on every screen. */
export function TopBanner() {
  return (
    <div className="protobar" role="note" aria-label="Honest status">
      {TOP_BANNER}
    </div>
  );
}

type NoteKind = "warn" | "soft" | "info";

/** A per-screen honest disclosure note. */
export function HonestNote({ kind = "info", children }: { kind?: NoteKind; children: ReactNode }) {
  return <div className={`note ${kind}`}>{children}</div>;
}

/** A labelled preview pill — used wherever a value is not (yet) a real result. */
export function PreviewTag({ label = "preview" }: { label?: string }) {
  return <span className="tag preview">{label}</span>;
}

export function Card({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <div className="card">
      {title ? <h3>{title}</h3> : null}
      {children}
    </div>
  );
}
