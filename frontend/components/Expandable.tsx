"use client";

import { useRef, useState } from "react";

/** Matches the line-height of .desc. */
const LINE = 24;

/**
 * Clamps long external text (NVD/ATT&CK descriptions run to a dozen lines) and
 * reveals the rest on demand. A <details> element cannot do this: everything
 * except the <summary> is hidden while it is closed.
 *
 * The paragraph is always rendered in full and only the wrapper is clipped, so
 * scrollHeight is the real height at any point. That is what lets the open
 * state transition to an actual number instead of a guessed max-height, which
 * would leave dead time at the end of every collapse.
 */
export function Expandable({ text, lines = 6, threshold = 420 }: { text: string; lines?: number; threshold?: number }) {
  const [open, setOpen] = useState(false);
  const body = useRef<HTMLDivElement>(null);
  const long = text.length > threshold;
  const collapsed = lines * LINE;

  // body.current is null on the first render, but `open` can only be true
  // after a click, by which point the element is mounted and measurable.
  const height = !long ? undefined : open ? (body.current?.scrollHeight ?? collapsed) : collapsed;

  return (
    <div>
      <div className="expandable" data-clipped={long && !open ? "" : undefined} style={{ maxHeight: height }}>
        <div ref={body}>
          <p className="desc">{text}</p>
        </div>
      </div>
      {long ? (
        <button
          type="button"
          className="btn btn-ghost expandable-toggle"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
        >
          {open ? "Show less" : "Show full description"}
        </button>
      ) : null}
    </div>
  );
}
