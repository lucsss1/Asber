"use client";

import { useState } from "react";

/**
 * Clamps long external text (NVD/ATT&CK descriptions run to a dozen lines) and
 * reveals the rest on demand. A <details> element cannot do this: everything
 * except the <summary> is hidden while it is closed.
 */
export function Expandable({ text, lines = 6, threshold = 420 }: { text: string; lines?: number; threshold?: number }) {
  const [open, setOpen] = useState(false);
  const long = text.length > threshold;

  return (
    <div>
      <p
        className="desc"
        style={open ? { WebkitLineClamp: "unset", display: "block" } : { WebkitLineClamp: lines }}
      >
        {text}
      </p>
      {long ? (
        <button type="button" className="btn btn-ghost" style={{ padding: "4px 0", color: "var(--accent)" }}
          onClick={() => setOpen((v) => !v)}>
          {open ? "Show less" : "Show full description"}
        </button>
      ) : null}
    </div>
  );
}
