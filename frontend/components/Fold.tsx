"use client";

import { useState } from "react";

/**
 * Secondary numbers, folded.
 *
 * These seven counts were on screen at all times and none of them ever changed
 * what anyone did next. They are still one press away, and the press is what
 * tells you they exist.
 */
export function Fold({ label, count, children }: { label: string; count?: number; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="fold">
      <button type="button" className="fold-toggle" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <span className="row-chevron" aria-hidden="true">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="m9 6 6 6-6 6" />
          </svg>
        </span>
        {label}
        {count !== undefined ? <span className="fold-count">{count}</span> : null}
      </button>
      <div className="fold-wrap" data-open={open ? "" : undefined}>
        <div>{children}</div>
      </div>
    </div>
  );
}
