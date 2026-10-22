"use client";

import Link from "next/link";
import { Fragment, useState } from "react";
import type { Vuln } from "@/lib/api";
import { vulnLabel } from "@/lib/format";
import { Risk, Signals } from "@/components/ui";
import { RowDetail } from "@/components/RowDetail";

/**
 * The table rows, and what each one is hiding.
 *
 * The table used to carry six columns so that nothing was ever more than a
 * glance away, which meant every screen was full and there was nothing left to
 * find. It now shows what you scan by — risk, what it is, what is known about
 * it, when it last moved — and keeps the rest one press away, in place.
 *
 * Opening a row does not navigate. That matters: the comparison you were in
 * the middle of making is still on screen underneath.
 *
 * ``activity`` arrives already formatted rather than being derived here. This
 * is a client component, so a string computed from ``Date.now()`` during
 * render is computed twice — once to produce the HTML, again to hydrate it —
 * and the two disagree as soon as a minute boundary falls between them. That
 * shipped: the Overview threw React #418 and discarded the hydration for this
 * subtree, which leaves the rows briefly unpressable. One clock decides now.
 */
export function ThreatRows({ items, activity }: { items: Vuln[]; activity: string[] }) {
  const [open, setOpen] = useState<string | null>(null);

  return (
    <tbody>
      {items.map((v, i) => {
        const isOpen = open === v.cve_id;
        return (
          <Fragment key={v.cve_id}>
            <tr className={isOpen ? "row-open" : undefined}>
              <td>
                <Risk value={v.relevance_score} reasons={v.relevance_reasons} id={v.cve_id} />
              </td>
              <td>
                <button
                  type="button"
                  className="row-toggle"
                  aria-expanded={isOpen}
                  aria-controls={`detail-${v.cve_id}`}
                  onClick={() => setOpen(isOpen ? null : v.cve_id)}
                >
                  <span className="row-chevron" aria-hidden="true">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="m9 6 6 6-6 6" />
                    </svg>
                  </span>
                  <span className="cve-cell">
                    <span className="cve-id">{v.cve_id}</span>
                    <span className="cve-name">{vulnLabel(v)}</span>
                  </span>
                </button>
              </td>
              <td>
                <Signals v={v} />
              </td>
              <td className="nowrap faint">{activity[i]}</td>
            </tr>
            <tr className="row-detail" aria-hidden={!isOpen}>
              <td colSpan={4}>
                <div className="row-detail-wrap" id={`detail-${v.cve_id}`} data-open={isOpen ? "" : undefined}>
                  <div>{isOpen ? <RowDetail cveId={v.cve_id} /> : null}</div>
                </div>
              </td>
            </tr>
          </Fragment>
        );
      })}
    </tbody>
  );
}
