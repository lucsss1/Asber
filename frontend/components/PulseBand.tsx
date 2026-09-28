"use client";

import Link from "next/link";
import { useState } from "react";

export type Day = { date: string; total: number; exploited: number; kev: number };

/**
 * The band, and its readout.
 *
 * An earlier version gave every bar its own floating label. Thirty absolutely
 * positioned 260px labels widened the document enough to put a horizontal
 * scrollbar on the whole page, and hiding them behind a hover query only fixed
 * real touch devices — a narrow desktop window still reports hover.
 *
 * One readout in a fixed place is both the smaller bug surface and the better
 * instrument: your eye already knows where the number will appear.
 */
export function PulseBand({ series, peak, busiest }: { series: Day[]; peak: number; busiest: Day }) {
  const [at, setAt] = useState<number | null>(null);
  const shown = at === null ? null : series[at];

  return (
    <section className="pulse" aria-label="Threat activity, last 30 days">
      <div className="pulse-bars" onMouseLeave={() => setAt(null)}>
        {series.map((d, i) => {
          const h = Math.max(2, Math.round((d.total / peak) * 100));
          return (
            <span
              key={d.date}
              className={`pulse-bar${d.total === 0 ? " empty" : ""}${i === at ? " on" : ""}`}
              style={{ "--h": `${h}%` } as React.CSSProperties}
              onMouseEnter={() => setAt(i)}
            >
              <i />
            </span>
          );
        })}
      </div>

      <div className="pulse-legend">
        {shown ? (
          <>
            <span className="pulse-caption">{shown.date.slice(5)}</span>
            <span className="pulse-peak">
              <b>{shown.total.toLocaleString()}</b> updated
              {shown.exploited ? <> · <b>{shown.exploited}</b> exploited</> : null}
            </span>
          </>
        ) : (
          <>
            <span className="pulse-caption">30 days</span>
            <span className="pulse-peak">
              peak <b>{busiest.total.toLocaleString()}</b> on {busiest.date.slice(5)}
            </span>
          </>
        )}
        <Link href="/threats" className="pulse-link">
          Active threats →
        </Link>
      </div>
    </section>
  );
}
