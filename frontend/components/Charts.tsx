import { num } from "@/lib/format";

/**
 * The Overview's charts. Inline SVG, no library.
 *
 * Three rules hold these together, and none of them is taste.
 *
 * **The form follows what the data looks like, measured first.** Three chart
 * candidates were dropped because the numbers said they would show nothing —
 * exploit availability across the environment is 2,532 / 17 / 10, so a pie
 * would be ninety-nine per cent one slice. Those are figures now, where a
 * small number reads as small instead of as a sliver.
 *
 * **Severity wears the severity colours.** Not a second palette for the same
 * concept: the bars are the same `--risk-*` steps as the chips on every other
 * page, so a critical is the same colour wherever you meet it. The categorical
 * hues used by the verdict chart are a different, validated set — every check
 * in both themes — because identity and severity are different jobs.
 *
 * **No colour carries meaning alone.** Every segment and every bar is directly
 * labelled, so the chart survives colour blindness, a greyscale print and a
 * forced-colors mode without needing a legend to be decoded.
 */

/* The validated categorical set, for identity rather than magnitude. Measured
   with the palette validator in both themes: lightness band, chroma floor, CVD
   separation (worst adjacent ΔE 21.0 deutan), normal-vision floor (26.9) and
   contrast against both surfaces all pass. Do not nudge these by eye. */
const VERDICT_FILL: Record<string, string> = {
  affected: "#e73b5d",
  possibly_affected: "#886bef",
  not_affected: "#079e72",
};

const SEVERITY_FILL: Record<string, string> = {
  CRITICAL: "var(--fill-critical)",
  HIGH: "var(--fill-high)",
  MEDIUM: "var(--fill-medium)",
  LOW: "var(--fill-low)",
  UNSCORED: "var(--rule-strong)",
};

const SEVERITY_LABEL: Record<string, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  UNSCORED: "Unscored",
};

type Slice = { state: string; label: string; count: number };

/** Part-to-whole over three states — the one shape here a pie is honest for. */
export function VerdictDonut({ data }: { data: Slice[] }) {
  const shown = data.filter((d) => d.count > 0);
  const total = shown.reduce((n, d) => n + d.count, 0);
  if (!total) return null;

  // A donut rather than a pie: the hole carries the total, which is the number
  // the reader wants first and would otherwise need a caption to find.
  const r = 56;
  const stroke = 26;
  const circumference = 2 * Math.PI * r;
  let offset = 0;

  return (
    <figure className="chart">
      <figcaption className="chart-title">What reaches your environment</figcaption>
      <div className="chart-donut">
        <svg viewBox="0 0 160 160" role="img" aria-label={`${num(total)} CVEs by verdict`}>
          <g transform="rotate(-90 80 80)">
            {shown.map((d) => {
              const length = (d.count / total) * circumference;
              // A 2px surface gap between segments, so adjacent fills never
              // touch and the boundary is structural rather than chromatic.
              const dash = `${Math.max(length - 2, 0)} ${circumference - Math.max(length - 2, 0)}`;
              const el = (
                <circle
                  key={d.state}
                  cx="80"
                  cy="80"
                  r={r}
                  fill="none"
                  stroke={VERDICT_FILL[d.state]}
                  strokeWidth={stroke}
                  strokeDasharray={dash}
                  strokeDashoffset={-offset}
                >
                  <title>{`${d.label}: ${num(d.count)} (${Math.round((d.count / total) * 100)}%)`}</title>
                </circle>
              );
              offset += length;
              return el;
            })}
          </g>
          <text x="80" y="76" className="chart-centre-value">
            {num(total)}
          </text>
          {/* "matched", not "CVEs": this total includes the ruled-out slice, so it
              is a larger denominator than the "reaching you" the figures use.
              Two numbers that differ need to say why they differ. */}
          <text x="80" y="94" className="chart-centre-label">
            matched
          </text>
        </svg>
        <ul className="chart-key">
          {shown.map((d) => (
            <li key={d.state}>
              <span className="chart-swatch" style={{ background: VERDICT_FILL[d.state] }} aria-hidden="true" />
              <span className="chart-key-label">{d.label}</span>
              <b className="chart-key-value">{num(d.count)}</b>
              <span className="faint">{Math.round((d.count / total) * 100)}%</span>
            </li>
          ))}
        </ul>
      </div>
    </figure>
  );
}

type Bar = { key: string; label: string; value: number; fill: string; hot?: boolean };

function Columns({ title, sub, bars, empty }: {
  title: string;
  sub?: string;
  bars: Bar[];
  empty: string;
}) {
  const max = Math.max(...bars.map((b) => b.value), 1);
  const any = bars.some((b) => b.value > 0);

  return (
    <figure className="chart">
      <figcaption className="chart-title">
        {title}
        {sub ? <span className="chart-sub">{sub}</span> : null}
      </figcaption>
      {any ? (
        <div className="chart-columns">
          {bars.map((b) => (
            <div className="chart-col" key={b.key}>
              {/* The value sits above the bar rather than inside it: inside, a
                  short bar has nowhere to put it and the label falls outside
                  anyway, so half of them would be aligned differently. */}
              <b className={`chart-col-value${b.hot ? " chart-col-hot" : ""}`}>{num(b.value)}</b>
              <div className="chart-col-track">
                <div
                  className="chart-col-fill"
                  style={{ height: `${(b.value / max) * 100}%`, background: b.fill }}
                  title={`${b.label}: ${num(b.value)}`}
                />
              </div>
              <span className="chart-col-label">{b.label}</span>
            </div>
          ))}
        </div>
      ) : (
        <p className="faint small">{empty}</p>
      )}
    </figure>
  );
}

/** An ordered scale, so: the project's own reserved severity steps. */
export function SeverityColumns({ data, scope }: {
  data: { severity: string; count: number }[];
  scope: string;
}) {
  return (
    <Columns
      title="How bad it is"
      sub={scope}
      bars={data.map((d) => ({
        key: d.severity,
        label: SEVERITY_LABEL[d.severity] ?? d.severity,
        value: d.count,
        fill: SEVERITY_FILL[d.severity] ?? "var(--ink-3)",
        hot: d.severity === "CRITICAL",
      }))}
      empty="Nothing scored yet."
    />
  );
}

/** Magnitude per asset, so one hue — the interface accent, not the risk scale.
 *  These bars say "how much", and how much is not the same as how bad. */
export function AssetColumns({ data }: {
  data: { id: number; label: string; affected: number; possibly_affected: number }[];
}) {
  return (
    <Columns
      title="Which of your things carries the most"
      sub="confirmed matches"
      bars={data.map((a) => ({
        key: String(a.id),
        label: a.label,
        value: a.affected,
        fill: "var(--signal)",
      }))}
      empty="Register something in Rampart and this fills in."
    />
  );
}

/** A figure, for a number a chart would have told a lie about.
 *
 *  "4 of 2,559" is a sentence. As a meter it is a sliver the eye reads as
 *  zero, and as a slice of a pie it is a hairline — both of which overstate
 *  how much the reader can see and understate how little coverage there is.
 */
export function Figure({ value, of, label, hot }: {
  value: number;
  of?: number;
  label: string;
  hot?: boolean;
}) {
  return (
    <div className={`figure${hot ? " hot" : ""}`}>
      <div className="figure-value">{num(value)}</div>
      <div className="figure-label">{label}</div>
      {of !== undefined ? <div className="figure-of">of {num(of)} reaching you</div> : null}
    </div>
  );
}
