import Link from "next/link";
import { PageHead, Panel } from "@/components/ui";

/** Honest placeholder for a feature that is registered but not implemented yet. */
export function Planned({
  title,
  phase,
  sub,
  willInclude,
  available,
}: {
  title: string;
  phase: number;
  sub: string;
  willInclude: string[];
  available?: { href: string; label: string }[];
}) {
  return (
    <>
      <PageHead title={title} sub={sub} right={<span className="tag">Phase {phase}</span>} />
      <Panel title={`Planned for phase ${phase}`}>
        <ul className="stack small" style={{ paddingLeft: 18 }}>
          {willInclude.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
        <p className="faint">
          Nothing is faked here: this page stays empty until the corresponding workers are implemented, so the
          dashboard never shows data it does not have.
        </p>
      </Panel>
      {available?.length ? (
        <Panel title="Available today">
          <div className="tags">
            {available.map((a) => (
              <Link key={a.href} href={a.href} className="tag">
                {a.label}
              </Link>
            ))}
          </div>
        </Panel>
      ) : null}
    </>
  );
}
