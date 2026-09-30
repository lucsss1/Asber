import Link from "next/link";
import { notFound } from "next/navigation";

import { apiSafe, type Paged, type Vuln } from "@/lib/api";
import { canSeeRampart, STATE_LABELS, type Match } from "@/lib/rampart";
import { one, Segmented, Toggles, WINDOW_OPTIONS, type SP } from "@/components/Filters";
import { Empty, PageHead, Panel, Risk, Signals } from "@/components/ui";
import { relative, vulnLabel } from "@/lib/format";

export const dynamic = "force-dynamic";

type Result = Paged<Vuln> & { matches: Record<string, Match> };

const STATES = [
  { value: "", label: "Affected & possible" },
  { value: "affected", label: "Affected" },
  { value: "possibly_affected", label: "Possible" },
  { value: "not_affected", label: "Ruled out" },
];

export default async function RampartThreatsPage({ searchParams }: { searchParams: Promise<SP> }) {
  if (!(await canSeeRampart())) notFound();

  const sp = await searchParams;
  const state = one(sp, "state") || "";
  const data = await apiSafe<Result>("/api/rampart/threats", {
    state: state || undefined,
    window: one(sp, "window"),
    exploited: one(sp, "exploited"),
    kev: one(sp, "kev"),
    page: one(sp, "page"),
  });
  if (!data) return <div className="notice notice-danger">API unavailable.</div>;

  return (
    <>
      <PageHead
        title="Threats in Rampart"
        sub="The same corpus, narrowed to what you registered. Every row says which state it is in and why — a verdict you cannot interrogate is not worth having."
        right={
          <Link href="/rampart" className="link small">
            Your environment →
          </Link>
        }
      />

      <div className="toolbar">
        <Segmented base="/rampart/threats" sp={sp} param="state" options={STATES} fallback="" />
        <Segmented base="/rampart/threats" sp={sp} param="window" options={WINDOW_OPTIONS} fallback="all" />
        <span className="spacer" />
        <Toggles
          base="/rampart/threats"
          sp={sp}
          options={[
            { param: "exploited", label: "Exploited" },
            { param: "kev", label: "In CISA KEV" },
          ]}
        />
      </div>

      <Panel title={`${data.total.toLocaleString()} matching your environment`} flush>
        {data.items.length ? (
          <table>
            <thead>
              <tr>
                <th style={{ width: 104 }}>Risk</th>
                <th>Vulnerability</th>
                <th style={{ width: 300 }}>Why it is here</th>
                <th style={{ width: 200 }}>Signals</th>
                <th style={{ width: 104 }}>Activity</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((v) => {
                const match = data.matches[v.cve_id];
                return (
                  <tr key={v.cve_id}>
                    <td>
                      <Risk value={v.relevance_score} reasons={v.relevance_reasons} id={v.cve_id} />
                    </td>
                    <td>
                      <Link href={`/cve/${v.cve_id}`} className="cve-cell">
                        <span className="cve-id">{v.cve_id}</span>
                        <span className="cve-name">{vulnLabel(v)}</span>
                      </Link>
                    </td>
                    <td>
                      {match ? (
                        <>
                          <span className={`state state-${match.state}`}>
                            {STATE_LABELS[match.state]}
                          </span>
                          {/* The sentence is the product: it is what turns a
                              coloured word into something you can act on. */}
                          <div className="state-why">{match.evidence}</div>
                        </>
                      ) : (
                        <span className="faint">—</span>
                      )}
                    </td>
                    <td>
                      <Signals v={v} />
                    </td>
                    <td className="nowrap faint">{relative(v.last_activity_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <Empty title="Nothing matches">
            {state === "not_affected"
              ? "Nothing has been ruled out yet — that only happens once a version puts an asset outside a published range."
              : "Either your environment is not touched by anything Asber tracks in this window, or there is nothing registered yet."}
          </Empty>
        )}
      </Panel>
    </>
  );
}
