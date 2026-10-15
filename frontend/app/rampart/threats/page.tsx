import Link from "next/link";
import { notFound } from "next/navigation";

import { apiSafe, type Paged, type Vuln } from "@/lib/api";
import { canSeeRampart, STATE_LABELS, type Match } from "@/lib/rampart";
import { href, one, Segmented, Toggles, WINDOW_OPTIONS, type SP } from "@/components/Filters";
import { Empty, PageHead, Panel, Risk, Signals } from "@/components/ui";
import { relative, vulnLabel } from "@/lib/format";

export const dynamic = "force-dynamic";

type AssetCount = {
  id: number;
  label: string;
  vendor: string;
  product: string;
  category: string;
  affected: number;
  possibly_affected: number;
  not_affected: number;
  /** Under the state filter currently on screen — what clicking this tab shows. */
  total: number;
};

type Result = Paged<Vuln> & {
  matches: Record<string, Match>;
  assets: AssetCount[];
  asset_id: number | null;
  /** Distinct across every asset, so it is not the sum of the tabs. */
  environment_total: number;
};

/** What a tab's number is counting, so it reads as the same unit as the panel. */
const STATE_NOUN: Record<string, string> = {
  "": "reaching you",
  affected: "affected",
  possibly_affected: "to check",
  not_affected: "ruled out",
};

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
  const assetId = one(sp, "asset_id");
  const data = await apiSafe<Result>("/api/rampart/threats", {
    state: state || undefined,
    asset_id: assetId,
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

      {/* Ordering already puts the ten CISA KEV entries in the top ten rows, so
          priority is not the problem here; reachability is. A firewall with
          three matches cannot be found behind thirteen hundred browser and
          server ones without a way to ask for it directly. */}
      {data.assets.length > 1 ? (
        <nav className="asset-tabs" aria-label="Filter by asset">
          <Link
            href={href("/rampart/threats", sp, { asset_id: undefined })}
            className={`asset-tab${assetId ? "" : " on"}`}
          >
            <span className="asset-tab-name">Everything</span>
            {/* The environment-wide number comes from the API, not from adding
                the tabs up: a CVE can be affected on one asset and merely
                possible on another, and the sum would count it twice. */}
            <span className="asset-tab-counts">
              <b>{data.environment_total.toLocaleString()}</b> {STATE_NOUN[state] ?? "shown"}
            </span>
          </Link>
          {data.assets.map((a) => (
            <Link
              key={a.id}
              href={href("/rampart/threats", sp, { asset_id: String(a.id) })}
              className={`asset-tab${assetId === String(a.id) ? " on" : ""}`}
            >
              <span className="asset-tab-name">{a.label}</span>
              <span className="asset-tab-counts">
                <b className={a.affected && state !== "not_affected" ? "asset-tab-hot" : undefined}>
                  {a.total.toLocaleString()}
                </b>{" "}
                {STATE_NOUN[state] ?? "shown"}
                {/* Only when it splits the number: "14 reaching you · 14 to
                    check" says nothing twice. */}
                {!state && a.affected && a.possibly_affected ? (
                  <span className="faint"> · {a.possibly_affected.toLocaleString()} to check</span>
                ) : null}
              </span>
            </Link>
          ))}
        </nav>
      ) : null}

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

      <Panel
        title={
          data.asset_id
            ? `${data.total.toLocaleString()} on ${
                data.assets.find((a) => a.id === data.asset_id)?.label ?? "this asset"
              }`
            : `${data.total.toLocaleString()} matching your environment`
        }
        flush
      >
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
