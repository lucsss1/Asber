import { apiSafe, type SourceHealth } from "@/lib/api";
import { duration, fmtDateTime, relative, tierLabel } from "@/lib/format";
import { Empty, Ext, PageHead, Panel } from "@/components/ui";
import { IconAlert } from "@/components/icons";

export const dynamic = "force-dynamic";

const DOT: Record<string, string> = {
  ok: "dot dot-ok",
  stale: "dot dot-warn",
  error: "dot dot-error",
  never_run: "dot dot-warn",
  disabled: "dot dot-off",
};

const LABEL: Record<string, string> = {
  ok: "Up to date",
  stale: "Stale",
  error: "Failing",
  never_run: "Not run yet",
  disabled: "Off",
};

export default async function SourcesPage() {
  const data = await apiSafe<{ sources: SourceHealth[] }>("/api/sources");
  if (!data) return <div className="notice notice-danger">API unavailable.</div>;

  const active = data.sources.filter((s) => s.enabled);
  const problems = active.filter((s) => s.health === "error" || s.health === "stale");
  const off = data.sources.filter((s) => !s.enabled);

  return (
    <>
      <PageHead
        title="Source health"
        sub="Whether this dashboard is actually up to date. Each source is fetched independently, so one failure never stops the others."
      />

      {problems.length ? (
        <div className="notice notice-warn">
          <IconAlert />
          <div>
            <b>
              {problems.length} of {active.length} active sources need attention.
            </b>{" "}
            Data from them may be out of date.
          </div>
        </div>
      ) : (
        <div className="notice">
          <span className="dot dot-ok" />
          <div>
            All <b>{active.length}</b> active sources are up to date.
          </div>
        </div>
      )}

      <Panel title={`Collecting (${active.length})`}>
        <div className="health-grid">
          {active.map((s) => (
            <article key={s.key} className={`health-card is-${s.health}`}>
              <div className="health-name">
                <span className={DOT[s.health] || "dot dot-off"} />
                <Ext href={s.homepage} plain>
                  {s.name}
                </Ext>
              </div>
              <div className="health-meta">
                <span title={tierLabel(s.tier)}>Tier {s.tier}</span>
                <span>{s.method}</span>
                <span>every {duration(s.interval_seconds)}</span>
              </div>
              <div className="health-meta">
                <span title={fmtDateTime(s.last_successful_fetch)}>
                  {LABEL[s.health]} · synced {relative(s.last_successful_fetch)}
                </span>
              </div>
              <div className="health-meta">
                {/* a conditional-GET 304 fetches nothing, which is success, not an empty result */}
                {s.items_fetched ? (
                  <span>{s.items_fetched.toLocaleString()} items</span>
                ) : (
                  <span>no change last sync</span>
                )}
                {s.items_new ? <span>{s.items_new.toLocaleString()} new</span> : null}
                {s.latency_ms ? <span>{s.latency_ms} ms</span> : null}
              </div>
              {s.last_error ? (
                <div className="health-meta" style={{ color: "var(--risk-critical)" }}>
                  <span className="truncate" title={s.last_error}>
                    {s.last_error}
                  </span>
                </div>
              ) : null}
            </article>
          ))}
        </div>
        {!active.length ? <Empty title="No source is enabled" /> : null}
      </Panel>

      <Panel title={`Not collecting (${off.length})`}>
        <div className="health-grid">
          {off.map((s) => (
            <article key={s.key} className="health-card">
              <div className="health-name" style={{ color: "var(--ink-2)" }}>
                <span className="dot dot-off" />
                <Ext href={s.homepage} plain>
                  {s.name}
                </Ext>
              </div>
              <div className="health-meta">
                <span>Tier {s.tier}</span>
                <span>{s.requires_auth ? "needs an API key" : `phase ${s.phase}`}</span>
              </div>
              {s.notes ? (
                <div className="health-meta">
                  <span className="truncate" title={s.notes}>
                    {s.notes}
                  </span>
                </div>
              ) : null}
            </article>
          ))}
        </div>
      </Panel>

      <p className="faint">
        Sources awaiting a later phase are registered and documented but have no worker yet. Those needing a key stay
        off until it is present in <code>.env</code>. Intervals are configurable with{" "}
        <code>SOURCE_INTERVAL_&lt;KEY&gt;</code>.
      </p>
    </>
  );
}
