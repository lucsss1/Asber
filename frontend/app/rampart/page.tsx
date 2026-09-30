import Link from "next/link";
import { notFound } from "next/navigation";

import { apiSafe } from "@/lib/api";
import { CATEGORIES, canSeeRampart, type EnvironmentView } from "@/lib/rampart";
import { Empty, PageHead, Panel } from "@/components/ui";
import { AssetForm } from "@/components/AssetForm";
import { deleteAsset } from "./actions";

export const dynamic = "force-dynamic";

const CATEGORY_LABEL = Object.fromEntries(CATEGORIES.map((c) => [c.value, c.label]));

export default async function RampartPage() {
  // The middleware already refuses non-owners; this is the second lock, and it
  // answers 404 rather than 403 for the same reason it does there — whether
  // this deployment keeps an inventory is not something to confirm.
  if (!(await canSeeRampart())) notFound();

  const env = await apiSafe<EnvironmentView>("/api/rampart/environment");
  if (!env) return <div className="notice notice-danger">API unavailable.</div>;

  const { affected, possibly_affected: possibly } = env.counts;

  return (
    <>
      <PageHead
        title="Rampart"
        sub="What you run, and which of the threats Asber already tracks reach it. Nothing here is sent anywhere: the inventory stays in this deployment."
        right={
          env.assets.length ? (
            <span className="row">
              {/* The file describes a live environment. The page says so, and
                  so does the export itself, in its own footer. */}
              <a className="btn" href="/api/rampart/export?format=markdown">Markdown</a>
              <a className="btn" href="/api/rampart/export?format=json">JSON</a>
              <a className="btn" href="/api/rampart/export?format=csv">CSV</a>
              <Link href="/rampart/threats" className="link small">
                Threats in Rampart →
              </Link>
            </span>
          ) : null
        }
      />

      {env.assets.length ? (
        <section className="lead">
          {affected > 0 ? (
            <>
              <p className="lead-line">
                <span className="lead-count">{affected}</span>
                <span>{affected === 1 ? "threat reaches" : "threats reach"} your environment.</span>
              </p>
              <p className="lead-detail">
                <Link href="/rampart/threats?state=affected" className="lead-link">
                  <b>{affected}</b> matched on a version you run
                </Link>
                {possibly > 0 ? (
                  <>
                    <span className="lead-sep">·</span>
                    <Link href="/rampart/threats?state=possibly_affected" className="lead-link">
                      <b>{possibly}</b> to check by hand
                    </Link>
                  </>
                ) : null}
              </p>
            </>
          ) : (
            <p className="lead-line calm">
              <span>
                Nothing currently reaches your environment
                {possibly > 0 ? `, though ${possibly} need checking by hand.` : "."}
              </span>
            </p>
          )}
        </section>
      ) : null}

      <Panel title="Your environment" flush>
        {env.assets.length ? (
          <table className="asset-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th style={{ width: 220 }}>Software</th>
                <th style={{ width: 130 }}>Version</th>
                <th style={{ width: 140 }}>Category</th>
                <th style={{ width: 90 }} />
              </tr>
            </thead>
            <tbody>
              {env.assets.map((a) => (
                <tr key={a.id}>
                  <td>
                    <div className="asset-label">{a.label}</div>
                    {a.hardware_model ? <div className="faint">{a.hardware_model}</div> : null}
                  </td>
                  <td>
                    <div className="mono">{a.product}</div>
                    <div className="faint">{a.vendor}</div>
                  </td>
                  <td>
                    {a.version ? (
                      <span className="mono">{a.version}</span>
                    ) : (
                      <span className="tag" title="Without a version every match stays unconfirmed">
                        not set
                      </span>
                    )}
                  </td>
                  <td className="faint">{CATEGORY_LABEL[a.category] ?? a.category}</td>
                  <td className="num">
                    {!a.catalogued ? (
                      <span className="tag" title="Typed by hand — matching falls back to the name">
                        unmatched
                      </span>
                    ) : null}
                    <form action={deleteAsset} style={{ display: "inline" }}>
                      <input type="hidden" name="id" value={a.id} />
                      <button type="submit" className="btn btn-ghost small">Remove</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title="Nothing registered yet">
            Add the software and firmware you actually run. Asber already tracks the threats; this is
            what tells it which of them are yours.
          </Empty>
        )}
      </Panel>

      <Panel title="Add something you run">
        <p className="page-sub" style={{ marginTop: 0 }}>
          Register the software or firmware, not the hardware: matching compares vendor, product and
          version, so <span className="mono">FortiOS 7.2.8</span> produces a verdict where{" "}
          <span className="mono">FortiGate 100F</span> cannot.
        </p>
        <AssetForm />
        <p className="faint" style={{ marginTop: "var(--space-4)" }}>
          {env.assets.length} of {env.asset_limit} assets.
        </p>
      </Panel>
    </>
  );
}
