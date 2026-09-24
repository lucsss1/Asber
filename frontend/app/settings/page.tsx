import { apiSafe } from "@/lib/api";
import { duration } from "@/lib/format";
import { PageHead, Panel } from "@/components/ui";

export const dynamic = "force-dynamic";

interface SettingsData {
  credentials_configured: Record<string, boolean>;
  intervals: Record<string, number>;
  scoring_weights: Record<string, number>;
  features: Record<string, string | number | boolean>;
  safety: string[];
}

export default async function SettingsPage() {
  const data = await apiSafe<SettingsData>("/api/settings");
  if (!data) return <div className="notice notice-danger">API unavailable.</div>;

  return (
    <>
      <PageHead
        title="Settings"
        sub="Configuration comes from environment variables. Secret values never reach the browser — only whether each one is set."
      />

      <div className="grid-2">
        <Panel title="Optional credentials">
          <ul className="list-reset stack-sm">
            {Object.entries(data.credentials_configured).map(([k, v]) => (
              <li key={k} className="row" style={{ justifyContent: "space-between" }}>
                <code>{k}</code>
                <span className="faint">
                  <span className={v ? "dot dot-ok" : "dot dot-off"} />
                  {v ? "configured" : "not set"}
                </span>
              </li>
            ))}
          </ul>
          <p className="faint" style={{ marginTop: 14 }}>
            Every public source works without a key. A key only raises rate limits or unlocks a Phase 2 source.
          </p>
        </Panel>

        <Panel title="Safety guarantees">
          <ul className="list-reset stack-sm">
            {data.safety.map((s) => (
              <li key={s} className="small">
                <span className="dot dot-ok" />
                {s}
              </li>
            ))}
          </ul>
          <p className="faint" style={{ marginTop: 14 }}>
            Malware download: <b>{String(data.features.malware_download_enabled)}</b> · AI layer:{" "}
            <b>{String(data.features.ai_provider)}</b>
          </p>
        </Panel>
      </div>

      <Panel title="Threat Relevance weights">
        <p className="faint" style={{ marginBottom: 14 }}>
          The score is a plain sum of these factors, capped at 100. Every CVE page shows exactly which ones applied.
        </p>
        <div className="tags">
          {Object.entries(data.scoring_weights).map(([k, v]) => (
            <span key={k} className="tag">
              {k.replace(/_/g, " ")} <b style={{ color: "var(--ink)" }}>{v}</b>
            </span>
          ))}
        </div>
      </Panel>

      <Panel title="Polling intervals" flush>
        <table>
          <thead>
            <tr>
              <th style={{ width: 220 }}>Source</th>
              <th style={{ width: 120 }}>Every</th>
              <th>Environment override</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(data.intervals).map(([k, v]) => (
              <tr key={k}>
                <td className="mono">{k}</td>
                <td>{duration(v)}</td>
                <td className="faint mono">SOURCE_INTERVAL_{k.toUpperCase()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </>
  );
}
