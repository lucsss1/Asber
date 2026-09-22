import Link from "next/link";
import { notFound } from "next/navigation";
import { ApiError, api, type AttackItem, type Doc, type Vuln } from "@/lib/api";
import { DocList, Empty, Ext, PageHead, Panel, ThreatTable } from "@/components/ui";
import { Expandable } from "@/components/Expandable";

export const dynamic = "force-dynamic";

interface AttackDetail extends AttackItem {
  extra: Record<string, unknown>;
  relationships: Record<string, (AttackItem & { how: string })[]>;
  documents: Doc[];
  vulnerabilities: Vuln[];
  correlation_note: string;
  technique?: {
    detection_strategies: {
      external_id: string;
      name: string;
      url: string | null;
      analytics: {
        external_id: string;
        platforms: string[];
        description: string | null;
        log_sources: { data_component: string | null; name: string | null; channel: string | null }[];
      }[];
    }[];
    mitigations: { external_id: string; name: string; url: string | null; how: string }[];
    legacy_detection: string | null;
    tactics: { name: string; external_id: string }[];
  };
}

const REL_LABELS: Record<string, string> = {
  "uses:technique": "Techniques used",
  "uses:malware": "Software used",
  "uses:tool": "Tools used",
  "used_by:group": "Used by groups",
  "used_by:campaign": "Used in campaigns",
  "used_by:malware": "Used by malware",
  "mitigates:technique": "Mitigates",
  "detects:technique": "Detects",
  "attributed-to:intrusion-set": "Attributed to",
  "subtechnique-of:technique": "Parent technique",
};

export default async function AttackObjectPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let data: AttackDetail;
  try {
    data = await api<AttackDetail>(`/api/attack/objects/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound();
    throw err;
  }

  return (
    <>
      <PageHead
        title={`${data.external_id ? data.external_id + " · " : ""}${data.name}`}
        sub={`${data.type}${data.aliases.length ? " · also known as " + data.aliases.join(", ") : ""}`}
        right={data.url ? <Ext href={data.url}>MITRE ATT&CK ↗</Ext> : undefined}
      />

      <Panel title="Description">
        <Expandable text={data.description || "No description."} lines={8} threshold={600} />
        {data.platforms.length ? <p className="faint">Platforms: {data.platforms.join(", ")}</p> : null}
      </Panel>

      {data.technique?.detection_strategies?.length ? (
        <Panel title="Detection strategies (ATT&CK)">
          <div className="stack">
            {data.technique.detection_strategies.map((s) => (
              <div key={s.external_id}>
                <Ext href={s.url || "https://attack.mitre.org/"}>
                  <b>
                    {s.external_id} · {s.name}
                  </b>
                </Ext>
                {s.analytics.map((a) => (
                  <div key={a.external_id} className="small" style={{ paddingLeft: 12, marginTop: 4 }}>
                    <div className="faint">
                      {a.external_id} · {a.platforms.join(", ")}
                    </div>
                    <div className="muted">{a.description}</div>
                    <div className="faint">
                      Log sources:{" "}
                      {a.log_sources
                        .map((ls) => [ls.data_component, ls.name, ls.channel].filter(Boolean).join(" / "))
                        .join(" · ") || "—"}
                    </div>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </Panel>
      ) : null}

      {data.technique?.mitigations?.length ? (
        <Panel title="Mitigations">
          <ul className="list-reset stack small">
            {data.technique.mitigations.map((m) => (
              <li key={m.external_id}>
                <Ext href={m.url || "https://attack.mitre.org/"}>
                  {m.external_id} · {m.name}
                </Ext>
                <div className="faint">{m.how}</div>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      <Panel title="ATT&CK relationships">
        {Object.keys(data.relationships).length === 0 ? (
          <Empty>No relationships.</Empty>
        ) : (
          <div className="grid-3">
            {Object.entries(data.relationships).map(([rel, items]) => (
              <div key={rel}>
                <h3>{REL_LABELS[rel] || rel.replace(/[:_]/g, " ")}</h3>
                <div className="tags" style={{ marginTop: 6 }}>
                  {items.slice(0, 40).map((i) => (
                    <Link key={i.stix_id} href={`/attack/${i.external_id || i.stix_id}`} className="tag" title={i.how}>
                      {i.external_id ? `${i.external_id} ` : ""}
                      {i.name}
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title={`Correlated vulnerabilities (${data.vulnerabilities.length})`} flush>
        {data.vulnerabilities.length ? (
          <ThreatTable items={data.vulnerabilities} />
        ) : (
          <Empty>No CVE has been co-mentioned with this entity yet.</Empty>
        )}
      </Panel>
      <p className="faint" style={{ marginTop: -8 }}>
        {data.correlation_note}
      </p>

      <Panel title={`Reports mentioning this entity (${data.documents.length})`}>
        <DocList docs={data.documents} />
      </Panel>
    </>
  );
}
