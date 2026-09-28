import { apiSafe, type SourceHealth } from "@/lib/api";
import { Empty, Ext, PageHead, Panel, Tier } from "@/components/ui";

export const dynamic = "force-dynamic";

/**
 * Where each part of the dashboard gets its data.
 *
 * Grouped by what *you* see in Asber rather than by the internal category
 * names, and built from the same registry the collectors use — so this page
 * cannot drift from what is actually being fetched.
 */
const GROUPS: { title: string; blurb: string; categories: string[] }[] = [
  {
    title: "Vulnerabilities & CVEs",
    blurb:
      "Every CVE page, the threat table and the relevance score. One canonical entry per CVE, merged from all of these.",
    categories: ["vulnerability"],
  },
  {
    title: "Exploits & proof-of-concept code",
    blurb:
      "The Exploit and PoC signals on a CVE, and the Exploits page. Metadata only — Asber never downloads or runs exploit code.",
    categories: ["exploit"],
  },
  {
    title: "Threat actors, malware, campaigns & techniques",
    blurb:
      "The Threat actors, Malware, Campaigns and MITRE ATT&CK pages, plus the detection guidance on every technique.",
    categories: ["attack"],
  },
  {
    title: "Research & analysis",
    blurb:
      "The Research feed, exploitation evidence, and the actor and malware associations shown on a CVE.",
    categories: ["research", "threat_intel"],
  },
  {
    title: "Security news",
    blurb: "The News feed. Treated as context, never as the primary technical fact about a vulnerability.",
    categories: ["news"],
  },
  {
    title: "Detection rules",
    blurb: "Planned for the Detection page: Sigma and YARA rules mapped to ATT&CK techniques.",
    categories: ["detection"],
  },
  {
    title: "Malware samples & indicators",
    blurb: "Planned for the IOCs page: hashes, malicious URLs and indicator feeds. Samples are never downloaded.",
    categories: ["ioc"],
  },
];

export default async function DataSourcesPage() {
  const data = await apiSafe<{ sources: SourceHealth[] }>("/api/sources");
  if (!data) return <div className="notice notice-danger">API unavailable.</div>;

  const collecting = data.sources.filter((s) => s.enabled).length;

  return (
    <>
      <PageHead
        title="Data sources"
        sub="Everything in Asber comes from a public source, and every page links back to the original. Nothing here is generated or inferred without saying so."
      />

      <div className="notice">
        <div>
          <b>
            {collecting} of {data.sources.length} sources are collecting right now.
          </b>{" "}
          The rest are registered and documented but are either waiting on a later phase or need an API key.{" "}
          <Ext href="https://github.com/lucsss1/Asber/blob/main/SOURCES.md">
            <span className="link">Per-source contract →</span>
          </Ext>
        </div>
      </div>

      {GROUPS.map((group) => {
        const sources = data.sources.filter((s) => group.categories.includes(s.category));
        if (!sources.length) return null;
        return (
          <Panel key={group.title} title={group.title}>
            <p className="page-sub" style={{ marginTop: 0 }}>
              {group.blurb}
            </p>
            <div className="health-grid">
              {sources
                .slice()
                .sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.tier - b.tier)
                .map((s) => (
                  <article key={s.key} className="health-card">
                    <div className="health-name">
                      <Ext href={s.homepage} plain>
                        {s.name}
                      </Ext>
                    </div>
                    <div className="health-meta">
                      <Tier tier={s.tier} />
                      <span>{s.source_type}</span>
                    </div>
                    {s.fields.length ? (
                      <div className="health-meta">
                        <span>
                          Provides: {s.fields.slice(0, 6).join(", ")}
                          {s.fields.length > 6 ? `, +${s.fields.length - 6} more` : ""}
                        </span>
                      </div>
                    ) : null}
                    <div className="health-meta">
                      {s.enabled ? (
                        <span>
                          <span className="dot dot-ok" />
                          Collecting via {s.method.toUpperCase()}
                        </span>
                      ) : (
                        <span>
                          <span className="dot" />
                          {s.requires_auth
                            ? "Needs an API key"
                            : s.implemented
                              ? "Available, currently switched off"
                              : "Not collected on a schedule"}
                        </span>
                      )}
                    </div>
                    {/* The registry note is the accurate explanation — some sources are
                        used without being polled (CVE.org is linked from every CVE page). */}
                    {!s.enabled && s.notes ? <div className="health-meta">{s.notes}</div> : null}
                  </article>
                ))}
            </div>
          </Panel>
        );
      })}

      <Panel title="How the data is treated">
        <ul className="list-reset stack-sm small">
          <li>
            <b>Attribution is never dropped.</b> Every CVE, article and exploit keeps the original URL, the source
            that supplied it and the date it was collected.
          </li>
          <li>
            <b>Sources are not equally trusted.</b> Tier 1 is a government body, vendor PSIRT or the original
            researcher; Tier 2 a security research organisation; Tier 3 security news; Tier 4 unverified community
            code. The tier is shown wherever a source appears.
          </li>
          <li>
            <b>Only excerpts are stored.</b> Articles are kept as a title and a short summary, never a full copy. The
            complete text is read once to extract CVEs and actor names, then discarded.
          </li>
          <li>
            <b>Collection is polite.</b> Official APIs and feeds are used where they exist, rate limits and
            robots.txt are respected, and unchanged data is not re-downloaded.
          </li>
          <li>
            <b>Inference is labelled.</b> An ATT&CK mapping derived from impact rather than stated by a source is
            marked <em>inferred</em>, and an actor association always shows the report it came from.
          </li>
        </ul>
      </Panel>

      <p className="faint">
        Source status and sync times live on <span className="link">Source health</span>. This page is about where
        the information comes from; that one is about whether it arrived.
      </p>
    </>
  );
}
