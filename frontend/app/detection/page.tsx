import Link from "next/link";
import { num } from "@/lib/format";

import { apiSafe, type Paged } from "@/lib/api";
import { ClearFilters, PillSelect, Segmented, TextFilters, one, type SP } from "@/components/Filters";
import { Empty, PageHead, Pagination, Panel } from "@/components/ui";

export const dynamic = "force-dynamic";

type Rule = {
  id: number;
  external_id: string;
  title: string;
  description: string | null;
  url: string | null;
  format: string;
  status: string | null;
  level: string | null;
  logsource: Record<string, string | null>;
  techniques: string[];
  cve_ids: string[];
  falsepositives: string[];
  author: string | null;
  release: string | null;
};

type Overview = {
  rules: number;
  by_level: Record<string, number>;
  techniques_covered: number;
  cves_covered: number;
  kev_covered: number;
  kev_total: number;
  releases: string[];
};

const LEVELS = [
  { value: "", label: "Any severity" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
];

const STATUSES = [
  { value: "stable", label: "Stable" },
  { value: "test", label: "Test" },
  { value: "experimental", label: "Experimental" },
];

/** Where a rule has to be looking to fire at all. */
function sourceLine(logsource: Record<string, string | null>): string {
  const parts = [logsource.product, logsource.service, logsource.category].filter(Boolean);
  return parts.length ? parts.join(" · ") : "unspecified";
}

export default async function DetectionPage({ searchParams }: { searchParams: Promise<SP> }) {
  const sp = await searchParams;
  const page = Number(one(sp, "page") || 1);
  const hasCve = one(sp, "has_cve");

  const [overview, data] = await Promise.all([
    apiSafe<Overview>("/api/detection/overview"),
    apiSafe<Paged<Rule>>("/api/detection/rules", {
      level: one(sp, "level"),
      status: one(sp, "status"),
      technique: one(sp, "technique"),
      cve: one(sp, "cve"),
      has_cve: hasCve,
      q: one(sp, "q"),
      sort: one(sp, "sort") || "level",
      page,
      page_size: 30,
    }),
  ]);

  if (!data || !overview) return <div className="notice notice-danger">API unavailable.</div>;

  return (
    <>
      <PageHead
        title="Detection"
        sub="Published Sigma rules, parsed as data and never executed. Every rule says what it needs to be fed and what it was written to catch, because 'covered' means nothing if you cannot read the rule."
        right={
          <Link href="/attack" className="link small">
            ATT&CK coverage →
          </Link>
        }
      />

      {/* The honest headline. Coverage of the corpus is thin, and saying so is
          the point: the number that matters is how much of KEV is covered, not
          how many rules exist. */}
      <p className="lead-line">
        <b>{overview.cves_covered}</b> of your{" "}
        <b>{num(overview.kev_total)}</b> exploited CVEs have a public detection rule.
      </p>
      <p className="lead-sub">
        From {num(overview.rules)} rules covering {overview.techniques_covered} ATT&CK
        techniques. The CVE coverage is thin because detection gets written for what is actually
        being exploited — which is why every CVE named here is already in CISA KEV.{" "}
        <Link href="/detection?has_cve=true" className="link">
          Show only those rules →
        </Link>
      </p>

      <div className="toolbar">
        <Segmented base="/detection" sp={sp} param="level" options={LEVELS} fallback="" />
        <PillSelect base="/detection" sp={sp} param="status" options={STATUSES} label="Status" />
        <Segmented
          base="/detection"
          sp={sp}
          param="has_cve"
          options={[
            { value: "", label: "All rules" },
            { value: "true", label: "Names a CVE you track" },
          ]}
          fallback=""
        />
        <span className="spacer" />
        <ClearFilters base="/detection" sp={sp} />
      </div>

      <TextFilters
        base="/detection"
        sp={sp}
        fields={[
          { name: "q", placeholder: "Title or description" },
          { name: "technique", placeholder: "Technique, e.g. T1190" },
          { name: "cve", placeholder: "CVE" },
        ]}
      />

      <Panel title={`${num(data.total)} rules`} flush>
        {data.items.length ? (
          <table>
            <thead>
              <tr>
                <th style={{ width: 86 }}>Severity</th>
                <th>Rule</th>
                <th style={{ width: 200 }}>Needs</th>
                <th style={{ width: 210 }}>Catches</th>
                <th style={{ width: 90 }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    <span className={`sev sev-${rule.level ?? "low"}`}>{rule.level ?? "—"}</span>
                  </td>
                  <td>
                    <div className="doc-title">
                      {rule.url ? (
                        <a href={rule.url} target="_blank" rel="noreferrer noopener" className="link">
                          {rule.title}
                        </a>
                      ) : (
                        rule.title
                      )}
                    </div>
                    {rule.description ? (
                      <div className="faint desc-cell">{rule.description}</div>
                    ) : null}
                  </td>
                  <td className="faint">{sourceLine(rule.logsource)}</td>
                  <td>
                    {rule.techniques.length ? (
                      <div className="tags">
                        {rule.techniques.map((t) => (
                          <Link key={t} href={`/detection?technique=${t}`} className="tag tag-mono tag-accent">
                            {t}
                          </Link>
                        ))}
                      </div>
                    ) : null}
                    {rule.cve_ids.length ? (
                      <div className="tags">
                        {rule.cve_ids.map((c) => (
                          <Link key={c} href={`/cve/${c}`} className="tag tag-mono tag-strong">
                            {c}
                          </Link>
                        ))}
                      </div>
                    ) : null}
                    {!rule.techniques.length && !rule.cve_ids.length ? (
                      <span className="faint">untagged</span>
                    ) : null}
                  </td>
                  <td className="faint nowrap">{rule.status ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title="No rules match">
            Narrow the filters, or clear them to see the whole corpus.
          </Empty>
        )}
      </Panel>

      <Pagination base="/detection" params={sp} page={page} total={data.total} pageSize={30} />
    </>
  );
}
