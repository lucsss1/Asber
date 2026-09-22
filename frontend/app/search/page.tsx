import Link from "next/link";
import { apiSafe, type AttackItem, type Doc, type ExploitItem, type Vuln } from "@/lib/api";
import { one, type SP } from "@/components/Filters";
import { DocList, Empty, ExploitTable, PageHead, Panel, ThreatTable } from "@/components/ui";

export const dynamic = "force-dynamic";

interface SearchResult {
  query: string;
  exact_cve: string | null;
  vulnerabilities: Vuln[];
  documents: Doc[];
  exploits: ExploitItem[];
  attack: AttackItem[];
}

export default async function SearchPage({ searchParams }: { searchParams: Promise<SP> }) {
  const sp = await searchParams;
  const q = (one(sp, "q") || "").trim();
  if (q.length < 2) {
    return (
      <>
        <PageHead title="Search" sub="Search across CVEs, reports, exploits and ATT&CK entities." />
        <Empty>Type at least two characters.</Empty>
      </>
    );
  }
  const data = await apiSafe<SearchResult>("/api/search", { q, limit: 15 });
  if (!data) return <div className="notice notice-warn">API unavailable.</div>;

  const total =
    data.vulnerabilities.length + data.documents.length + data.exploits.length + data.attack.length;

  return (
    <>
      <PageHead title={`Search: ${q}`} sub={`${total} result${total === 1 ? "" : "s"} across all entity types`} />

      {data.exact_cve ? (
        <div className="notice">
          Exact CVE match — <Link href={`/cve/${data.exact_cve}`}>open {data.exact_cve} →</Link>
        </div>
      ) : null}

      {data.vulnerabilities.length ? (
        <Panel title="Vulnerabilities" action={<Link href={`/threats?q=${encodeURIComponent(q)}`} className="small">All →</Link>} flush>
          <ThreatTable items={data.vulnerabilities} />
        </Panel>
      ) : null}

      {data.attack.length ? (
        <Panel title="MITRE ATT&CK">
          <div className="tags">
            {data.attack.map((a) => (
              <Link key={a.stix_id} href={`/attack/${a.external_id || a.stix_id}`} className="tag">
                {a.external_id ? `${a.external_id} · ` : ""}
                {a.name} <span className="faint">({a.type})</span>
              </Link>
            ))}
          </div>
        </Panel>
      ) : null}

      {data.exploits.length ? (
        <Panel title="Exploits & PoCs" flush>
          <ExploitTable items={data.exploits} />
        </Panel>
      ) : null}

      {data.documents.length ? (
        <Panel title="Research & news">
          <DocList docs={data.documents} />
        </Panel>
      ) : null}

      {total === 0 ? <Empty>Nothing found. Try a vendor, product, CVE id or actor name.</Empty> : null}
    </>
  );
}
