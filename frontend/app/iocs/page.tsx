import Link from "next/link";

import { apiSafe, type Paged } from "@/lib/api";
import { one, type SP } from "@/components/Filters";
import { Empty, PageHead, Pagination, Panel } from "@/components/ui";
import { num, relative } from "@/lib/format";

export const dynamic = "force-dynamic";

type Indicator = {
  id: number;
  kind: string;
  value: string;
  host: string | null;
  family: string | null;
  attack_stix_id: string | null;
  threat: string | null;
  status: string | null;
  file_type: string | null;
  related: Record<string, string>;
  tags: string[];
  reporter: string | null;
  reference_url: string | null;
  source_key: string;
  first_seen_at: string | null;
};

type Attack = { stix_id: string; external_id: string | null; name: string };

type Lookup = {
  query: string;
  kind: string;
  found: boolean;
  total: number;
  items: Indicator[];
  attack: Record<string, Attack>;
  scope: string;
};

type Overview = {
  total: number;
  by_kind: Record<string, number>;
  by_source: Record<string, number>;
  attack_resolved: number;
  attack_families: number;
  online: number;
  newest: string | null;
};

const SOURCE_LABEL: Record<string, string> = {
  malwarebazaar: "MalwareBazaar",
  urlhaus: "URLhaus",
};

export default async function IocsPage({ searchParams }: { searchParams: Promise<SP> }) {
  const sp = await searchParams;
  const q = (one(sp, "q") || "").trim();
  const page = Number(one(sp, "page") || 1);

  const [overview, result, recent] = await Promise.all([
    apiSafe<Overview>("/api/iocs/overview"),
    q ? apiSafe<Lookup>("/api/iocs/lookup", { q }) : Promise.resolve(null),
    q ? Promise.resolve(null) : apiSafe<Paged<Indicator>>("/api/iocs/indicators", {
      has_family: "true",
      page,
      page_size: 30,
    }),
  ]);

  if (!overview) return <div className="notice notice-danger">API unavailable.</div>;

  return (
    <>
      <PageHead
        title="Indicators"
        sub="Paste a hash, URL, domain or address from an alert. This answers whether it is known, and what is known about it — offline, from two public feeds."
        right={
          <Link href="/malware" className="link small">
            ATT&CK malware →
          </Link>
        }
      />

      {/* The lookup is the page. A list of thirty thousand URLs answers no
          operational question for a reader with nothing to block them in. */}
      <form className="lookup" action="/iocs" method="get">
        <input
          type="search"
          name="q"
          defaultValue={q}
          autoFocus
          placeholder="sha256, md5, sha1, URL, domain or IPv4"
          aria-label="Indicator to look up"
          spellCheck={false}
        />
        <button type="submit" className="btn btn-primary">
          Look up
        </button>
      </form>

      {result ? <LookupResult result={result} /> : null}

      {!q ? (
        <>
          <p className="lead-sub">
            <b>{num(overview.total)}</b> indicators from{" "}
            {Object.entries(overview.by_source)
              .map(([k, n]) => `${SOURCE_LABEL[k] ?? k} (${num(n)})`)
              .join(" and ")}
            . {num(overview.attack_resolved)} name a malware family ATT&CK also
            carries, across {overview.attack_families}. Most do not: a feed names what it sees,
            and the Enterprise matrix does not cover everything seen — Mirai, the largest family
            here, is absent from it entirely.
          </p>

          <Panel title="Recently seen, where the family is known" flush>
            {recent?.items.length ? (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 150 }}>Family</th>
                    <th>Indicator</th>
                    <th style={{ width: 110 }}>Kind</th>
                    <th style={{ width: 90 }}>Status</th>
                    <th style={{ width: 96 }}>First seen</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.items.map((row) => (
                    <tr key={row.id}>
                      <td>{row.family ?? <span className="faint">—</span>}</td>
                      <td>
                        <Link href={`/iocs?q=${encodeURIComponent(row.value)}`} className="mono ioc-value">
                          {row.value}
                        </Link>
                      </td>
                      <td className="faint mono">{row.kind}</td>
                      <td>
                        {row.status === "online" ? (
                          <span className="sev sev-high">online</span>
                        ) : (
                          <span className="faint">{row.status ?? "—"}</span>
                        )}
                      </td>
                      <td className="faint nowrap">{relative(row.first_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty title="Nothing collected yet">
                Enable <span className="mono">malwarebazaar</span> and{" "}
                <span className="mono">urlhaus</span> on Source Health.
              </Empty>
            )}
          </Panel>

          {recent ? (
            <Pagination base="/iocs" params={sp} page={page} total={recent.total} pageSize={30} />
          ) : null}
        </>
      ) : null}
    </>
  );
}

function LookupResult({ result }: { result: Lookup }) {
  if (!result.found) {
    return (
      <Panel title={`Nothing known about this ${result.kind}`}>
        {/* Absence is not safety, and the page says so rather than letting a
            clean result read as a clean verdict. */}
        <p className="desc">
          <span className="mono">{result.query}</span> does not appear in {result.scope}. That is a
          much smaller corpus than the internet: it is not evidence the indicator is safe, only
          that these two feeds have not published it recently.
        </p>
      </Panel>
    );
  }

  return (
    <Panel title={`Known — ${result.total} record${result.total === 1 ? "" : "s"}`}>
      {result.items.map((row) => {
        const attack = row.attack_stix_id ? result.attack[row.attack_stix_id] : undefined;
        return (
          <div key={row.id} className="ioc-hit">
            <div className="ioc-hit-head">
              <span className="mono ioc-value">{row.value}</span>
              {row.status === "online" ? <span className="sev sev-high">online</span> : null}
            </div>
            <dl className="kv">
              <dt>Source</dt>
              <dd>
                {row.reference_url ? (
                  <a href={row.reference_url} target="_blank" rel="noreferrer noopener" className="link">
                    {SOURCE_LABEL[row.source_key] ?? row.source_key}
                  </a>
                ) : (
                  SOURCE_LABEL[row.source_key] ?? row.source_key
                )}
              </dd>
              {row.family ? (
                <>
                  <dt>Family</dt>
                  <dd>
                    {row.family}
                    {attack ? (
                      <>
                        {" — "}
                        <Link href={`/attack/${attack.external_id ?? attack.stix_id}`} className="link">
                          {attack.name}
                          {attack.external_id ? ` (${attack.external_id})` : ""}
                        </Link>
                      </>
                    ) : (
                      <span className="faint"> · not in the Enterprise ATT&CK matrix</span>
                    )}
                  </dd>
                </>
              ) : null}
              {row.threat ? (
                <>
                  <dt>Threat</dt>
                  <dd>{row.threat}</dd>
                </>
              ) : null}
              {row.file_type ? (
                <>
                  <dt>File</dt>
                  <dd>{row.file_type}</dd>
                </>
              ) : null}
              {Object.keys(row.related).length ? (
                <>
                  <dt>Also</dt>
                  <dd className="mono ioc-related">
                    {Object.entries(row.related).map(([k, v]) => (
                      <span key={k}>
                        {k} {v}
                      </span>
                    ))}
                  </dd>
                </>
              ) : null}
              {row.tags.length ? (
                <>
                  <dt>Tags</dt>
                  <dd>
                    <span className="tags">
                      {row.tags.map((t) => (
                        <span key={t} className="tag tag-mono">
                          {t}
                        </span>
                      ))}
                    </span>
                  </dd>
                </>
              ) : null}
              <dt>First seen</dt>
              <dd className="faint">{relative(row.first_seen_at)}</dd>
            </dl>
          </div>
        );
      })}
      <p className="faint small ioc-scope">Searched {result.scope} — nothing else.</p>
    </Panel>
  );
}
