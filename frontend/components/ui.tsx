import Link from "next/link";
import type { Doc, ExploitItem, Reason, SourceInfo, Vuln } from "@/lib/api";
import { PLATFORM_LABELS, fmtDate, relative, riskLevel, severityClass, tierLabel, vulnLabel } from "@/lib/format";
import { IconExternal } from "@/components/icons";

export function PageHead({
  title,
  sub,
  right,
  children,
}: {
  title: string;
  sub?: string;
  right?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <header className="page-head">
      <div className="page-head-row">
        <div>
          <h1>{title}</h1>
          {sub ? <p className="page-sub">{sub}</p> : null}
        </div>
        {right}
      </div>
      {children}
    </header>
  );
}

export function Panel({
  title,
  action,
  children,
  flush,
}: {
  title?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="panel">
      {title ? (
        <div className="panel-head">
          <h2>{title}</h2>
          {action}
        </div>
      ) : null}
      <div className={flush ? "panel-body flush" : "panel-body"}>{children}</div>
    </section>
  );
}

export function Empty({ title, children }: { title?: string; children?: React.ReactNode }) {
  return (
    <div className="empty">
      {title ? <strong>{title}</strong> : null}
      {children}
    </div>
  );
}

export function Tier({ tier }: { tier: number }) {
  return (
    <span className={`tier tier-${tier}`} title={tierLabel(tier)}>
      <i className="tier-dot" />
      Tier {tier}
    </span>
  );
}

/** External links never render HTML and always carry safe rel attributes. */
export function Ext({ href, children, plain }: { href: string; children: React.ReactNode; plain?: boolean }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer nofollow" className={plain ? undefined : "link"}>
      {children}
    </a>
  );
}

/** Risk = a bar you can scan, not a bare number. */
export function Risk({ value, reasons }: { value: number; reasons?: Reason[] }) {
  const title = reasons?.length
    ? "Threat Relevance — " + reasons.map((r) => `+${r.points} ${r.factor}`).join(", ")
    : "Threat Relevance score";
  return (
    <span className={`risk r-${riskLevel(value)}`} title={title}>
      <span className="risk-meter">
        <span style={{ width: `${Math.max(3, value)}%` }} />
      </span>
      <span className="risk-score tnum">{value}</span>
    </span>
  );
}

export function Severity({ score, severity }: { score: number | null; severity: string | null }) {
  return (
    <span className={severityClass(severity)} title={severity ? `CVSS ${severity}` : "No CVSS score"}>
      {score ?? "—"}
    </span>
  );
}

export function ReasonList({ reasons }: { reasons: Reason[] }) {
  if (!reasons.length) return <p className="faint">No scoring factors recorded yet.</p>;
  return (
    <ul className="reasons">
      {reasons.map((r, i) => (
        <li key={i}>
          <span className="reason-pts">+{r.points}</span>
          <span>
            <span className="reason-factor">{r.factor}</span>
            <div className="reason-detail">{r.detail}</div>
          </span>
        </li>
      ))}
    </ul>
  );
}

/** Only genuinely alarming signals get colour; the rest stay neutral. */
export function Signals({ v }: { v: Vuln }) {
  return (
    <span className="signals">
      {v.in_kev ? (
        <span className="tag tag-strong" title="Listed in the CISA Known Exploited Vulnerabilities catalog">
          KEV
        </span>
      ) : null}
      {v.actively_exploited && !v.in_kev ? (
        <span className="tag tag-strong" title="Exploitation reported by a collected source">
          Exploited
        </span>
      ) : null}
      {v.has_exploit ? (
        <span className="tag tag-warn" title={`${v.exploit_count} public exploit(s)`}>
          Exploit{v.exploit_count > 1 ? ` ${v.exploit_count}` : ""}
        </span>
      ) : null}
      {v.has_poc ? (
        <span className="tag" title={`${v.poc_count} public proof-of-concept repo(s), unverified`}>
          PoC{v.poc_count > 1 ? ` ${v.poc_count}` : ""}
        </span>
      ) : null}
      {!v.in_kev && !v.actively_exploited && !v.has_exploit && !v.has_poc ? (
        <span className="faint">—</span>
      ) : null}
    </span>
  );
}

/**
 * Five columns instead of nine. The truncated description line is gone: it never
 * fitted, and the CVE page is one click away.
 */
export function ThreatTable({ items }: { items: Vuln[] }) {
  if (!items.length)
    return (
      <Empty title="Nothing matches these filters">
        Try widening the time window or clearing a filter.
      </Empty>
    );
  return (
    <table>
      <thead>
        <tr>
          <th style={{ width: 96 }}>Risk</th>
          <th>Vulnerability</th>
          <th style={{ width: 190 }}>Product</th>
          <th style={{ width: 240 }}>Signals</th>
          <th style={{ width: 90 }} className="num">CVSS</th>
          <th style={{ width: 110 }}>Activity</th>
        </tr>
      </thead>
      <tbody>
        {items.map((v) => (
          <tr key={v.cve_id}>
            <td>
              <Risk value={v.relevance_score} reasons={v.relevance_reasons} />
            </td>
            <td>
              <Link href={`/cve/${v.cve_id}`} className="cve-cell">
                <span className="cve-id">{v.cve_id}</span>
                <span className="cve-name">{vulnLabel(v)}</span>
              </Link>
            </td>
            <td>
              <div className="truncate" style={{ maxWidth: 180 }}>
                {v.vendor || "—"}
              </div>
              <div className="faint truncate" style={{ maxWidth: 180 }}>
                {v.product || ""}
              </div>
            </td>
            <td>
              <Signals v={v} />
            </td>
            <td className="num">
              <Severity score={v.cvss_score} severity={v.severity} />
            </td>
            <td className="nowrap faint" title={`First seen ${fmtDate(v.first_seen)}`}>
              {relative(v.last_activity_at)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function DocList({ docs, limit }: { docs: Doc[]; limit?: number }) {
  if (!docs.length) return <Empty title="Nothing collected yet">Sources may still be syncing.</Empty>;
  return (
    <ul className="doc-list">
      {(limit ? docs.slice(0, limit) : docs).map((d) => (
        <li className="doc" key={d.id}>
          <Ext href={d.url} plain>
            <span className="doc-title">{d.title}</span>
          </Ext>
          {d.summary ? <p className="doc-sum">{d.summary}</p> : null}
          <div className="doc-meta">
            <Tier tier={d.source.tier} />
            <span className="faint">{d.source.name}</span>
            <span className="faint">· {fmtDate(d.published_at)}</span>
            {d.reports_exploitation ? <span className="tag tag-strong">Reports exploitation</span> : null}
            {d.cves.slice(0, 3).map((c) => (
              <Link key={c} href={`/cve/${c}`} className="tag tag-accent tag-mono">
                {c}
              </Link>
            ))}
            {(d.entities || []).slice(0, 3).map((e) => (
              <Link key={e.stix_id} href={`/attack/${e.external_id || e.stix_id}`} className="tag">
                {e.name}
              </Link>
            ))}
          </div>
        </li>
      ))}
    </ul>
  );
}

export function ExploitTable({ items }: { items: ExploitItem[] }) {
  if (!items.length) return <Empty title="No exploits or PoCs match">Try another filter.</Empty>;
  return (
    <table>
      <thead>
        <tr>
          <th style={{ width: 84 }}>Kind</th>
          <th>Title</th>
          <th style={{ width: 150 }}>CVE</th>
          <th style={{ width: 130 }}>Source</th>
          <th style={{ width: 110 }}>Published</th>
        </tr>
      </thead>
      <tbody>
        {items.map((e) => (
          <tr key={`${e.source.key}-${e.id}`}>
            <td>
              <span className={`tag ${e.kind === "exploit" ? "tag-warn" : ""}`}>{e.kind}</span>
            </td>
            <td>
              <Ext href={e.url} plain>
                <span className="doc-title">{e.title}</span>
              </Ext>
              <div className="faint">
                {e.verified ? "Verified · " : ""}
                {e.platform || e.language || "—"}
                {e.author ? ` · ${e.author}` : ""}
                {e.warning ? " · unverified community code" : ""}
              </div>
            </td>
            <td className="nowrap">
              {e.cve_ids.slice(0, 2).map((c) => (
                <Link key={c} href={`/cve/${c}`} className="tag tag-accent tag-mono" style={{ marginRight: 4 }}>
                  {c}
                </Link>
              ))}
              {e.cve_ids.length === 0 ? <span className="faint">—</span> : null}
            </td>
            <td>
              <Tier tier={e.tier} />
              <div className="faint">{e.source.name}</div>
            </td>
            <td className="nowrap faint">{fmtDate(e.published_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Pagination({
  total,
  page,
  pageSize,
  params,
  base,
}: {
  total: number;
  page: number;
  pageSize: number;
  params: Record<string, string | string[] | undefined>;
  base: string;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const build = (p: number) => {
    const sp = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (k === "page" || v === undefined) continue;
      if (Array.isArray(v)) v.forEach((x) => sp.append(k, x));
      else sp.append(k, v);
    }
    sp.set("page", String(p));
    return `${base}?${sp.toString()}`;
  };
  if (pages <= 1) return null;
  return (
    <nav className="pagination">
      <span>
        Page {page} of {pages.toLocaleString()}
      </span>
      <span className="row">
        {page > 1 ? (
          <Link className="btn" href={build(page - 1)}>
            ← Previous
          </Link>
        ) : null}
        {page < pages ? (
          <Link className="btn" href={build(page + 1)}>
            Next →
          </Link>
        ) : null}
      </span>
    </nav>
  );
}

export function ExternalIcon() {
  return <IconExternal />;
}

export function PlatformTags({ platforms }: { platforms: string[] }) {
  if (!platforms.length) return <span className="faint">—</span>;
  return (
    <span className="tags">
      {platforms.map((p) => (
        <span key={p} className="tag">
          {PLATFORM_LABELS[p] || p}
        </span>
      ))}
    </span>
  );
}

export function SourceTag({ source }: { source: SourceInfo }) {
  return (
    <span className="row" style={{ gap: 6 }}>
      <Tier tier={source.tier} />
      <span className="faint">{source.name}</span>
    </span>
  );
}
