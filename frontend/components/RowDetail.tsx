"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Tier } from "@/components/ui";

type Named = { name: string; external_id?: string | null; stix_id: string };

type Detail = {
  risk?: { relevance_score: number; reasons: { points: number; factor: string; detail: string }[] };
  cvss?: { score: number | null; severity: string | null; vector: string | null };
  affected_products?: { vendor: string | null; product: string | null }[];
  exploitation?: { source: string; tier: number; detail: string; date: string | null }[];
  public_exploits?: unknown[];
  pocs?: unknown[];
  threat_actors?: Named[];
  malware?: Named[];
  campaigns?: Named[];
  attack?: { external_id: string; name: string }[];
  sources?: { source: string; tier: number }[];
};

/**
 * What a row is hiding. Fetched when it is opened, never before — the cost of
 * this depth is paid only by the person who asks for it, which is the whole
 * point of putting it here instead of in the table.
 */
export function RowDetail({ cveId }: { cveId: string }) {
  const [data, setData] = useState<Detail | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const abort = new AbortController();
    fetch(`/api/vulnerabilities/${encodeURIComponent(cveId)}`, { signal: abort.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
      .then(setData)
      .catch((e) => {
        if (e.name !== "AbortError") setFailed(true);
      });
    return () => abort.abort();
  }, [cveId]);

  if (failed) return <p className="faint">Could not load the detail for {cveId}.</p>;

  if (!data) {
    return (
      <div className="rd-loading" aria-busy="true">
        <span className="sr-only">Loading detail</span>
        {[68, 44, 56].map((w, i) => (
          <span key={i} className="rd-bar" style={{ width: `${w}%` }} />
        ))}
      </div>
    );
  }

  const products = data.affected_products ?? [];
  const named: Named[] = [
    ...(data.threat_actors ?? []),
    ...(data.malware ?? []),
    ...(data.campaigns ?? []),
  ];
  const cells: { label: string; body: React.ReactNode }[] = [];

  if (data.risk?.reasons?.length) {
    cells.push({
      label: `Why ${data.risk.relevance_score}`,
      body: (
        <ul className="rd-reasons">
          {data.risk.reasons.slice(0, 4).map((r, i) => (
            <li key={i}>
              <b>+{r.points}</b> {r.factor}
            </li>
          ))}
          {data.risk.reasons.length > 4 ? (
            <li className="faint">+{data.risk.reasons.length - 4} more factors</li>
          ) : null}
        </ul>
      ),
    });
  }

  if (data.exploitation?.length) {
    cells.push({
      label: "Exploitation reported by",
      body: <span>{[...new Set(data.exploitation.map((e) => e.source))].join(" · ")}</span>,
    });
  }

  if (data.cvss?.vector) {
    cells.push({
      label: `CVSS ${data.cvss.score ?? "—"}`,
      body: <span className="mono rd-wrap">{data.cvss.vector}</span>,
    });
  }

  if (products.length) {
    cells.push({
      label: `Affected ${products.length > 1 ? `(${products.length})` : ""}`,
      body: (
        <span>
          {products
            .slice(0, 4)
            .map((p) => [p.vendor, p.product].filter(Boolean).join(" "))
            .join(" · ")}
          {products.length > 4 ? ` · +${products.length - 4}` : ""}
        </span>
      ),
    });
  }

  if (data.attack?.length) {
    cells.push({
      label: "ATT&CK",
      body: (
        <span className="tags">
          {data.attack.slice(0, 6).map((t) => (
            <Link key={t.external_id} href={`/attack/${t.external_id}`} className="tag tag-mono" title={t.name}>
              {t.external_id}
            </Link>
          ))}
        </span>
      ),
    });
  }

  if (named.length) {
    cells.push({
      label: "Linked to",
      body: (
        <span className="tags">
          {named.slice(0, 6).map((n) => (
            <Link key={n.stix_id} href={`/attack/${n.external_id || n.stix_id}`} className="tag">
              {n.name}
            </Link>
          ))}
        </span>
      ),
    });
  }

  // 52 references can come from six publishers; the publisher is the fact.
  const publishers = [...new Map((data.sources ?? []).map((s) => [s.source, s])).values()];
  if (publishers.length) {
    cells.push({
      label: `${publishers.length} source${publishers.length > 1 ? "s" : ""}`,
      body: (
        <span className="tags">
          {publishers.slice(0, 5).map((s) => (
            <span key={s.source} className="row" style={{ gap: 5 }}>
              <Tier tier={s.tier} />
              <span className="faint">{s.source}</span>
            </span>
          ))}
          {publishers.length > 5 ? <span className="faint">+{publishers.length - 5}</span> : null}
        </span>
      ),
    });
  }

  const counts = [
    (data.public_exploits?.length ?? 0) > 0 ? `${data.public_exploits!.length} exploit` : null,
    (data.pocs?.length ?? 0) > 0 ? `${data.pocs!.length} PoC` : null,
  ].filter(Boolean);

  return (
    <div className="rd">
      <div className="rd-grid">
        {cells.map((c, i) => (
          // The stagger is what makes it read as unfolding rather than dumping.
          <div key={c.label} className="rd-cell" style={{ "--i": i } as React.CSSProperties}>
            <div className="rd-label">{c.label}</div>
            <div className="rd-body">{c.body}</div>
          </div>
        ))}
      </div>
      <div className="rd-foot">
        <span className="faint">{counts.join(" · ")}</span>
        <Link href={`/cve/${cveId}`} className="link small">
          Everything on {cveId} →
        </Link>
      </div>
    </div>
  );
}
