import Link from "next/link";
import { notFound } from "next/navigation";
import { ApiError, api, type Doc, type ExploitItem, type Reason, type Vuln } from "@/lib/api";
import { PLATFORM_LABELS, TAG_LABELS, fmtDate, riskColor, riskLabel, severityClass, tierLabel } from "@/lib/format";
import { DocList, Empty, Ext, PageHead, Panel, ReasonList, Tier } from "@/components/ui";
import { IconAlert, IconClock } from "@/components/icons";
import { Expandable } from "@/components/Expandable";

export const dynamic = "force-dynamic";

interface TechniqueMapping {
  external_id: string;
  name: string;
  url: string | null;
  tactics: { shortname: string; name: string; external_id: string }[];
  platforms: string[];
  description: string;
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
  legacy_detection: string | null;
  mitigations: { external_id: string; name: string; url: string | null; how: string }[];
  mapping: { method: string; detail: string; evidence: { title: string; url: string; source: string }[] };
}

interface AttackRef {
  stix_id: string;
  external_id: string | null;
  name: string;
  type: string;
  evidence: { document_id: number; title: string; url: string; source: string; snippet: string | null }[];
}

interface Detail {
  cve_id: string;
  tracked: boolean;
  overview: Vuln & { description?: string | null; cwes?: string[]; vuln_status?: string | null };
  risk: { relevance_score: number; reasons: Reason[]; note: string };
  cvss: { score: number | null; severity: string | null; vector: string | null; version: string | null } | null;
  ssvc: { exploitation: string | null; automatable: string | null; technical_impact: string | null } | null;
  kev: {
    in_kev: boolean;
    name: string | null;
    date_added: string | null;
    due_date: string | null;
    required_action: string | null;
    ransomware_use: string | null;
    notes: string | null;
  } | null;
  affected_products: { vendor: string; product: string; cpe: string | null; versions: string | null; source: string }[];
  exploitation: { source: string; tier: number; detail: string | null; date: string | null; url?: string }[];
  public_exploits: ExploitItem[];
  pocs: ExploitItem[];
  other_repositories: ExploitItem[];
  threat_actors: AttackRef[];
  campaigns: AttackRef[];
  malware: AttackRef[];
  attack: TechniqueMapping[];
  detection: {
    attack_detection_strategies: number;
    sigma: { status: string; items: unknown[] };
    yara: { status: string; items: unknown[] };
    detection_repositories: ExploitItem[];
  };
  vendor_advisories: ({ url: string; title: string | null; tags?: string[]; source?: string } & Partial<Doc>)[];
  research: Doc[];
  news: Doc[];
  timeline: { date: string; kind: string; title: string; source: string; url: string | null }[];
  sources: {
    url: string;
    title: string | null;
    ref_type: string;
    tags: string[];
    source: string;
    source_type: string;
    tier: number;
    published: string | null;
    collected: string | null;
  }[];
}

export default async function CvePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let d: Detail;
  try {
    d = await api<Detail>(`/api/vulnerabilities/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && (err.status === 404 || err.status === 400)) notFound();
    throw err;
  }

  const o = d.overview;
  const cve = d.cve_id;
  const score = d.risk.relevance_score;
  const exploitTotal = d.public_exploits.length + d.pocs.length;
  const adversaries = [...d.threat_actors, ...d.campaigns, ...d.malware];

  return (
    <>
      <PageHead
        title={cve}
        sub={d.kev?.name || (o.title && o.title.length <= 90 ? o.title : undefined)}
        right={
          <span className="row">
            <a className="btn" href={`/api/vulnerabilities/${cve}/export?format=markdown`}>
              Markdown
            </a>
            <a className="btn" href={`/api/vulnerabilities/${cve}/export?format=json`}>
              JSON
            </a>
            <a className="btn" href={`/api/vulnerabilities/${cve}/export?format=csv`}>
              CSV
            </a>
          </span>
        }
      />

      {!d.tracked ? (
        <div className="notice notice-warn">
          <IconAlert />
          <div>Not tracked locally — this page shows only correlated mentions.</div>
        </div>
      ) : null}

      {/* -------- the verdict, before any detail -------- */}
      <section className="panel">
        <div className="verdict">
          <div className="verdict-score">
            <div className="verdict-num" style={{ color: riskColor(score) }}>
              {score}
            </div>
            <div className="verdict-max">{riskLabel(score)}</div>
            <div className="verdict-bar">
              <span style={{ width: `${Math.max(3, score)}%`, background: riskColor(score) }} />
            </div>
          </div>
          <div className="facts">
            {d.kev?.in_kev ? (
              <span className="fact hot">
                In <b>CISA KEV</b> since {fmtDate(d.kev.date_added)}
              </span>
            ) : null}
            {o.actively_exploited ? (
              <span className="fact hot">
                <b>Exploited</b> in the wild
              </span>
            ) : (
              <span className="fact">No exploitation reported</span>
            )}
            {d.kev?.ransomware_use?.toLowerCase() === "known" ? (
              <span className="fact hot">
                Used by <b>ransomware</b>
              </span>
            ) : null}
            <span className={`fact${exploitTotal ? " hot" : ""}`}>
              {exploitTotal ? (
                <>
                  <b>
                    {d.public_exploits.length} exploit{d.public_exploits.length === 1 ? "" : "s"}
                  </b>
                  , {d.pocs.length} PoC
                </>
              ) : (
                "No public exploit"
              )}
            </span>
            <span className="fact">
              CVSS <b className={severityClass(d.cvss?.severity)}>{d.cvss?.score ?? "n/a"}</b>
            </span>
            {o.vendor ? (
              <span className="fact">
                <b>{o.vendor}</b> {o.product || ""}
              </span>
            ) : null}
            {adversaries.length ? (
              <span className="fact">
                Linked to <b>{adversaries[0].name}</b>
                {adversaries.length > 1 ? ` +${adversaries.length - 1}` : ""}
              </span>
            ) : null}
            <span className="fact">
              <IconClock size={14} /> {fmtDate(o.published)}
            </span>
          </div>
        </div>
      </section>

      <div className="grid-2">
        <Panel title="What it is">
          <Expandable text={o.description || "No description available."} />
          <dl className="kv" style={{ marginTop: 16 }}>
            <dt>Impact</dt>
            <dd>
              <span className="tags">
                {o.tags.length ? (
                  o.tags.map((t) => (
                    <span key={t} className="tag">
                      {TAG_LABELS[t] || t}
                    </span>
                  ))
                ) : (
                  <span className="faint">Not classified</span>
                )}
              </span>
            </dd>
            <dt>Platforms</dt>
            <dd>
              <span className="tags">
                {o.platforms.length ? (
                  o.platforms.map((p) => (
                    <span key={p} className="tag">
                      {PLATFORM_LABELS[p] || p}
                    </span>
                  ))
                ) : (
                  <span className="faint">—</span>
                )}
              </span>
            </dd>
            <dt>CWE</dt>
            <dd>{(o.cwes || []).join(", ") || <span className="faint">—</span>}</dd>
            <dt>CVSS vector</dt>
            <dd className="mono faint">{d.cvss?.vector || "—"}</dd>
            {d.ssvc?.exploitation ? (
              <>
                <dt>CISA SSVC</dt>
                <dd>
                  exploitation <b>{d.ssvc.exploitation}</b> · automatable {d.ssvc.automatable || "?"} · impact{" "}
                  {d.ssvc.technical_impact || "?"}
                </dd>
              </>
            ) : null}
            <dt>Sources</dt>
            <dd>{o.source_count} independent</dd>
          </dl>
        </Panel>

        <Panel title={`Why it scores ${score}`}>
          <ReasonList reasons={d.risk.reasons} />
          <p className="faint" style={{ marginTop: 14 }}>
            {d.risk.note}
          </p>
        </Panel>
      </div>

      {/* -------- exploitation + exploits -------- */}
      <div className="grid-2">
        <Panel title="Exploitation evidence">
          {d.exploitation.length ? (
            <ul className="list-reset stack">
              {d.exploitation.map((e, i) => (
                <li key={i}>
                  <div className="row" style={{ gap: 8 }}>
                    <Tier tier={e.tier} />
                    <b style={{ fontSize: 14 }}>{e.source}</b>
                    <span className="faint">{fmtDate(e.date)}</span>
                  </div>
                  <div className="muted small">{e.detail}</div>
                  {e.url ? (
                    <Ext href={e.url}>
                      <span className="small">View source →</span>
                    </Ext>
                  ) : null}
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="No exploitation evidence">Nothing collected reports this being exploited.</Empty>
          )}
        </Panel>

        <Panel title={`Exploits & PoCs${exploitTotal ? ` (${exploitTotal})` : ""}`}>
          {exploitTotal === 0 ? (
            <Empty title="No public exploit or PoC found" />
          ) : (
            <>
              <ul className="list-reset stack-sm">
                {[...d.public_exploits, ...d.pocs].slice(0, 12).map((e) => (
                  <li key={`${e.source.key}-${e.id}`} className="row" style={{ justifyContent: "space-between" }}>
                    <span className="row" style={{ gap: 8, minWidth: 0 }}>
                      <span className={`tag ${e.kind === "exploit" ? "tag-warn" : ""}`}>{e.kind}</span>
                      <Ext href={e.url}>
                        <span className="truncate" style={{ maxWidth: 330, display: "inline-block" }}>
                          {e.title}
                        </span>
                      </Ext>
                    </span>
                    <span className="faint nowrap">{fmtDate(e.published_at)}</span>
                  </li>
                ))}
              </ul>
              {d.pocs.length ? (
                <div className="notice notice-warn" style={{ marginTop: 14, marginBottom: 0 }}>
                  <IconAlert />
                  <div>Community PoC code is unverified and may be malicious. Never run it outside a lab.</div>
                </div>
              ) : null}
            </>
          )}
        </Panel>
      </div>

      {/* -------- adversaries -------- */}
      {adversaries.length ? (
        <Panel title="Who is associated with this">
          <p className="faint" style={{ marginBottom: 14 }}>
            Derived from co-mentions in focused reports — open the evidence to verify each claim.
          </p>
          <ul className="list-reset stack">
            {adversaries.map((a) => (
              <li key={a.stix_id}>
                <div className="row" style={{ gap: 8 }}>
                  <Link href={`/attack/${a.external_id || a.stix_id}`} className="link">
                    <b>{a.name}</b>
                  </Link>
                  <span className="tag">{a.type}</span>
                </div>
                {a.evidence.slice(0, 2).map((ev, i) => (
                  <div key={i} className="faint">
                    ↳ <Ext href={ev.url}>{ev.title}</Ext> · {ev.source}
                  </div>
                ))}
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      {/* -------- ATT&CK + detection -------- */}
      <Panel title="How it is used and how to detect it">
        {d.attack.length === 0 ? (
          <Empty title="No technique mapping available" />
        ) : (
          <div className="stack">
            {d.attack.map((t) => (
              <div key={t.external_id}>
                <div className="row" style={{ gap: 8 }}>
                  <Link href={`/attack/${t.external_id}`} className="link">
                    <b>
                      {t.external_id} · {t.name}
                    </b>
                  </Link>
                  {t.tactics.map((x) => (
                    <span key={x.external_id} className="tag">
                      {x.name}
                    </span>
                  ))}
                  <span className={`tag ${t.mapping.method === "explicit" ? "tag-accent" : ""}`}>
                    {t.mapping.method === "explicit" ? "stated by a source" : "inferred"}
                  </span>
                </div>
                <div className="faint">{t.mapping.detail}</div>
                {t.mapping.evidence?.slice(0, 2).map((ev, i) => (
                  <div key={i} className="faint">
                    ↳ <Ext href={ev.url}>{ev.title}</Ext>
                  </div>
                ))}
                {t.detection_strategies.length ? (
                  <details className="more" style={{ marginTop: 8 }}>
                    <summary>
                      Detection: {t.detection_strategies.length} strateg
                      {t.detection_strategies.length === 1 ? "y" : "ies"} from ATT&CK
                    </summary>
                    <div className="more-body" style={{ display: "block" }}>
                      {t.detection_strategies.slice(0, 4).map((s) => (
                        <div key={s.external_id} className="small" style={{ marginBottom: 10 }}>
                          <Ext href={s.url || "https://attack.mitre.org/"}>
                            {s.external_id} · {s.name}
                          </Ext>
                          {s.analytics.slice(0, 2).map((a) => (
                            <div key={a.external_id} className="faint" style={{ paddingLeft: 14 }}>
                              {a.platforms.join(", ")}:{" "}
                              {a.log_sources
                                .map((ls) => [ls.name, ls.channel].filter(Boolean).join(" "))
                                .filter(Boolean)
                                .join(" · ") || "see ATT&CK"}
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </details>
                ) : null}
                {t.mitigations.length ? (
                  <div className="faint small" style={{ marginTop: 6 }}>
                    Mitigations: {t.mitigations.map((m) => `${m.external_id} ${m.name}`).join(" · ")}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        )}
        <p className="faint" style={{ marginTop: 14 }}>
          Sigma and YARA correlation arrives in Phase 2.
          {d.detection.detection_repositories.length
            ? ` ${d.detection.detection_repositories.length} community detection repo(s) mention this CVE.`
            : ""}
        </p>
      </Panel>

      {/* -------- timeline -------- */}
      <Panel title="Timeline">
        {d.timeline.length ? (
          <ul className="timeline">
            {d.timeline.map((ev, i) => (
              <li key={i} className={`k-${ev.kind}`}>
                <span className="tl-date">{fmtDate(ev.date)}</span>
                <span className="tl-rail">
                  <span className="tl-dot" />
                </span>
                <span>
                  <span className="tl-title">{ev.url ? <Ext href={ev.url}>{ev.title}</Ext> : ev.title}</span>
                  <div className="tl-meta">
                    {ev.kind.replace(/_/g, " ")} · {ev.source}
                  </div>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <Empty title="No dated events" />
        )}
      </Panel>

      {/* -------- reading -------- */}
      {d.research.length || d.news.length ? (
        <div className="grid-2">
          {d.research.length ? (
            <Panel title="Research & advisories">
              <DocList docs={d.research} limit={6} />
            </Panel>
          ) : null}
          {d.news.length ? (
            <Panel title="News coverage">
              <DocList docs={d.news} limit={6} />
            </Panel>
          ) : null}
        </div>
      ) : null}

      {/* -------- collapsed reference data -------- */}
      <Panel title="Reference data">
        <details className="more" style={{ marginBottom: 10 }}>
          <summary>Affected products ({d.affected_products.length})</summary>
          <div className="more-body" style={{ display: "block" }}>
            {d.affected_products.length ? (
              <table>
                <thead>
                  <tr>
                    <th>Vendor</th>
                    <th>Product</th>
                    <th>Versions</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {d.affected_products.slice(0, 80).map((p, i) => (
                    <tr key={i}>
                      <td>{p.vendor || "—"}</td>
                      <td>{p.product || "—"}</td>
                      <td className="faint">{p.versions || "—"}</td>
                      <td className="faint">{p.source}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="faint">No affected-product data.</p>
            )}
          </div>
        </details>

        {d.vendor_advisories.length ? (
          <details className="more" style={{ marginBottom: 10 }}>
            <summary>Vendor advisories & patches ({d.vendor_advisories.length})</summary>
            <div className="more-body" style={{ display: "block" }}>
              <ul className="list-reset stack-sm small">
                {d.vendor_advisories.slice(0, 25).map((a, i) => (
                  <li key={i}>
                    <Ext href={a.url}>{a.title || a.url}</Ext>
                  </li>
                ))}
              </ul>
            </div>
          </details>
        ) : null}

        <details className="more">
          <summary>All sources ({d.sources.length})</summary>
          <div className="more-body" style={{ display: "block" }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 90 }}>Tier</th>
                  <th style={{ width: 170 }}>Source</th>
                  <th>Reference</th>
                  <th style={{ width: 110 }}>Published</th>
                  <th style={{ width: 110 }}>Collected</th>
                </tr>
              </thead>
              <tbody>
                {d.sources.map((s, i) => (
                  <tr key={i}>
                    <td title={tierLabel(s.tier)}>
                      <Tier tier={s.tier} />
                    </td>
                    <td className="nowrap">
                      {s.source}
                      <div className="faint">{s.ref_type}</div>
                    </td>
                    <td>
                      <div className="truncate" style={{ maxWidth: 460 }}>
                        <Ext href={s.url}>{s.title || s.url}</Ext>
                      </div>
                    </td>
                    <td className="faint nowrap">{fmtDate(s.published)}</td>
                    <td className="faint nowrap">{fmtDate(s.collected)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      </Panel>
    </>
  );
}
