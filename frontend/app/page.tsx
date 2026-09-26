import Link from "next/link";
import { apiSafe, type AttackItem, type Doc, type ExploitItem, type Vuln } from "@/lib/api";
import { fmtDateTime } from "@/lib/format";
import { Segmented, WINDOW_OPTIONS, one, type SP } from "@/components/Filters";
import { DocList, Empty, PageHead, Panel, ThreatTable } from "@/components/ui";
import { IconAlert } from "@/components/icons";
import { Pending } from "@/components/Pending";
import { Fold } from "@/components/Fold";

export const dynamic = "force-dynamic";

interface Overview {
  window: string;
  generated_at: string;
  cards: Record<string, number>;
  top_threats: Vuln[];
  latest_research: Doc[];
  latest_news: Doc[];
  latest_exploits: ExploitItem[];
  trending_attack: AttackItem[];
  source_health: { total: number; enabled: number; errors: string[]; stale: string[] };
  phase_2_pending: string[];
}

/** Only the things that should change what you do today. */
const HEADLINE = [
  {
    key: "actively_exploited",
    label: "Being exploited",
    href: "/threats?exploited=true",
    hint: "Confirmed exploitation in the wild",
    alert: true,
  },
  {
    key: "kev_added",
    label: "Added to CISA KEV",
    href: "/threats?kev=true",
    hint: "New entries in the KEV catalog",
    alert: true,
  },
  { key: "new_pocs", label: "New public PoCs", href: "/exploits?kind=poc", hint: "Unverified community code" },
  { key: "new_research", label: "New research", href: "/research", hint: "Tier 1–2 reports" },
];

/** Everything else: present, but not competing for attention. */
const SECONDARY = [
  { key: "new_cves", label: "CVEs published", href: "/vulnerabilities" },
  { key: "new_exploits", label: "Exploits", href: "/exploits?kind=exploit" },
  { key: "new_news", label: "News", href: "/news" },
  { key: "threat_actors_seen", label: "Actors seen", href: "/actors" },
  { key: "malware_seen", label: "Malware seen", href: "/malware" },
  { key: "campaigns_seen", label: "Campaigns", href: "/campaigns" },
  { key: "new_detection_rules", label: "Detection repos", href: "/exploits?kind=detection" },
];

const WINDOW_LABEL: Record<string, string> = {
  "24h": "the last 24 hours",
  "7d": "the last 7 days",
  "30d": "the last 30 days",
  "90d": "the last 90 days",
  all: "all time",
};

export default async function DashboardPage({ searchParams }: { searchParams: Promise<SP> }) {
  const sp = await searchParams;
  const window = one(sp, "window") || "24h";
  const data = await apiSafe<Overview>("/api/dashboard/overview", { window });

  if (!data) {
    return (
      <>
        <PageHead title="Overview" />
        <div className="notice notice-danger">
          <IconAlert />
          <div>
            <b>The API is not reachable.</b>
            <div>
              Check that the backend is running — <code>docker compose ps</code>.
            </div>
          </div>
        </div>
      </>
    );
  }

  const unhealthy = data.source_health.errors.length + data.source_health.stale.length;
  const urgent = (data.cards.actively_exploited ?? 0) + (data.cards.kev_added ?? 0);

  return (
    <>
      <PageHead
        title="Overview"
        sub={`What changed in ${WINDOW_LABEL[window] ?? window}. Updated ${fmtDateTime(data.generated_at)}.`}
        right={<Segmented base="/" sp={sp} param="window" options={WINDOW_OPTIONS} fallback="24h" />}
      />

      {unhealthy > 0 ? (
        <div className="notice notice-warn">
          <IconAlert />
          <div>
            <b>
              {unhealthy} source{unhealthy === 1 ? "" : "s"} stale or failing.
            </b>{" "}
            This view may be missing data. <Link href="/sources" className="link">Check source health →</Link>
          </div>
        </div>
      ) : null}

      <div className="kpis">
        {HEADLINE.map((c) => {
          const value = data.cards[c.key] ?? 0;
          const hot = Boolean(c.alert) && value > 0;
          return (
            <Link key={c.key} href={c.href} className={`kpi${hot ? " alert" : ""}${value === 0 ? " zero" : ""}`}>
              <span className="kpi-label">{c.label}</span>
              <div className="kpi-value">{value}</div>
              <div className="kpi-sub">{c.hint}</div>
              <Pending />
            </Link>
          );
        })}
      </div>

      <Fold label="Everything else collected" count={SECONDARY.length}>
      <div className="metric-strip">
        {SECONDARY.map((m) => {
          const value = data.cards[m.key] ?? 0;
          return (
            <Link key={m.key} href={m.href} className={`metric${value === 0 ? " is-zero" : ""}`}>
              <b>{value.toLocaleString()}</b>
              {m.label}
              <Pending />
            </Link>
          );
        })}
      </div>
      </Fold>

      <Panel
        title={urgent > 0 ? "Start here" : "Highest relevance"}
        action={
          <Link href="/threats" className="link small">
            Open threat table →
          </Link>
        }
        flush
      >
        <ThreatTable items={data.top_threats} />
      </Panel>

      <div className="grid-2">
        <Panel
          title="Latest research"
          action={
            <Link href="/research" className="link small">
              All →
            </Link>
          }
        >
          <DocList docs={data.latest_research} limit={5} />
        </Panel>
        <Panel
          title="Security news"
          action={
            <Link href="/news" className="link small">
              All →
            </Link>
          }
        >
          <DocList docs={data.latest_news} limit={5} />
        </Panel>
      </div>

      <Panel
        title="Who and what is being talked about"
        action={
          <Link href="/attack" className="link small">
            ATT&CK matrix →
          </Link>
        }
      >
        {data.trending_attack.length ? (
          <div className="tags">
            {data.trending_attack.map((a) => (
              <Link key={a.stix_id} href={`/attack/${a.external_id || a.stix_id}`} className="tag">
                {a.name}
                <span className="faint">{a.mentions}</span>
              </Link>
            ))}
          </div>
        ) : (
          <Empty title="No actors or techniques mentioned in this window">
            Widen the window, or wait for the next collection cycle.
          </Empty>
        )}
      </Panel>
    </>
  );
}
