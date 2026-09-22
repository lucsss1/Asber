import { apiSafe, type Paged, type Vuln } from "@/lib/api";
import {
  ClearFilters,
  IMPACT_OPTIONS,
  PLATFORM_OPTIONS,
  PillSelect,
  Segmented,
  TextFilters,
  Toggles,
  WINDOW_OPTIONS,
  one,
  type SP,
} from "@/components/Filters";
import { PageHead, Pagination, Panel, ThreatTable } from "@/components/ui";

export const dynamic = "force-dynamic";

const SORTS = [
  { value: "relevance", label: "Most relevant" },
  { value: "recent", label: "Latest activity" },
  { value: "published", label: "Newest CVE" },
  { value: "cvss", label: "Highest CVSS" },
  { value: "kev", label: "Recently in KEV" },
];

export default async function ThreatsPage({ searchParams }: { searchParams: Promise<SP> }) {
  const sp = await searchParams;
  const page = Number(one(sp, "page") || 1);
  const data = await apiSafe<Paged<Vuln>>("/api/vulnerabilities", {
    window: one(sp, "window") || "30d",
    kev: one(sp, "kev"),
    exploited: one(sp, "exploited"),
    exploit: one(sp, "exploit"),
    poc: one(sp, "poc"),
    tag: one(sp, "tag"),
    platform: one(sp, "platform"),
    vendor: one(sp, "vendor"),
    product: one(sp, "product"),
    q: one(sp, "q"),
    actor: one(sp, "actor"),
    technique: one(sp, "technique"),
    sort: one(sp, "sort") || "relevance",
    min_score: one(sp, "min_score"),
    page,
    page_size: 30,
  });

  return (
    <>
      <PageHead
        title="Active threats"
        sub="Ranked by Threat Relevance — a transparent score. Hover any bar to see the factors behind it."
        right={<Segmented base="/threats" sp={sp} param="window" options={WINDOW_OPTIONS} fallback="30d" />}
      />

      <div className="toolbar">
        <Toggles
          base="/threats"
          sp={sp}
          options={[
            { param: "exploited", label: "Exploited", title: "Exploitation reported by a collected source" },
            { param: "kev", label: "In CISA KEV" },
            { param: "exploit", label: "Has exploit" },
            { param: "poc", label: "Has PoC" },
          ]}
        />
        <span className="spacer" />
        <TextFilters
          base="/threats"
          sp={sp}
          fields={[{ name: "q", placeholder: "Filter by text…" }]}
          sorts={SORTS}
          sortDefault="relevance"
        />
        <ClearFilters base="/threats" sp={sp} ignore={["sort", "window"]} />
        <details
          className="more"
          style={{ width: "100%" }}
          open={Boolean(one(sp, "tag") || one(sp, "platform") || one(sp, "vendor"))}
        >
          <summary>Impact, platform & vendor</summary>
          <div className="more-body">
            <PillSelect base="/threats" sp={sp} param="tag" options={IMPACT_OPTIONS} label="Impact" />
            <span style={{ width: "100%" }} />
            <PillSelect base="/threats" sp={sp} param="platform" options={PLATFORM_OPTIONS} label="Platform" />
            <span style={{ width: "100%" }} />
            <TextFilters
              base="/threats"
              sp={sp}
              fields={[
                { name: "vendor", placeholder: "Vendor…" },
                { name: "product", placeholder: "Product…" },
              ]}
            />
          </div>
        </details>
      </div>

      {!data ? (
        <div className="notice notice-danger">API unavailable.</div>
      ) : (
        <>
          <Panel title={`${data.total.toLocaleString()} vulnerabilities`} flush>
            <ThreatTable items={data.items} />
          </Panel>
          <Pagination total={data.total} page={data.page} pageSize={data.page_size} params={sp} base="/threats" />
        </>
      )}
    </>
  );
}
