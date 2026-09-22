import { apiSafe, type Paged, type Vuln } from "@/lib/api";
import {
  ClearFilters,
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

const SEVERITIES = [
  { value: "CRITICAL", label: "Critical" },
  { value: "HIGH", label: "High" },
  { value: "MEDIUM", label: "Medium" },
  { value: "LOW", label: "Low" },
];

export default async function VulnerabilitiesPage({ searchParams }: { searchParams: Promise<SP> }) {
  const sp = await searchParams;
  const page = Number(one(sp, "page") || 1);
  const data = await apiSafe<Paged<Vuln>>("/api/vulnerabilities", {
    window: one(sp, "window") || "all",
    sort: one(sp, "sort") || "published",
    kev: one(sp, "kev"),
    exploit: one(sp, "exploit"),
    severity: one(sp, "severity"),
    vendor: one(sp, "vendor"),
    product: one(sp, "product"),
    q: one(sp, "q"),
    page,
    page_size: 30,
  });

  return (
    <>
      <PageHead
        title="Vulnerabilities"
        sub="Every CVE tracked locally, newest first. Use Active threats when you want them ranked by relevance."
        right={<Segmented base="/vulnerabilities" sp={sp} param="window" options={WINDOW_OPTIONS} fallback="all" />}
      />

      <div className="toolbar">
        <PillSelect base="/vulnerabilities" sp={sp} param="severity" options={SEVERITIES} label="Severity" />
        <span className="spacer" />
        <TextFilters
          base="/vulnerabilities"
          sp={sp}
          fields={[
            { name: "vendor", placeholder: "Vendor…" },
            { name: "q", placeholder: "Filter by text…" },
          ]}
          sorts={[
            { value: "published", label: "Newest first" },
            { value: "relevance", label: "Most relevant" },
            { value: "cvss", label: "Highest CVSS" },
            { value: "updated", label: "Recently updated" },
          ]}
          sortDefault="published"
        />
        <ClearFilters base="/vulnerabilities" sp={sp} ignore={["sort", "window"]} />
      </div>

      <div className="toolbar">
        <Toggles
          base="/vulnerabilities"
          sp={sp}
          options={[
            { param: "kev", label: "In CISA KEV" },
            { param: "exploit", label: "Has public exploit" },
          ]}
        />
      </div>

      {!data ? (
        <div className="notice notice-danger">API unavailable.</div>
      ) : (
        <>
          <Panel title={`${data.total.toLocaleString()} vulnerabilities`} flush>
            <ThreatTable items={data.items} />
          </Panel>
          <Pagination
            total={data.total}
            page={data.page}
            pageSize={data.page_size}
            params={sp}
            base="/vulnerabilities"
          />
        </>
      )}
    </>
  );
}
