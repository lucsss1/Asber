import { apiSafe, type Doc, type Paged } from "@/lib/api";
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
import { DocList, PageHead, Pagination, Panel } from "@/components/ui";

/** Shared page body for the Research and News feeds. */
export async function DocFeedPage({
  sp,
  base,
  title,
  sub,
  docTypes,
  sources,
}: {
  sp: SP;
  base: string;
  title: string;
  sub: string;
  docTypes: string[];
  sources: { value: string; label: string }[];
}) {
  const page = Number(one(sp, "page") || 1);
  const data = await apiSafe<Paged<Doc>>("/api/documents", {
    doc_type: docTypes,
    window: one(sp, "window") || "30d",
    source: one(sp, "source"),
    exploitation: one(sp, "exploitation"),
    cve: one(sp, "cve"),
    actor: one(sp, "actor"),
    q: one(sp, "q"),
    page,
    page_size: 20,
  });

  return (
    <>
      <PageHead
        title={title}
        sub={sub}
        right={<Segmented base={base} sp={sp} param="window" options={WINDOW_OPTIONS} fallback="30d" />}
      />

      <div className="toolbar">
        <Toggles base={base} sp={sp} options={[{ param: "exploitation", label: "Reports exploitation" }]} />
        <span className="spacer" />
        <TextFilters
          base={base}
          sp={sp}
          fields={[
            { name: "q", placeholder: "Filter by text…" },
            { name: "cve", placeholder: "CVE…" },
          ]}
        />
        <ClearFilters base={base} sp={sp} ignore={["window"]} />
      </div>

      <div className="toolbar">
        <PillSelect base={base} sp={sp} param="source" options={sources} label="Source" />
      </div>

      {!data ? (
        <div className="notice notice-danger">API unavailable.</div>
      ) : (
        <>
          <Panel title={`${data.total.toLocaleString()} article${data.total === 1 ? "" : "s"}`}>
            <DocList docs={data.items} />
          </Panel>
          <Pagination total={data.total} page={data.page} pageSize={data.page_size} params={sp} base={base} />
        </>
      )}
    </>
  );
}
