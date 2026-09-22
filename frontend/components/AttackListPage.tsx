import Link from "next/link";
import { apiSafe, type AttackItem, type Paged } from "@/lib/api";
import { ClearFilters, TextFilters, Toggles, one, type SP } from "@/components/Filters";
import { Empty, PageHead, Pagination, Panel } from "@/components/ui";

/** Shared list page for ATT&CK groups / software / campaigns. */
export async function AttackListPage({
  sp,
  base,
  title,
  sub,
  type,
}: {
  sp: SP;
  base: string;
  title: string;
  sub: string;
  type: string;
}) {
  const page = Number(one(sp, "page") || 1);
  const data = await apiSafe<Paged<AttackItem>>("/api/attack/objects", {
    type,
    q: one(sp, "q"),
    mentioned: one(sp, "mentioned"),
    sort: one(sp, "sort") || "mentions",
    page,
    page_size: 30,
  });

  return (
    <>
      <PageHead title={title} sub={sub} />

      <div className="toolbar">
        <Toggles
          base={base}
          sp={sp}
          options={[{ param: "mentioned", label: "Only those seen in collected reports" }]}
        />
        <span className="spacer" />
        <TextFilters
          base={base}
          sp={sp}
          fields={[{ name: "q", placeholder: "Name, alias or ID…" }]}
          sorts={[
            { value: "mentions", label: "Most mentioned" },
            { value: "name", label: "Name (A–Z)" },
          ]}
          sortDefault="mentions"
        />
        <ClearFilters base={base} sp={sp} ignore={["sort"]} />
      </div>

      {!data ? (
        <div className="notice notice-danger">API unavailable.</div>
      ) : (
        <>
          <Panel title={`${data.total.toLocaleString()} entries`} flush>
            {data.items.length ? (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 80 }}>ID</th>
                    <th style={{ width: 220 }}>Name</th>
                    <th style={{ width: 110 }} className="num">
                      Reports
                    </th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((a) => (
                    <tr key={a.stix_id}>
                      <td className="mono nowrap faint">{a.external_id || "—"}</td>
                      <td>
                        <Link href={`/attack/${a.external_id || a.stix_id}`} className="cve-cell">
                          <span style={{ fontWeight: 550 }}>{a.name}</span>
                          {a.aliases.length ? (
                            <span className="cve-name" style={{ maxWidth: 200 }}>
                              {a.aliases.slice(0, 3).join(", ")}
                            </span>
                          ) : null}
                        </Link>
                      </td>
                      <td className="num">
                        {a.mentions ? (
                          <span className="tag tag-accent">{a.mentions}</span>
                        ) : (
                          <span className="faint">—</span>
                        )}
                      </td>
                      <td>
                        <div className="truncate faint" style={{ maxWidth: 620 }}>
                          {a.description}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty title="Nothing matches">MITRE ATT&CK may still be importing.</Empty>
            )}
          </Panel>
          <Pagination total={data.total} page={data.page} pageSize={data.page_size} params={sp} base={base} />
        </>
      )}
    </>
  );
}
