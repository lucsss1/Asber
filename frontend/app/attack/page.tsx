import Link from "next/link";
import { apiSafe, type AttackItem } from "@/lib/api";
import { Empty, PageHead, Panel } from "@/components/ui";

export const dynamic = "force-dynamic";

interface Tactic {
  external_id: string;
  name: string;
  shortname: string;
  url: string | null;
  description: string;
  technique_count: number;
  techniques: AttackItem[];
}

export default async function AttackPage() {
  const data = await apiSafe<{ tactics: Tactic[]; mentioned_total: number }>("/api/attack/tactics");

  if (!data || !data.tactics.length) {
    return (
      <>
        <PageHead title="MITRE ATT&CK" />
        <Panel title="Enterprise matrix">
          <Empty>
            ATT&CK data has not been imported yet. The MITRE worker runs every 6 hours — you can trigger it from{" "}
            <Link href="/sources">Source Health</Link>.
          </Empty>
        </Panel>
      </>
    );
  }

  return (
    <>
      <PageHead
        title="MITRE ATT&CK — Enterprise"
        sub={`Techniques highlighted are those mentioned in reports collected here (${data.mentioned_total} mentions).`}
      />
      <div className="matrix">
        {data.tactics.map((t) => (
          <div className="matrix-col" key={t.external_id}>
            <div className="matrix-head" title={t.description}>
              {t.name} <span className="faint">({t.technique_count})</span>
            </div>
            {t.techniques.slice(0, 40).map((tech) => (
              <Link
                key={tech.stix_id}
                href={`/attack/${tech.external_id}`}
                className={`matrix-cell${tech.mentions ? " hot" : ""}`}
                title={tech.description}
              >
                {tech.name}
                {tech.mentions ? <span className="matrix-count">{tech.mentions}</span> : null}
              </Link>
            ))}
          </div>
        ))}
      </div>
    </>
  );
}
