import { AttackListPage } from "@/components/AttackListPage";
import type { SP } from "@/components/Filters";

export const dynamic = "force-dynamic";

export default async function Page({ searchParams }: { searchParams: Promise<SP> }) {
  return (
    <AttackListPage
      sp={await searchParams}
      base="/actors"
      title="Threat Actors"
      sub="ATT&CK groups, ranked by how often they appear in the reports collected here."
      type="group"
    />
  );
}
