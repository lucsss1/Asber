import { AttackListPage } from "@/components/AttackListPage";
import type { SP } from "@/components/Filters";

export const dynamic = "force-dynamic";

export default async function Page({ searchParams }: { searchParams: Promise<SP> }) {
  return (
    <AttackListPage
      sp={await searchParams}
      base="/campaigns"
      title="Campaigns"
      sub="ATT&CK campaigns and the reports that mention them."
      type="campaign"
    />
  );
}
