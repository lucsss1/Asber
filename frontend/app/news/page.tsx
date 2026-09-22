import { DocFeedPage } from "@/components/DocFeedPage";
import type { SP } from "@/components/Filters";

export const dynamic = "force-dynamic";

export default async function NewsPage({ searchParams }: { searchParams: Promise<SP> }) {
  return (
    <DocFeedPage
      sp={await searchParams}
      base="/news"
      title="Security News"
      sub="Context layer (Tier 3). Facts should be confirmed against the Tier 1–2 source linked on each CVE page."
      docTypes={["news"]}
      sources={[
        { value: "bleepingcomputer", label: "BleepingComputer" },
        { value: "krebs", label: "Krebs on Security" },
        { value: "therecord", label: "The Record" },
      ]}
    />
  );
}
