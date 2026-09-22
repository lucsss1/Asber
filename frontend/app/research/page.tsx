import { DocFeedPage } from "@/components/DocFeedPage";
import type { SP } from "@/components/Filters";

export const dynamic = "force-dynamic";

export default async function ResearchPage({ searchParams }: { searchParams: Promise<SP> }) {
  return (
    <DocFeedPage
      sp={await searchParams}
      base="/research"
      title="Security Research"
      sub="Threat research and vendor advisories. Tier 1–2 sources; extracted entities are shown with each report."
      docTypes={["research", "advisory", "repository"]}
      sources={[
        { value: "unit42", label: "Unit 42" },
        { value: "talos", label: "Cisco Talos" },
        { value: "mandiant", label: "Mandiant" },
        { value: "sentinellabs", label: "SentinelLabs" },
        { value: "project_zero", label: "Project Zero" },
        { value: "msrc", label: "MSRC" },
      ]}
    />
  );
}
