import { Planned } from "@/components/Planned";

export default function BriefingPage() {
  return (
    <Planned
      title="Daily Cyber Briefing"
      phase={3}
      sub="A generated morning read: what is critical, what is exploited, what is new."
      willInclude={[
        "Critical / Exploited / New research / Offensive security / Threat intel / Detection / Trends sections",
        "Each item with title, why it matters, technical detail, ATT&CK mapping, sources and first-seen date",
        "Trend detection: topics rising in frequency compared to the previous period",
        "Optional AI summaries, where every sentence links back to the source it came from",
      ]}
      available={[
        { href: "/", label: "Threat overview (24h)" },
        { href: "/threats?window=24h&exploited=true", label: "Exploited in the last 24h" },
        { href: "/research?window=24h", label: "Research from the last 24h" },
      ]}
    />
  );
}
