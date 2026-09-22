import { Planned } from "@/components/Planned";

export default function WatchlistPage() {
  return (
    <Planned
      title="Personal Watchlist"
      phase={3}
      sub="Products, technologies, threat actors, malware and CVEs you want to be alerted about."
      willInclude={[
        "Watchlist entries stored locally (products, technologies, actors, malware, CVE ids)",
        "WATCHLIST ALERT badge on anything newly ingested that matches",
        "A notification centre in the dashboard, with optional browser notifications",
        "Pluggable delivery (Telegram / Discord / Slack / email) behind one notifier interface",
      ]}
      available={[
        { href: "/threats?platform=active_directory", label: "Filter: Active Directory" },
        { href: "/threats?platform=identity", label: "Filter: Identity" },
        { href: "/threats?vendor=microsoft", label: "Filter: Microsoft" },
      ]}
    />
  );
}
