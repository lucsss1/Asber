import { Planned } from "@/components/Planned";

export default function DetectionPage() {
  return (
    <Planned
      title="Detection Intelligence"
      phase={2}
      sub="Sigma and YARA rules, mapped to MITRE ATT&CK techniques and correlated with CVEs."
      willInclude={[
        "SigmaHQ rules from the official release archive, parsed as YAML (never executed)",
        "Rule → ATT&CK technique mapping via the rule's attack.* tags",
        "YARA rule repositories tracked through GITHUB_WATCH_REPOS",
        "Detection coverage shown on each CVE page next to the ATT&CK detection strategies",
      ]}
      available={[
        { href: "/attack", label: "ATT&CK detection strategies & analytics" },
        { href: "/exploits?kind=detection", label: "Community detection repositories" },
      ]}
    />
  );
}
