import { Planned } from "@/components/Planned";

export default function IocsPage() {
  return (
    <Planned
      title="IOCs"
      phase={2}
      sub="Hashes, domains, IPs and URLs from abuse.ch and (optionally) OTX and VirusTotal."
      willInclude={[
        "MalwareBazaar sample metadata from the public CSV export (never the samples themselves)",
        "URLhaus malicious URLs from the public CSV dump",
        "AlienVault OTX pulses when OTX_API_KEY is configured",
        "On-demand VirusTotal lookups for a hash, domain, IP or URL when VIRUSTOTAL_API_KEY is configured",
        "IOC → malware family → ATT&CK software correlation",
      ]}
      available={[{ href: "/malware", label: "ATT&CK malware & tools" }]}
    />
  );
}
