"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

type Item = { href: string; label: string; soon?: boolean };

const MAIN: { title: string; items: Item[] }[] = [
  {
    title: "Monitor",
    items: [
      { href: "/", label: "Overview" },
      { href: "/threats", label: "Active threats" },
    ],
  },
  {
    title: "Investigate",
    items: [
      { href: "/vulnerabilities", label: "Vulnerabilities" },
      { href: "/exploits", label: "Exploits & PoCs" },
      { href: "/actors", label: "Threat actors" },
      { href: "/malware", label: "Malware" },
      { href: "/campaigns", label: "Campaigns" },
      { href: "/attack", label: "MITRE ATT&CK" },
    ],
  },
  {
    title: "Read",
    items: [
      { href: "/research", label: "Research" },
      { href: "/news", label: "News" },
    ],
  },
  {
    title: "System",
    items: [
      { href: "/sources", label: "Source health" },
      { href: "/settings", label: "Settings" },
      { href: "/data-sources", label: "Data sources" },
    ],
  },
];

// Registered but not collecting yet — kept visible, but visually de-emphasised
// so they don't compete with the features that work.
const UPCOMING: Item[] = [
  { href: "/briefing", label: "Daily briefing", soon: true },
  { href: "/detection", label: "Detection rules", soon: true },
  { href: "/iocs", label: "IOCs", soon: true },
  { href: "/watchlist", label: "Watchlist", soon: true },
];

export function Sidebar() {
  const pathname = usePathname();
  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  const link = (item: Item) => (
    <Link
      key={item.href}
      href={item.href}
      className={`nav-link${isActive(item.href) ? " active" : ""}${item.soon ? " muted" : ""}`}
    >
      <span className="nav-label">{item.label}</span>
      {item.soon ? <span className="nav-soon">soon</span> : null}
    </Link>
  );

  return (
    <nav className="sidebar">
      <div className="brand">
        <div className="brand-title">Asber</div>
        <div className="brand-sub">Cyber threat watch</div>
      </div>

      {MAIN.map((group) => (
        <div key={group.title}>
          <div className="nav-group">{group.title}</div>
          {group.items.map(link)}
        </div>
      ))}

      <div className="nav-upcoming">
        <div className="nav-group">Coming soon</div>
        {UPCOMING.map(link)}
      </div>
    </nav>
  );
}
