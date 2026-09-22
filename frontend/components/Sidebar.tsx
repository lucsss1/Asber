"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  IconBug,
  IconCode,
  IconDoc,
  IconFingerprint,
  IconFlame,
  IconGauge,
  IconGrid,
  IconNews,
  IconPulse,
  IconSettings,
  IconShield,
  IconTarget,
  IconUsers,
  IconVirus,
} from "@/components/icons";

type Item = { href: string; label: string; icon: React.ReactNode; soon?: boolean };

const MAIN: { title: string; items: Item[] }[] = [
  {
    title: "Monitor",
    items: [
      { href: "/", label: "Overview", icon: <IconGauge /> },
      { href: "/threats", label: "Active threats", icon: <IconFlame /> },
    ],
  },
  {
    title: "Investigate",
    items: [
      { href: "/vulnerabilities", label: "Vulnerabilities", icon: <IconBug /> },
      { href: "/exploits", label: "Exploits & PoCs", icon: <IconCode /> },
      { href: "/actors", label: "Threat actors", icon: <IconUsers /> },
      { href: "/malware", label: "Malware", icon: <IconVirus /> },
      { href: "/campaigns", label: "Campaigns", icon: <IconTarget /> },
      { href: "/attack", label: "MITRE ATT&CK", icon: <IconGrid /> },
    ],
  },
  {
    title: "Read",
    items: [
      { href: "/research", label: "Research", icon: <IconDoc /> },
      { href: "/news", label: "News", icon: <IconNews /> },
    ],
  },
  {
    title: "System",
    items: [
      { href: "/sources", label: "Source health", icon: <IconPulse /> },
      { href: "/settings", label: "Settings", icon: <IconSettings /> },
    ],
  },
];

// Registered but not collecting yet — kept visible, but visually de-emphasised
// so they don't compete with the features that work.
const UPCOMING: Item[] = [
  { href: "/briefing", label: "Daily briefing", icon: <IconDoc />, soon: true },
  { href: "/detection", label: "Detection rules", icon: <IconShield />, soon: true },
  { href: "/iocs", label: "IOCs", icon: <IconFingerprint />, soon: true },
  { href: "/watchlist", label: "Watchlist", icon: <IconTarget />, soon: true },
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
      <span className="nav-icon">{item.icon}</span>
      <span>{item.label}</span>
      {item.soon ? <span className="nav-soon">soon</span> : null}
    </Link>
  );

  return (
    <nav className="sidebar">
      <div className="brand">
        <div className="brand-mark">A</div>
        <div>
          <div className="brand-title">Asber</div>
          <div className="brand-sub">Cyber threat watch</div>
        </div>
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
