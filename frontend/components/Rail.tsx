"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Pending } from "@/components/Pending";

type Item = { href: string; label: string };

/**
 * The navigation, as a rail across the top.
 *
 * It replaced a 216px sidebar. Three reasons: the sidebar is the single most
 * recognisable shape in software and made Asber look like everything else;
 * horizontal room is the scarce resource in a console built on wide tables;
 * and four of its thirteen slots were spent on features that do not exist yet.
 *
 * Everything not on the rail is still one keystroke away in the palette, and
 * the More button says so out loud for anyone who does not know that.
 */
const RAIL: Item[] = [
  { href: "/", label: "Overview" },
  { href: "/threats", label: "Threats" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/exploits", label: "Exploits" },
  { href: "/actors", label: "Actors" },
  { href: "/malware", label: "Malware" },
  { href: "/attack", label: "ATT&CK" },
  { href: "/research", label: "Research" },
  { href: "/news", label: "News" },
];

export function Rail({ children }: { children?: React.ReactNode }) {
  const pathname = usePathname();
  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  return (
    <header className="rail">
      <Link href="/" className="rail-brand" aria-label="Asber, home">
        <span className="rail-mark" aria-hidden="true">
          <i /><i /><i /><i />
        </span>
        Asber
      </Link>

      <nav className="rail-nav" aria-label="Sections">
        {RAIL.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`rail-link${isActive(item.href) ? " active" : ""}`}
            aria-current={isActive(item.href) ? "page" : undefined}
          >
            {item.label}
            <Pending />
          </Link>
        ))}
      </nav>

      <button
        type="button"
        className="rail-more"
        onClick={() => document.dispatchEvent(new CustomEvent("asber:palette"))}
      >
        More
      </button>

      <div className="rail-end">{children}</div>
    </header>
  );
}
