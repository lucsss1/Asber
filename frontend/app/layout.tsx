import type { Metadata } from "next";
import { IBM_Plex_Mono, Inter } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { SearchBox } from "@/components/SearchBox";
import { AccountMenu } from "@/components/AccountMenu";
import { PopoverAnchor } from "@/components/PopoverAnchor";
import { Palette } from "@/components/Palette";
import { auth } from "@/auth";
import { authDisabled } from "@/lib/authz";

// Two voices, not three. The sans works (everything you read and operate);
// the mono records (identifiers, dates, CVSS vectors, scores). The serif is
// gone: it spoke in an editorial register, and Asber is scanned, not read.
//
// Mono is now reserved for data. It used to also set every label and column
// heading, which made the chrome as loud as the numbers.
const sans = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-sans",
  fallback: ["system-ui", "Segoe UI", "Helvetica Neue", "Arial", "sans-serif"],
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-mono",
  weight: ["400", "500", "600"],
  fallback: ["ui-monospace", "Consolas", "monospace"],
});

export const metadata: Metadata = {
  title: { default: "Asber", template: "%s · Asber" },
  description: "Asber — watch, correlate and prioritise cyber threats from public sources",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();

  // The shell (sidebar + top bar) is shown to anyone who can actually use the
  // dashboard. Keying it on the session alone stripped the whole shell from the
  // local stack, where authentication is disabled and a session never exists.
  // Signed out *and* auth enabled means the only reachable page is /login,
  // which is deliberately rendered bare.
  const showShell = Boolean(session?.user) || authDisabled();

  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        {showShell ? (
          <div className="app">
            <Sidebar />
            <main className="main">
              <div className="topbar-row">
                <SearchBox />
                {session?.user ? <AccountMenu user={session.user} /> : null}
              </div>
              {children}
              <PopoverAnchor />
              <Palette />
            </main>
          </div>
        ) : (
          children
        )}
      </body>
    </html>
  );
}
