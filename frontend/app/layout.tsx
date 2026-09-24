import type { Metadata } from "next";
import { Archivo, IBM_Plex_Mono, Source_Serif_4 } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { SearchBox } from "@/components/SearchBox";
import { AccountMenu } from "@/components/AccountMenu";
import { auth } from "@/auth";
import { authDisabled } from "@/lib/authz";

// Three voices: the serif speaks (titles, numerals), the sans works (UI and
// tables), the mono records (identifiers, dates, labels).
const display = Source_Serif_4({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-display",
  weight: ["400", "500", "600"],
  fallback: ["Georgia", "serif"],
});

const sans = Archivo({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-sans",
  fallback: ["Helvetica Neue", "Arial", "sans-serif"],
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-mono",
  weight: ["400", "500"],
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
    <html lang="en" className={`${display.variable} ${sans.variable} ${mono.variable}`}>
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
            </main>
          </div>
        ) : (
          children
        )}
      </body>
    </html>
  );
}
