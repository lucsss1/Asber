import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { SearchBox } from "@/components/SearchBox";
import { AccountMenu } from "@/components/AccountMenu";
import { auth } from "@/auth";
import { authDisabled } from "@/lib/authz";

const sans = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-sans",
  fallback: ["system-ui", "Segoe UI", "sans-serif"],
});

const mono = JetBrains_Mono({
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
            </main>
          </div>
        ) : (
          children
        )}
      </body>
    </html>
  );
}
