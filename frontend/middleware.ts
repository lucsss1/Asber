import { NextResponse } from "next/server";

import { auth } from "@/auth";

/** Paths reachable without a session: the sign-in page and the OAuth dance itself. */
const PUBLIC = ["/login", "/api/auth"];

/** Writes that only an admin may perform (they cost source rate-limit budget). */
const ADMIN_ONLY = /^\/api\/sources\/[^/]+\/run$/;

export default auth((req) => {
  const { pathname } = req.nextUrl;

  if (PUBLIC.some((p) => pathname === p || pathname.startsWith(`${p}/`))) {
    return NextResponse.next();
  }

  if (!req.auth?.user) {
    // The API is proxied to the backend, so answer it as an API would rather
    // than redirecting a fetch into an HTML sign-in page.
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ detail: "authentication required" }, { status: 401 });
    }
    const login = new URL("/login", req.nextUrl);
    login.searchParams.set("next", pathname + req.nextUrl.search);
    return NextResponse.redirect(login);
  }

  if (ADMIN_ONLY.test(pathname) && !req.auth.user.admin) {
    return NextResponse.json({ detail: "admin privileges required" }, { status: 403 });
  }

  return NextResponse.next();
});

export const config = {
  matcher: [
    // `/api` is matched on its own, with no extension exclusion. In the single
    // catch-all below, the trailing `.png|.svg|...` exclusion also applied to
    // API paths, so `/api/anything.png` skipped this middleware entirely and
    // was proxied to the backend with no session.
    "/api/:path*",
    // Pages: everything except Next's own static assets.
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|ico|webmanifest)$).*)",
  ],
};
