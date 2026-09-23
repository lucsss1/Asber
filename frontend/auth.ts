import NextAuth from "next-auth";
import GitHub from "next-auth/providers/github";
import Google from "next-auth/providers/google";

import { isAdmin, isAllowed } from "@/lib/authz";

/** Only the providers that were actually configured are offered. */
const providers = [
  process.env.AUTH_GITHUB_ID ? GitHub : null,
  process.env.AUTH_GOOGLE_ID ? Google : null,
].filter(Boolean) as never[];

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers,
  trustHost: true,
  session: { strategy: "jwt", maxAge: 60 * 60 * 24 * 7 },
  pages: { signIn: "/login", error: "/login" },
  callbacks: {
    /** The allowlist check. A verified OAuth identity is not an authorisation. */
    signIn({ profile }) {
      return isAllowed(profile?.email as string | undefined);
    },
    jwt({ token }) {
      token.admin = isAdmin(token.email);
      return token;
    },
    session({ session, token }) {
      session.user.admin = Boolean(token.admin);
      return session;
    },
  },
});
