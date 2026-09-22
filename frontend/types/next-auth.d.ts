import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    user: { admin: boolean } & DefaultSession["user"];
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    admin?: boolean;
  }
}
