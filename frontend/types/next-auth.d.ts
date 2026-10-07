import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    // `rampart` is separate from `admin`: see lib/authz.isRampartOwner.
    user: { admin: boolean; rampart: boolean } & DefaultSession["user"];
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    admin?: boolean;
    rampart?: boolean;
  }
}
