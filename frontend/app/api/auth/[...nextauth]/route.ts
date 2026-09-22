// A real route file, so it wins over the `/api/:path*` rewrite in
// next.config.mjs (rewrites declared that way run *after* the filesystem).
import { handlers } from "@/auth";

export const { GET, POST } = handlers;
