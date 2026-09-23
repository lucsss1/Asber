/** @type {import('next').NextConfig} */
const raw = (process.env.API_INTERNAL_URL || "http://backend:8000").trim().replace(/\/$/, "");
// A platform may hand us "host:port" without a scheme (e.g. Render's hostport).
const API = /^https?:\/\//.test(raw) ? raw : `http://${raw}`;

const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  async rewrites() {
    // Only the export/download endpoints are reached from the browser;
    // every page fetches server-side. The API key never reaches the client.
    //
    // `/api/auth/*` must be excluded: those are NextAuth's own routes. A
    // rewrite returned as a plain array is applied *before* dynamic routes,
    // so a blanket `/api/:path*` shadows `app/api/auth/[...nextauth]` and
    // sign-in breaks with a 404 from the backend.
    return [
      {
        source: "/api/:path((?!auth(?:/|$)).*)",
        destination: `${API}/api/:path`,
      },
    ];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Frame-Options", value: "DENY" },
          {
            key: "Content-Security-Policy",
            // No inline scripts are used by this app; external content is text-only.
            value: [
              "default-src 'self'",
              "img-src 'self' data:",
              "style-src 'self' 'unsafe-inline'",
              "script-src 'self' 'unsafe-inline'",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join("; "),
          },
        ],
      },
    ];
  },
};

export default nextConfig;
