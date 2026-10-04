import type { NextConfig } from "next";

// The browser only ever talks to the dashboard: requests to /api/* are
// forwarded to the API from the server side. So one address serves both,
// from any device that can reach the dashboard, and the API's own port never
// has to be exposed. Read at build time (Docker passes the API's internal
// address; `npm run dev` uses the API on this machine).
const apiUrl = process.env.API_INTERNAL_URL || "http://localhost:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiUrl}/:path*` }];
  },
};

export default nextConfig;
