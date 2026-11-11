/** @type {import('next').NextConfig} */
const apiInternalUrl = (process.env.API_INTERNAL_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${apiInternalUrl}/api/:path*`,
      },
      {
        source: "/healthz",
        destination: `${apiInternalUrl}/healthz`,
      },
      {
        source: "/readyz",
        destination: `${apiInternalUrl}/readyz`,
      },
    ];
  },
};

export default nextConfig;
