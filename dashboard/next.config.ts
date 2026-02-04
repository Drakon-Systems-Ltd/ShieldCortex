import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output for npm package distribution
  // Creates a self-contained build without needing node_modules
  output: "standalone",
};

export default nextConfig;
