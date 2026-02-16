import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  // Standalone output for npm package distribution
  // Creates a self-contained build without needing node_modules
  output: "standalone",

  // Set tracing root to the ShieldCortex package root so standalone paths
  // are relative to it (dashboard/server.js) instead of preserving the
  // full absolute filesystem path from the build machine.
  // build:dashboard runs from the dashboard/ directory, so cwd/.. = package root
  outputFileTracingRoot: path.join(process.cwd(), ".."),
};

export default nextConfig;
