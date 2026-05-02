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

  // Exclude Sharp's per-platform native binaries from the standalone bundle.
  // The dashboard does not call Sharp directly; Next.js only needs it at
  // build-time for image optimization. Without this, the published npm
  // tarball ships ~16 MB of Mac-only libvips per release.
  outputFileTracingExcludes: {
    "*": [
      "**/node_modules/sharp/**",
      "**/node_modules/@img/**",
    ],
  },
};

export default nextConfig;
