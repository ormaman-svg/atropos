import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const root = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: { "@": resolve(root, "src") },
  },
  test: {
    environment: "node",
    // The isolation tests share fixture rows; running files in parallel against
    // one cluster makes failures hard to read.
    fileParallelism: false,
  },
});
