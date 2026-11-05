import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

// Development catalog for frontend work. The controller's production build
// uses ../vite.config.ts and never includes this entry.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  publicDir: fileURLToPath(new URL("../static", import.meta.url)),
  plugins: [tailwindcss(), svelte()],
  server: { host: "0.0.0.0", port: 4174, strictPort: true },
});
