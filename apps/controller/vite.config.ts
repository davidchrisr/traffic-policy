import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";
import adapter from "@sveltejs/adapter-node";
import tailwindcss from "@tailwindcss/vite";
import { requireBuildOrigin } from "./build-origin.ts";

export default defineConfig(() => {
  const origin =
    process.env.TP_PUBLIC_ORIGIN === undefined
      ? undefined
      : requireBuildOrigin(process.env.TP_PUBLIC_ORIGIN);

  return {
    plugins: [
      {
        name: "require-controller-build-origin",
        apply: "build",
        buildStart() {
          requireBuildOrigin(origin);
        },
      },
      tailwindcss(),
      sveltekit({
        adapter: adapter({ out: "build" }),
        paths: { origin },
      }),
    ],
    server: { host: "0.0.0.0", port: 4173, strictPort: true },
    ssr: {
      noExternal: [
        "@traffic-policy/contracts",
        "@traffic-policy/core",
        "clsx",
        "bits-ui",
        "@internationalized/date",
        "tailwind-variants",
        "tailwind-merge",
        "@lucide/svelte",
        "echarts",
      ],
    },
  };
});
