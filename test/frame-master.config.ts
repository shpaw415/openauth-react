import type { FrameMasterConfig } from "frame-master/server/types";
import ReactToHtml from "frame-master-plugin-react-to-html";
import ApplyReact from "frame-master-plugin-apply-react/plugin";
import TailwindPlugin from "frame-master-plugin-tailwind";
import actionPlugin from "frame-master-plugin-cloudflare-pages-functions-action";

export default {
  HTTPServer: {
    port: 3002,
  },
  plugins: [
    ReactToHtml({
      shellPath: "src/shell.tsx",
      srcDir: "src/pages",
    }),
    ApplyReact({
      clientShellPath: "src/client-wrapper.tsx",
      route: "src/pages",
      style: "nextjs",
    }),
    TailwindPlugin({
      inputFile: "static/tailwind.css",
      outputFile: "static/style.css",
      options: {
        autoInjectInBuild: true,
        runtime: "bun",
      },
    }),
    actionPlugin({
      actionBasePath: "src/api",
      outDir: ".frame-master/build",
      serverPort: 8788,
    }),
    {
      name: "static-assets",
      version: "1.0.0",
      build: {
        buildConfig: {
          naming: {
            asset: "[dir]/[name].[ext]",
          },
        },
      },
    },
  ],
} satisfies FrameMasterConfig;
