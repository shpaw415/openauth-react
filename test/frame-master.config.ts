import type { FrameMasterConfig } from "frame-master/server/types";
import ReactToHtml from "frame-master-plugin-react-to-html";
import ApplyReact from "frame-master-plugin-apply-react/plugin";
import TailwindPlugin from "frame-master-plugin-tailwind";
import actionPlugin from "frame-master-plugin-cloudflare-pages-functions-action";

export default {
  HTTPServer: {
    port: 3001,
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
      name: "dev-proxy-to-auth",
      version: "1.0.0",
      router: {
        async request(master) {
          if (!master.URL.pathname.startsWith("/auth")) return;
          const url = new URL(master.request.url);
          url.port = "8788";

          const res = await fetch(url.toString(), master.request);

          master.setResponse(Bun.gzipSync(await res.arrayBuffer()), {
            status: res.status,
            headers: {
              ...Object.fromEntries(res.headers),
            },
          });
        },
      },
    },
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
