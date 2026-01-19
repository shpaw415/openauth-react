import type { FrameMasterConfig } from "frame-master/server/types";
import ReactToHtml from "frame-master-plugin-react-to-html";
import ApplyReact from "frame-master-plugin-apply-react/plugin";
import TailwindPlugin from "frame-master-plugin-tailwind";
import actionPlugin from "frame-master-plugin-cloudflare-pages-functions-action";

const doProxyFetch = async (req: Bun.BunRequest<string>) => {
  const url = new URL(req.url);
  url.hostname = "localhost";
  url.port = "8788";
  const res = await fetch(url.toString(), {
    method: req.method,
    headers: req.headers,
    body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
  });

  const text = await res.clone().text();

  console.log(
    `[Proxy] ${req.method} ${url.pathname} -> ${res.status}\n${text}`,
  );

  return res;
};

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
      serverConfig: {
        routes: {
          "/auth/*": doProxyFetch,
          "/auth": doProxyFetch,
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
