"no action";

import { AuthManager } from "openauth-react/server/endpoint";

export const onRequest: PagesFunction = (ctx) =>
  new AuthManager({
    issuer: "http://localhost:8787",
    callback: {
      onError(error) {},
      onSuccess() {},
    },
  }).run(ctx.request);
