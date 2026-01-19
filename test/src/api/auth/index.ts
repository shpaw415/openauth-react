"no action";

import { AuthManager } from "openauth-react/server/endpoint";
import { client, subjects } from "../../auth-client";

export const onRequest: PagesFunction = (ctx) =>
  new AuthManager({
    issuer: "http://localhost:8787",
    client,
    publicPath: "/auth",
    callback: {
      onError(error) {},
      onSuccess(success) {},
    },
    verify: {
      subjects,
      onSuccess(user) {
        console.log("Verified user:", user);
        return Response.json(user.subject.properties);
      },
      onError(err) {
        console.log(err);
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      },
    },
  }).run(ctx.request);
