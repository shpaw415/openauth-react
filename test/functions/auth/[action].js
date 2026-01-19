import {
  AuthManager,
  client,
  subjects
} from "../chunk-xvyxt2bp.js";

// src/api/auth/[action].ts
"no action";
var onRequest = (ctx) => new AuthManager({
  issuer: "http://localhost:8787",
  client,
  publicPath: "/auth",
  callback: {
    onError(error) {},
    onSuccess(success) {}
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
    }
  }
}).run(ctx.request);
export {
  onRequest
};
