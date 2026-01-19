import {
  AuthManager,
  client,
  subjects
} from "../chunk-fxemzh4g.js";

// src/api/auth/[action].ts
"no action";
var onRequest = (ctx) => new AuthManager({
  issuer: "http://localhost:8787",
  client,
  publicPath: "/auth",
  callback: {
    onError(error) {
      console.log("Callback error:");
      console.log(error.err);
      console.log("-".repeat(20));
    },
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
