import { onRequest as __auth__action__js_onRequest } from "/home/shpaw415/openauth-react/test/functions/auth/[action].js"
import { onRequest as __auth_index_js_onRequest } from "/home/shpaw415/openauth-react/test/functions/auth/index.js"

export const routes = [
    {
      routePath: "/auth/:action",
      mountPath: "/auth",
      method: "",
      middlewares: [],
      modules: [__auth__action__js_onRequest],
    },
  {
      routePath: "/auth",
      mountPath: "/auth",
      method: "",
      middlewares: [],
      modules: [__auth_index_js_onRequest],
    },
  ]