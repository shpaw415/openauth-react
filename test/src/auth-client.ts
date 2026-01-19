import { createClient } from "@openauthjs/openauth/client";

export const client = createClient({
  clientID: "test-id",
  issuer: "http://localhost:8787",
});
