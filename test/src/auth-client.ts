import { createClient } from "@openauthjs/openauth/client";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

export const client = createClient({
  clientID: "test-id",
  issuer: "http://localhost:8787",
});

export const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});
