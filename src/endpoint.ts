import {
  type Client,
  type ExchangeError,
  type ExchangeSuccess,
  type VerifyResult,
} from "@openauthjs/openauth/client";
import { createSubjects } from "@openauthjs/openauth/subject";

export type AuthManagerProps<Schema extends ReturnType<typeof createSubjects>> =
  {
    client: Client;
    request: Request;
    issuer: string;
    /**
     * Callback handler for processing the OAuth2 callback.
     *
     * @example
     * ```ts
     * {
     *   onSuccess: (success) => {
     *     console.log("Successfully exchanged code for tokens", success);
     *   },
     *   onError: (error) => {
     *     console.error("Failed to exchange code for tokens", error);
     *   },
     *   response: {
     *     init: {
     *       status: 302,
     *       headers: {},
     *     },
     *     body: null,
     *   },
     * }
     * ```
     */
    callback: callbackHandlerProps;

    verify: {
      /**
       * Create a subject schema.
       *
       * @example
       * ```ts
       * createSubjects({
       *   user: object({
       *     userID: string()
       *   }),
       *   admin: object({
       *     workspaceID: string()
       *   })
       * })
       * ```
       *
       * This is using [valibot](https://github.com/fabian-hiller/valibot) to define the shape of the
       * subjects. You can use any validation library that's following the
       * [standard-schema specification](https://github.com/standard-schema/standard-schema).
       */
      subjects: Schema;
      /**
       * Verify the access token from the request cookies.
       *
       * return Response object calling .
       */
      onSuccess: (
        subject: VerifyResult<Schema>,
      ) => Response | Promise<Response>;
      onError?: (
        error: ExchangeError,
      ) => Response | Promise<Response | void> | void;
    };
  };

export type callbackHandlerProps = {
  onSuccess: (success: ExchangeSuccess) => void;
  onError: (error: ExchangeError) => void | Promise<void>;
  request: Request;
  response?: {
    init: ResponseInit;
    body: BodyInit | null;
  };
  client: Client;
};

export class AuthManager<Schema extends ReturnType<typeof createSubjects>> {
  client: Client;
  redirectURI: string;
  props: {
    callback: Omit<callbackHandlerProps, "request">;
    verify: AuthManagerProps<Schema>["verify"];
  };
  constructor(props: AuthManagerProps<Schema>) {
    this.client = props.client;
    this.redirectURI = props.issuer + "/callback";
    this.props = { callback: props.callback, verify: props.verify };
  }

  public run(request: Request) {
    switch (new URL(request.url).pathname) {
      case "/callback":
        return this.callback({ ...this.props.callback, request });
      case "/authorize":
        return this.authorize();
      case "/":
        return this.verify({ request, subjects: this.props.verify.subjects });
      default:
        throw new Error("Invalid path for AuthManager");
    }
  }

  private async callback(props: callbackHandlerProps) {
    const { onSuccess, onError, client } = props;
    const url = new URL(props.request.url);
    const code = url.searchParams.get("code")!;
    try {
      const exchanged = await client.exchange(code, this.redirectURI);
      if (exchanged.err) {
        throw new Error("Code exchange failed", { cause: exchanged });
      }
      const response = new Response(props.response?.body ?? null, {
        status: 302,
        headers: {},
        ...(props.response?.init || {}),
      });
      response.headers.set("Location", url.origin);
      setSession(response, exchanged.tokens.access, exchanged.tokens.refresh);
      onSuccess(exchanged);
      return response;
    } catch (e) {
      await onError((e as Error).cause as ExchangeError);
      throw e;
    }
  }
  private async authorize() {
    return Response.redirect(
      await this.client.authorize(this.redirectURI, "code").then((v) => v.url),
      302,
    );
  }

  private async verify({
    request,
    subjects,
  }: {
    request: Request;
    subjects: Schema;
  }) {
    const cookies = new URLSearchParams(
      request.headers.get("cookie")?.replaceAll("; ", "&"),
    );
    const verified = await this.client.verify<Schema>(
      subjects,
      cookies.get("access_token")!,
      {
        refresh: cookies.get("refresh_token") || undefined,
      },
    );
    if (verified.err) {
      const res = await this.props.verify.onError?.(verified);
      return (
        res ||
        Response.redirect(new URL(request.url).origin + "/authorize", 302)
      );
    }
    const resp = await this.props.verify.onSuccess(verified);
    if (verified.tokens)
      setSession(resp, verified.tokens.access, verified.tokens.refresh);
    return resp;
  }
}

function setSession(response: Response, access: string, refresh: string) {
  if (access) {
    response.headers.append(
      "Set-Cookie",
      `access_token=${access}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2147483647`,
    );
  }
  if (refresh) {
    response.headers.append(
      "Set-Cookie",
      `refresh_token=${refresh}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2147483647`,
    );
  }
}
