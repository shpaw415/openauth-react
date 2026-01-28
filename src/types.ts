import type { Client } from "@openauthjs/openauth/client";

export type AuthContextType = {
  userData?: SessionData;
  loaded: boolean;
  loggedIn: boolean;
  logout: () => void;
  login: () => Promise<void>;
  getToken: () => Promise<string | undefined>;
};

export type AuthProviderProps = {
  children: React.ReactNode;
  /**
   * The callback redirect URI where it should trigger the token exchange.
   *
   * **Must match the redirectURI for the Auth flow.**
   *
   * External example: `http://my.api.com/api/auth`
   *
   * Internal example: `/auth`
   */
  callbackRedirectURI: string;
  /**
   *  Indicates whether the callback is being handled on the front-end or back-end.
   *
   * - `true` front-end callback
   * - `false` back-end callback
   * @default false
   */
  isFrontendCallback?: boolean;
  /**
   * UserInfo endpoint to fetch user information.
   */
  userInfoEndpoint: string;
  /**
   * UserInfo parser function to transform the fetched user information.
   *
   * If not provided, the default session data structure will be used. `res.json()`
   */
  userInfoParser?: (data: Response) => SessionData;
  /**
   * OpenAuth Client instance.
   */
  client: Client;
};

/**
 * Session data stored in the OAuth session.
 * can be extended by the user. to reflect the specific data they want to store.
 */
export interface SessionData {}
