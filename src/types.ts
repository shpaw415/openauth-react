export type AuthContextType = {
  userId?: string;
  loaded: boolean;
  loggedIn: boolean;
  logout: () => void;
  login: () => Promise<void>;
  getToken: () => Promise<string | undefined>;
};

export type AuthProviderProps = {
  children: React.ReactNode;
  clientID: string;
  issuer: string;
  /**
   * The public path where the auth endpoints are hosted.
   *
   * External example: `http://my.api.com/api/auth`
   *
   * @default "/auth"
   */
  publicPath?: string;
  /**
   *  Indicates whether the callback is being handled on the front-end or back-end.
   *
   * - `true` front-end callback
   * - `false` back-end callback
   * @default false
   */
  isFrontendCallback?: boolean;
};

/**
 * Session data stored in the OAuth session.
 * can be extended by the user. to reflect the specific data they want to store.
 */
export interface SessionData {}
