import { useRef, useState, useEffect, useContext, createContext } from "react";
import { createClient } from "@openauthjs/openauth/client";
import type { AuthContextType, AuthProviderProps } from "./types";

const AuthContext = createContext(null as unknown as AuthContextType);

export function AuthProvider({
  children,
  clientID,
  issuer,
}: AuthProviderProps) {
  const initializing = useRef(true);
  const [loaded, setLoaded] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);
  const token = useRef<string | undefined>(undefined);
  const [userId, setUserId] = useState<string | undefined>();
  const _client_ = useRef(
    createClient({
      clientID,
      issuer,
    }),
  );
  const client = _client_.current;

  useEffect(() => {
    const hash = new URLSearchParams(location.search.slice(1));
    const code = hash.get("code");
    const state = hash.get("state");

    if (!initializing.current) {
      return;
    }

    initializing.current = false;

    if (code && state) {
      callback(code, state);
      return;
    }

    auth();
  }, []);

  async function refreshTokens() {
    const refresh = localStorage.getItem("refresh");
    if (!refresh) return;
    const next = await client.refresh(refresh, {
      access: token.current,
    });
    if (next.err) return;
    if (!next.tokens) return token.current;

    localStorage.setItem("refresh", next.tokens.refresh);
    token.current = next.tokens.access;

    return next.tokens.access;
  }

  async function auth() {
    const token = await refreshTokens();

    if (token) {
      await user();
    }

    setLoaded(true);
  }

  async function getToken() {
    const token = await refreshTokens();

    if (!token) {
      await login();
      return;
    }

    return token;
  }

  async function login() {
    const { challenge, url } = await client.authorize(location.origin, "code", {
      pkce: true,
    });
    sessionStorage.setItem("challenge", JSON.stringify(challenge));
    location.href = url;
  }

  async function callback(code: string, state: string) {
    const challenge = JSON.parse(sessionStorage.getItem("challenge")!);
    if (code) {
      if (state === challenge.state && challenge.verifier) {
        const exchanged = await client.exchange(
          code!,
          location.origin,
          challenge.verifier,
        );
        if (!exchanged.err) {
          token.current = exchanged.tokens?.access;
          localStorage.setItem("refresh", exchanged.tokens.refresh);
        }
      }
      window.location.replace("/");
    }
  }

  async function user() {
    const res = await fetch("http://localhost:3001/auth", {
      headers: {
        Authorization: `Bearer ${token.current}`,
      },
    });

    if (res.ok) {
      setUserId(await res.text());
      setLoggedIn(true);
    }
  }

  function logout() {
    localStorage.removeItem("refresh");
    token.current = undefined;
    setLoggedIn(false);
  }

  return (
    <AuthContext.Provider
      value={{
        login,
        logout,
        userId,
        loaded,
        loggedIn,
        getToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType | null {
  const context = useContext(AuthContext);
  if (typeof window !== "undefined" && !context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
