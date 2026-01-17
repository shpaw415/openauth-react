# openauth-react

React bindings for [OpenAuth](https://github.com/openauthjs/openauth) - a simple, secure authentication library.

## Installation

```bash
npm install openauth-react @openauthjs/openauth
# or
bun add openauth-react @openauthjs/openauth
```

## Features

- 🔐 **Client-side authentication** with React Context API
- 🍪 **Server-side session management** with HttpOnly cookies
- 🔄 **Automatic token refresh** handling
- 📦 **PKCE support** for secure OAuth2 flows
- 🎯 **Type-safe** with full TypeScript support

## Client Usage

### Setup the AuthProvider

Wrap your application with the `AuthProvider` component:

```tsx
import { AuthProvider } from "openauth-react/client";

function App() {
  return (
    <AuthProvider
      clientID="your-client-id"
      issuer="https://your-auth-server.com"
    >
      <YourApp />
    </AuthProvider>
  );
}
```

### Use the useAuth hook

Access authentication state and methods anywhere in your app:

```tsx
import { useAuth } from "openauth-react/client";

function Profile() {
  const { loaded, loggedIn, userId, login, logout, getToken } = useAuth();

  if (!loaded) {
    return <div>Loading...</div>;
  }

  if (!loggedIn) {
    return <button onClick={login}>Login</button>;
  }

  return (
    <div>
      <p>Welcome, {userId}!</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### Auth Context API

| Property   | Type                                 | Description                                     |
| ---------- | ------------------------------------ | ----------------------------------------------- |
| `loaded`   | `boolean`                            | Whether the auth state has been initialized     |
| `loggedIn` | `boolean`                            | Whether the user is currently authenticated     |
| `userId`   | `string \| undefined`                | The authenticated user's ID                     |
| `login`    | `() => Promise<void>`                | Initiates the OAuth login flow                  |
| `logout`   | `() => void`                         | Logs out the user and clears tokens             |
| `getToken` | `() => Promise<string \| undefined>` | Gets a valid access token (refreshes if needed) |

## Server Usage

The `AuthManager` class provides server-side authentication handling for API routes.

### Setup AuthManager

```ts
import { AuthManager } from "openauth-react/server/endpoint";
import { createClient } from "@openauthjs/openauth/client";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const client = createClient({
  clientID: "your-client-id",
  issuer: "https://your-auth-server.com",
});

const subjects = createSubjects({
  user: object({
    userID: string(),
  }),
});

const authManager = new AuthManager({
  client,
  issuer: "https://your-api.com",
  callback: {
    onSuccess: (tokens) => {
      console.log("Login successful");
    },
    onError: (error) => {
      console.error("Login failed", error);
    },
  },
  verify: {
    subjects,
    onSuccess: (subject) => {
      return new Response(subject.subject.properties.userID);
    },
    onError: (error) => {
      return new Response("Unauthorized", { status: 401 });
    },
  },
});
```

### Handle requests

The `AuthManager` automatically routes requests based on the pathname:

```ts
// In your server handler (e.g., Bun, Node, Cloudflare Workers)
export default {
  fetch(request: Request) {
    return authManager.run(request);
  },
};
```

### Endpoints

| Path         | Description                                         |
| ------------ | --------------------------------------------------- |
| `/authorize` | Initiates the OAuth authorization flow              |
| `/callback`  | Handles the OAuth callback and sets session cookies |
| `/`          | Verifies the session and returns the subject        |

## Session Management

The server-side `AuthManager` automatically manages sessions using HttpOnly cookies:

- `access_token` - The OAuth access token
- `refresh_token` - The OAuth refresh token

Both cookies are set with `HttpOnly`, `SameSite=Strict`, and `Path=/` for security.

## Requirements

- React 19+
- TypeScript 5+
- @openauthjs/openauth

## License

MIT
