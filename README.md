# openauth-react

React provider for client-side session management with [OpenAuthJS](https://github.com/openauthjs/openauth). Compatible with [openauth-endpoints](https://github.com/shpaw415/openauth-endpoints) for full-stack authentication flows.

## Installation

```bash
bun add openauth-react
```

```bash
npm install openauth-react
```

## Features

- 🔐 **React Context Provider** - Easy-to-use authentication state management
- 🔄 **Automatic Token Refresh** - Seamlessly refreshes tokens when they expire
- 🎯 **Flexible Callback Handling** - Support for both frontend and backend callback flows
- 🍪 **Cookie Sync** - Automatically syncs tokens to cookies for SSR compatibility
- 📦 **TypeScript First** - Full type safety with extensible session data

## Usage

### Basic Setup

Wrap your application with the `AuthProvider`:

```tsx
import { AuthProvider } from "openauth-react/client";

function App() {
  return (
    <AuthProvider
      clientID="your-client-id"
      issuer="https://your-issuer.com"
      callbackRedirectURI="/auth/callback"
    >
      <YourApp />
    </AuthProvider>
  );
}
```

### Using the Auth Hook

Access authentication state and methods with the `useAuth` hook:

```tsx
import { useAuth } from "openauth-react/client";

function Profile() {
  const auth = useAuth();

  if (!auth?.loaded) {
    return <div>Loading...</div>;
  }

  if (!auth.loggedIn) {
    return <button onClick={auth.login}>Login</button>;
  }

  return (
    <div>
      <p>Welcome, {auth.userData?.name}</p>
      <button onClick={auth.logout}>Logout</button>
    </div>
  );
}
```

### Getting Access Tokens

Use `getToken()` to get a valid access token for API calls:

```tsx
import { useAuth } from "openauth-react/client";

function ApiComponent() {
  const auth = useAuth();

  async function fetchData() {
    const token = await auth?.getToken();

    const response = await fetch("/api/protected", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    return response.json();
  }

  return <button onClick={fetchData}>Fetch Data</button>;
}
```

## Provider Props

| Prop                  | Type                             | Required | Default | Description                                            |
| --------------------- | -------------------------------- | -------- | ------- | ------------------------------------------------------ |
| `clientID`            | `string`                         | Yes      | -       | OAuth client ID                                        |
| `issuer`              | `string`                         | Yes      | -       | OpenAuth issuer URL                                    |
| `callbackRedirectURI` | `string`                         | No       | `/auth` | Callback URI for token exchange                        |
| `isFrontendCallback`  | `boolean`                        | No       | `false` | Whether callback is handled on frontend (enables PKCE) |
| `userInfoEndpoint`    | `string`                         | No       | -       | Custom endpoint for fetching user info                 |
| `userInfoParser`      | `(res: Response) => SessionData` | No       | -       | Custom parser for user info response                   |

## Auth Context

The `useAuth` hook returns the following:

| Property   | Type                                 | Description                                     |
| ---------- | ------------------------------------ | ----------------------------------------------- |
| `loaded`   | `boolean`                            | Whether auth state has been initialized         |
| `loggedIn` | `boolean`                            | Whether user is currently authenticated         |
| `userData` | `SessionData \| undefined`           | User session data from the auth endpoint        |
| `login`    | `() => Promise<void>`                | Initiates the login flow                        |
| `logout`   | `() => void`                         | Logs out the user and clears tokens             |
| `getToken` | `() => Promise<string \| undefined>` | Gets a valid access token (refreshes if needed) |

## Extending Session Data

Define your own session data type by extending the `SessionData` interface:

```tsx
// types.d.ts
import "openauth-react/types";

declare module "openauth-react/types" {
  interface SessionData {
    id: string;
    email: string;
    name: string;
    avatar?: string;
  }
}

export {};
```

## Frontend vs Backend Callback

### Backend Callback (Recommended)

Use with [openauth-endpoints](https://github.com/shpaw415/openauth-endpoints) for secure server-side token exchange:

```tsx
<AuthProvider
  clientID="your-client-id"
  issuer="https://your-issuer.com"
  callbackRedirectURI="/auth/callback"
  isFrontendCallback={false}
>
```

### Frontend Callback

Handle the OAuth callback entirely on the client with PKCE:

```tsx
<AuthProvider
  clientID="your-client-id"
  issuer="https://your-issuer.com"
  callbackRedirectURI="/auth/callback"
  isFrontendCallback={true}
>
```

## Server-Side Integration

Re-export the `AuthManager` from [openauth-endpoints](https://github.com/shpaw415/openauth-endpoints) for convenience:

```typescript
import { AuthManager } from "openauth-react/endpoint";

const authManager = new AuthManager({
  client,
  issuer: "https://your-issuer.com",
  redirectURI: "https://your-app.com/auth/callback",
  verify: {
    subjects,
    onSuccess: (subject) => {
      return new Response(JSON.stringify(subject), {
        headers: { "Content-Type": "application/json" },
      });
    },
  },
});
```

## Exports

| Export                    | Description                           |
| ------------------------- | ------------------------------------- |
| `openauth-react/client`   | React provider and hooks              |
| `openauth-react/types`    | TypeScript types                      |
| `openauth-react/endpoint` | Server-side AuthManager (re-exported) |

## License

MIT
