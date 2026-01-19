// ClientWrapper is used client side only for state management
// you can create your own version of the routerHost

import { RouterHost } from "frame-master-plugin-apply-react/router";
import { AuthProvider } from "openauth-react/client";
import { StrictMode, type JSX } from "react";

export default function ClientWrapper({ children }: { children: JSX.Element }) {
  return (
    <StrictMode>
      <AuthProvider
        clientID="test-id"
        issuer="http://localhost:8787"
        callbackRedirectURI="/frontend-auth/callback"
        userInfoEndpoint="/auth"
        isFrontendCallback
      >
        <RouterHost>{children}</RouterHost>
      </AuthProvider>
    </StrictMode>
  );
}
