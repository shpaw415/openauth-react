import { useAuth } from "openauth-react/client";

export default function HomePage() {
  return (
    <div>
      <LogComponent />
    </div>
  );
}

function LogComponent() {
  const auth = useAuth();

  return (
    <div>
      {auth?.loggedIn ? (
        <p>Logged in as {auth.userData?.id}</p>
      ) : (
        <>
          <p>Not logged in</p>
          <button onClick={auth?.login}>Login</button>
        </>
      )}
    </div>
  );
}
