import { useUser } from "@clerk/nextjs";

export default function UserProfile() {
  const { user } = useUser();
  // publicMetadata is server-writable / client-readable — safe for display.
  const displayRole = user?.publicMetadata?.role ?? "member";
  return <div>Role: {String(displayRole)}</div>;
}
