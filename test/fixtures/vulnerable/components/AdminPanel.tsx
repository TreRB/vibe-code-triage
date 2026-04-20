import { useUser } from "@clerk/nextjs";
import { createClient } from "@supabase/supabase-js";

// VC3: service-role key pulled into a client component.
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

export default function AdminPanel() {
  const { user } = useUser();

  // VC4: role check against unsafeMetadata (client-writable).
  if (user?.unsafeMetadata?.role !== "admin") {
    return <div>Access denied.</div>;
  }

  // VC4: another unsafeMetadata check.
  const isPro = user?.unsafeMetadata?.plan === "pro";

  return <div>Hello admin {String(isPro)}</div>;
}
