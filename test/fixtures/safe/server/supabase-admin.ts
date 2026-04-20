// Server-only module. SUPABASE_SERVICE_ROLE_KEY belongs here because the
// path segment /server/ excludes it from VC3's client-side check.
import { createClient } from "@supabase/supabase-js";

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);
