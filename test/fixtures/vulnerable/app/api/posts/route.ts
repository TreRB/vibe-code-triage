import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

// VC3: SUPABASE_SERVICE_ROLE_KEY is fine here — this is a server route — but
// the file still lives under app/api so VC3's path filter must skip it.
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// VC5: this POST handler writes to DB and has no auth().
// VC8: no CSRF indicator of any kind.
export async function POST(req: NextRequest) {
  const body = await req.json();
  const { data, error } = await supabase.from("posts").insert(body);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ data });
}

// VC5 (medium): read-only handler that exposes sensitive user/profile data
// without auth.
export async function GET(req: NextRequest) {
  const { data } = await supabase
    .from("user")
    .select("id, email, subscription, admin");
  return NextResponse.json({ users: data });
}
