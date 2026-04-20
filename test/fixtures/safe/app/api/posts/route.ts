import { NextRequest, NextResponse } from "next/server";
import { auth } from "@clerk/nextjs/server";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

export async function POST(req: NextRequest) {
  const { userId } = await auth();
  if (!userId) return new NextResponse("unauthorized", { status: 401 });

  const body = await req.json();
  const { data, error } = await supabase
    .from("posts")
    .insert({ ...body, author_id: userId });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ data });
}

export async function GET() {
  const { userId } = await auth();
  if (!userId) return new NextResponse("unauthorized", { status: 401 });
  const { data } = await supabase.from("posts").select("id, body").eq("author_id", userId);
  return NextResponse.json({ posts: data });
}
