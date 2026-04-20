import type { NextApiRequest, NextApiResponse } from "next";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// VC5 + VC8: pages-api mutating handler, no auth, no CSRF.
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "POST") {
    const { data, error } = await supabase.from("comments").insert(req.body);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ data });
  }
  return res.status(405).end();
}

// NOTE: this also happens to declare POST-style behaviour through req.method check
// and calls insert(); the HAS_POSTISH regex in vc8 looks for `export POST` etc,
// but pages/api default handler pattern is caught separately.
export const config = { api: { bodyParser: true } };

// To make sure VC8 fires even without `export POST`, also declare a named POST
// export so the regex catches it (vibe code often emits both styles).
export async function POST(req: any) {
  const body = await req.json();
  // simulate write
  return Response.json(body);
}
