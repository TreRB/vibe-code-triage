// checks/index.js — registry of all vibe-code-triage checks.

import vc1 from "./vc1_rls_disabled.js";
import vc2 from "./vc2_permissive_rls.js";
import vc3 from "./vc3_service_role_client.js";
import vc4 from "./vc4_clerk_unsafe_metadata.js";
import vc5 from "./vc5_route_missing_auth.js";
import vc6 from "./vc6_hallucinated_package.js";
import vc7 from "./vc7_hardcoded_secret.js";
import vc8 from "./vc8_open_post.js";
import vc9 from "./vc9_env_committed.js";
import vc10 from "./vc10_cors.js";

export const CHECKS = [vc1, vc2, vc3, vc4, vc5, vc6, vc7, vc8, vc9, vc10];

export function findCheck(id) {
  return CHECKS.find((c) => c.id === id);
}
