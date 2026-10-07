import type { AuthUser, Role } from "../types";

const RANK: Record<Role, number> = { VIEWER: 1, ANALYST: 2, ADMIN: 3 };

/** UI convenience only. The server enforces roles on every request regardless of what the UI shows. */
export const hasRole = (user: AuthUser | null, minimum: Role) => !!user && RANK[user.role] >= RANK[minimum];
