import type { AuthApi } from "../api";

/** Demo mode has no accounts: the UI is open and signed in as a fictional admin. */
export const demoAuth: AuthApi = {
  async me() {
    return { id: 0, username: "demo", role: "ADMIN" };
  },
  async login() {
    return { id: 0, username: "demo", role: "ADMIN" };
  },
  async logout() {},
};
