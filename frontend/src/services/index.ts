import type { AuthApi, SentinelApi } from "./api";
import { demoApi } from "./demo/demoApi";
import { demoAuth } from "./demo/demoAuth";
import { httpApi, httpAuth } from "./http";

/**
 * The single place that chooses the data source.
 *   VITE_DATA_MODE=demo  -> built-in synthetic data, no backend, no login
 *   anything else        -> the Django REST API (default)
 */
export const dataMode: "demo" | "api" = __DATA_MODE__;
export const api: SentinelApi = dataMode === "demo" ? demoApi : httpApi;
export const authApi: AuthApi = dataMode === "demo" ? demoAuth : httpAuth;
export { ApiError } from "./api";
