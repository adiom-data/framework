import { Code, ConnectError, type Interceptor } from "@connectrpc/connect";
import type { AuthTokenManager } from "./tokenManager.js";

export function createAuthInterceptor(tokenManager: AuthTokenManager): Interceptor {
  return (next) => async (req) => {
    const authStateVersion = tokenManager.authStateVersion;
    const token = await tokenManager.getToken();
    if (token && authStateVersion !== tokenManager.authStateVersion) {
      throw new ConnectError("Authentication changed.", Code.Unauthenticated);
    }
    if (token) {
      req.header.set("Authorization", `Bearer ${token}`);
    }
    try {
      return await next(req);
    } catch (error) {
      if (token && error instanceof ConnectError && error.code === Code.Unauthenticated &&
          authStateVersion === tokenManager.authStateVersion) {
        // Another RPC may already have refreshed this rejected token. Reuse
        // that token or join its pending fetch before starting another one.
        let refreshedToken = await tokenManager.getToken();
        if (authStateVersion !== tokenManager.authStateVersion) {
          throw error;
        }
        if (refreshedToken === token) {
          refreshedToken = await tokenManager.getToken({ forceRefresh: true });
        }
        if (refreshedToken && authStateVersion === tokenManager.authStateVersion) {
          req.header.set("Authorization", `Bearer ${refreshedToken}`);
          return next(req);
        }
      }
      throw error;
    }
  };
}
