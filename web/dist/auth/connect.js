import { Code, ConnectError } from "@connectrpc/connect";
export function createAuthInterceptor(tokenManager) {
    return (next) => async (req) => {
        const token = await tokenManager.getToken();
        if (token) {
            req.header.set("Authorization", `Bearer ${token}`);
        }
        try {
            return await next(req);
        }
        catch (error) {
            if (token && error instanceof ConnectError && error.code === Code.Unauthenticated) {
                tokenManager.clear();
                const refreshedToken = await tokenManager.getToken({ forceRefresh: true });
                if (refreshedToken) {
                    req.header.set("Authorization", `Bearer ${refreshedToken}`);
                    return next(req);
                }
            }
            throw error;
        }
    };
}
