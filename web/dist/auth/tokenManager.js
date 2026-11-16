import { jwtDecode } from "jwt-decode";
export class AuthTokenManager {
    tokenUrl;
    logoutUrl;
    refreshSkewMs;
    credentials;
    fetch;
    token;
    pendingToken;
    generation = 0;
    logoutRequests = 0;
    redirecting = false;
    constructor(options = {}) {
        this.tokenUrl = options.tokenUrl ?? "/auth/token";
        this.logoutUrl = options.logoutUrl ?? "/auth/logout";
        this.refreshSkewMs = options.refreshSkewMs ?? 60_000;
        this.credentials = options.credentials ?? "same-origin";
        this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    }
    async getToken(options = {}) {
        if (this.logoutRequests > 0 || this.redirecting) {
            return undefined;
        }
        if (options.forceRefresh) {
            // Refresh the token within the current authentication state. Keep any
            // in-flight fetch so concurrent refresh callers can share its result.
            this.token = undefined;
        }
        if (!options.forceRefresh && this.token && !this.isExpiring(this.token.expiresAtMs)) {
            return this.token.value;
        }
        if (this.pendingToken) {
            return this.pendingToken;
        }
        const pending = this.fetchToken(this.generation);
        this.pendingToken = pending;
        try {
            return await pending;
        }
        finally {
            if (this.pendingToken === pending) {
                this.pendingToken = undefined;
            }
        }
    }
    // Request retries can use this version to avoid crossing a clear/logout.
    get authStateVersion() {
        return this.generation;
    }
    clear() {
        this.generation++;
        this.token = undefined;
        this.pendingToken = undefined;
    }
    async logout() {
        this.logoutRequests++;
        this.clear();
        try {
            const response = await this.fetch(this.logoutUrl, {
                credentials: this.credentials,
                method: "POST",
                cache: "no-store",
            });
            if (!response.ok) {
                throw new Error("Unable to end auth session.");
            }
        }
        finally {
            this.clear();
            this.logoutRequests--;
        }
    }
    logoutWithRedirect(options = {}) {
        this.clear();
        const location = options.location ?? globalThis.location;
        this.redirecting = true;
        try {
            location.assign(this.logoutUrl);
        }
        catch (error) {
            this.redirecting = false;
            throw error;
        }
    }
    async fetchToken(generation) {
        try {
            const response = await this.fetch(this.tokenUrl, {
                credentials: this.credentials,
                method: "POST",
                cache: "no-store",
            });
            if (generation !== this.generation) {
                return undefined;
            }
            if (response.status === 401) {
                this.clear();
                return undefined;
            }
            if (!response.ok) {
                throw new Error("Unable to refresh auth session.");
            }
            const body = (await response.json());
            if (generation !== this.generation) {
                return undefined;
            }
            if (!body.access_token) {
                this.clear();
                return undefined;
            }
            this.token = {
                value: body.access_token,
                expiresAtMs: tokenExpiresAtMs(body.access_token),
            };
            return this.token.value;
        }
        catch (error) {
            if (generation !== this.generation) {
                return undefined;
            }
            this.clear();
            throw error;
        }
    }
    isExpiring(expiresAtMs) {
        return Date.now() + this.refreshSkewMs >= expiresAtMs;
    }
}
function tokenExpiresAtMs(token) {
    const claims = jwtDecode(token);
    if (!claims.exp) {
        throw new Error("Auth token is missing an expiration.");
    }
    return claims.exp * 1000;
}
