import { jwtDecode } from "jwt-decode";
export class AuthTokenManager {
    tokenUrl;
    logoutUrl;
    refreshSkewMs;
    credentials;
    fetch;
    token;
    pendingToken;
    constructor(options = {}) {
        this.tokenUrl = options.tokenUrl ?? "/auth/token";
        this.logoutUrl = options.logoutUrl ?? "/auth/logout";
        this.refreshSkewMs = options.refreshSkewMs ?? 60_000;
        this.credentials = options.credentials ?? "same-origin";
        this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    }
    async getToken(options = {}) {
        if (!options.forceRefresh && this.token && !this.isExpiring(this.token.expiresAtMs)) {
            return this.token.value;
        }
        if (!options.forceRefresh && this.pendingToken) {
            return this.pendingToken;
        }
        this.pendingToken = this.fetchToken();
        try {
            return await this.pendingToken;
        }
        finally {
            this.pendingToken = undefined;
        }
    }
    clear() {
        this.token = undefined;
    }
    async logout() {
        this.clear();
        await this.fetch(this.logoutUrl, {
            credentials: this.credentials,
            method: "POST",
        });
    }
    logoutWithRedirect(options = {}) {
        this.clear();
        const location = options.location ?? globalThis.location;
        location.assign(this.logoutUrl);
    }
    async fetchToken() {
        const response = await this.fetch(this.tokenUrl, {
            credentials: this.credentials,
            method: "POST",
        });
        if (response.status === 401) {
            this.clear();
            return undefined;
        }
        if (!response.ok) {
            this.clear();
            throw new Error("Unable to refresh auth session.");
        }
        const body = (await response.json());
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
