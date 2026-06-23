type Fetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export type AuthTokenManagerOptions = {
    tokenUrl?: string;
    logoutUrl?: string;
    refreshSkewMs?: number;
    credentials?: RequestCredentials;
    fetch?: Fetch;
};
export type TokenOptions = {
    forceRefresh?: boolean;
};
export type LogoutRedirectOptions = {
    location?: Pick<Location, "assign">;
};
export declare class AuthTokenManager {
    private readonly tokenUrl;
    private readonly logoutUrl;
    private readonly refreshSkewMs;
    private readonly credentials;
    private readonly fetch;
    private token?;
    private pendingToken?;
    constructor(options?: AuthTokenManagerOptions);
    getToken(options?: TokenOptions): Promise<string | undefined>;
    clear(): void;
    logout(): Promise<void>;
    logoutWithRedirect(options?: LogoutRedirectOptions): void;
    private fetchToken;
    private isExpiring;
}
export {};
//# sourceMappingURL=tokenManager.d.ts.map