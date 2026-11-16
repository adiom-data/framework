import { jwtDecode } from "jwt-decode";

type AccessTokenClaims = {
  exp?: number;
};

type TokenResponse = {
  access_token?: string;
};

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

export class AuthTokenManager {
  private readonly tokenUrl: string;
  private readonly logoutUrl: string;
  private readonly refreshSkewMs: number;
  private readonly credentials: RequestCredentials;
  private readonly fetch: Fetch;
  private token?: { value: string; expiresAtMs: number };
  private pendingToken?: Promise<string | undefined>;
  private generation = 0;
  private logoutRequests = 0;
  private redirecting = false;

  constructor(options: AuthTokenManagerOptions = {}) {
    this.tokenUrl = options.tokenUrl ?? "/auth/token";
    this.logoutUrl = options.logoutUrl ?? "/auth/logout";
    this.refreshSkewMs = options.refreshSkewMs ?? 60_000;
    this.credentials = options.credentials ?? "same-origin";
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  async getToken(options: TokenOptions = {}): Promise<string | undefined> {
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
    } finally {
      if (this.pendingToken === pending) {
        this.pendingToken = undefined;
      }
    }
  }

  // Request retries can use this version to avoid crossing a clear/logout.
  get authStateVersion(): number {
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
    } finally {
      this.clear();
      this.logoutRequests--;
    }
  }

  logoutWithRedirect(options: LogoutRedirectOptions = {}) {
    this.clear();
    const location = options.location ?? globalThis.location;
    this.redirecting = true;
    try {
      location.assign(this.logoutUrl);
    } catch (error) {
      this.redirecting = false;
      throw error;
    }
  }

  private async fetchToken(generation: number): Promise<string | undefined> {
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

      const body = (await response.json()) as TokenResponse;
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
    } catch (error) {
      if (generation !== this.generation) {
        return undefined;
      }
      this.clear();
      throw error;
    }
  }

  private isExpiring(expiresAtMs: number): boolean {
    return Date.now() + this.refreshSkewMs >= expiresAtMs;
  }
}

function tokenExpiresAtMs(token: string): number {
  const claims = jwtDecode<AccessTokenClaims>(token);
  if (!claims.exp) {
    throw new Error("Auth token is missing an expiration.");
  }
  return claims.exp * 1000;
}
